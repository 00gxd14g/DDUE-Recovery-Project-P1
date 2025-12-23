from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional


@dataclass(frozen=True)
class Region:
    start: int
    end: int  # exclusive

    def overlaps(self, other: "Region") -> bool:
        return self.start < other.end and other.start < self.end

    def merge(self, other: "Region") -> "Region":
        return Region(start=min(self.start, other.start), end=max(self.end, other.end))


class BadRegionMap:
    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.Lock()
        self._regions: list[Region] = []
        self.load()

    def load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            regions = [Region(int(r[0]), int(r[1])) for r in raw.get("bad_regions", [])]
            regions.sort(key=lambda r: (r.start, r.end))
            with self._lock:
                self._regions = self._merge_all(regions)
        except Exception:
            return

    def save(self) -> None:
        with self._lock:
            payload = {"bad_regions": [[r.start, r.end] for r in self._regions]}
        try:
            self._path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            return

    def add(self, start: int, length: int) -> None:
        if length <= 0:
            return
        new_region = Region(start, start + length)
        with self._lock:
            self._regions.append(new_region)
            self._regions.sort(key=lambda r: (r.start, r.end))
            self._regions = self._merge_all(self._regions)

    def contains(self, offset: int, size: int) -> bool:
        if size <= 0:
            return False
        query = Region(offset, offset + size)
        with self._lock:
            for region in self._regions:
                if region.start >= query.end:
                    return False
                if region.overlaps(query):
                    return True
        return False

    @staticmethod
    def _merge_all(regions: Iterable[Region]) -> list[Region]:
        merged: list[Region] = []
        for region in regions:
            if not merged:
                merged.append(region)
                continue
            last = merged[-1]
            if last.end >= region.start:
                merged[-1] = last.merge(region)
            else:
                merged.append(region)
        return merged

    def region_count(self) -> int:
        with self._lock:
            return len(self._regions)


LogCb = Callable[[str, str], None]


class RecoveryState:
    def __init__(
        self,
        map_path: Path,
        block_size: int = 4096,
        max_skip_size: int = 1024 * 1024 * 100,
    ):
        self.block_size = int(block_size)
        self.max_skip_size = int(max_skip_size)

        self.bad_map = BadRegionMap(map_path)
        self.skip_size = self.block_size
        self.consecutive_errors = 0

        self.is_alive = True
        self.stop_requested = False
        self.pause_until: float = 0.0
        self._panic_level = 0

        self._lock = threading.Lock()
        self._dirty_counter = 0

    def register_error(self, offset: int, size: int) -> None:
        with self._lock:
            self.bad_map.add(offset, max(size, 1))
            self.consecutive_errors += 1
            self.skip_size = min(self.skip_size * 2, self.max_skip_size)
            self._dirty_counter += 1
            if self._dirty_counter >= 50:
                self._dirty_counter = 0
                self.bad_map.save()

    def register_success(self) -> None:
        with self._lock:
            if self.consecutive_errors:
                self.consecutive_errors = 0
                self.skip_size = self.block_size
            if self._panic_level > 0:
                self._panic_level -= 1

    def register_controller_panic(self, log_cb: Optional[LogCb] = None) -> None:
        """
        Called when OS logs indicate a device reset/controller panic.
        We do NOT auto-stop; instead we pause reads with exponential backoff to avoid a reset loop.
        """
        with self._lock:
            self._panic_level = min(self._panic_level + 1, 10)
            pause_s = min(60.0, 2.0 * (1.5 ** self._panic_level))
            self.pause_until = max(self.pause_until, time.time() + pause_s)
        if log_cb:
            try:
                log_cb("WARNING", f"Controller Panic detected! Pausing for {pause_s:.1f} seconds.")
            except Exception:
                pass

    def wait_if_paused(self) -> None:
        """
        Blocks briefly when a controller panic is detected, giving the device time to recover.
        Intended to be called inside worker threads before issuing more I/O.
        """
        if self.stop_requested or not self.is_alive:
            return
        now = time.time()
        until = self.pause_until
        if until > now:
            time.sleep(max(0.01, until - now))
