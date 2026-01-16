from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from .config import PyddeuConfig

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
        """
        Returns True only when the *entire* [offset, offset+size) range is known bad.

        This is intentionally a full-containment check (not an overlap check).
        Otherwise, tiny probe failures (e.g. 4 bytes) can incorrectly poison large
        reads and make partition/NTFS carving appear "stuck".
        """
        if size <= 0:
            return False
        start = int(offset)
        end = start + int(size)
        with self._lock:
            regions = self._regions
            if not regions:
                return False
            # Binary search for the rightmost region whose start <= query start.
            lo = 0
            hi = len(regions) - 1
            idx = -1
            while lo <= hi:
                mid = (lo + hi) // 2
                if regions[mid].start <= start:
                    idx = mid
                    lo = mid + 1
                else:
                    hi = mid - 1
            if idx < 0:
                return False
            region = regions[idx]
            return region.start <= start and region.end >= end

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


_MAP_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def map_path_for_source(source_path: str, *, directory: Path | None = None) -> Path:
    """
    Returns a stable, filesystem-safe per-source bad-region map path.

    This avoids a single global map file poisoning scans across different disks/images.
    """
    raw = (source_path or "").strip()
    if raw.startswith("\\\\.\\"):
        base = raw[4:]
    else:
        try:
            base = Path(raw).name
        except Exception:
            base = raw
    base = _MAP_NAME_SAFE_RE.sub("_", base or "source").strip("_") or "source"
    digest = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:10] if raw else "unknown"
    root = directory or Path(".")
    return root / f"pyddeu.map.{base}.{digest}.json"


LogCb = Callable[[str, str], None]


class RecoveryState:
    def __init__(
        self,
        map_path: Path,
        block_size: int = 4096,
        max_skip_size: int = 128 * 1024 * 1024,  # cap skips to 128MB to avoid missing structures
        config: Optional[PyddeuConfig] = None,
    ):
        self.block_size = int(block_size)
        # Hard ceiling to keep skip behavior reasonable even if caller passes huge values.
        self.max_skip_size = min(int(max_skip_size), 128 * 1024 * 1024)
        self.config = config or PyddeuConfig()

        self.bad_map = BadRegionMap(map_path)
        self.skip_size = self.block_size
        self.consecutive_errors = 0

        self.is_alive = True
        self.stop_requested = False
        self.pause_until: float = 0.0
        self._panic_level = 0

        self._lock = threading.Lock()
        self._dirty_counter = 0

    def _clamp_skip(self) -> None:
        """Ensure skip_size and max_skip_size stay within sane bounds."""
        self.max_skip_size = min(self.max_skip_size, 128 * 1024 * 1024)
        self.skip_size = min(self.skip_size, self.max_skip_size)
        if self.skip_size <= 0:
            self.skip_size = self.block_size

    def bump_skip(self, target: int) -> None:
        """Raise skip_size up to target (bounded by max_skip_size)."""
        with self._lock:
            self.skip_size = max(self.skip_size, min(self.max_skip_size, max(0, target)))
            self._clamp_skip()

    def reset(self, *, map_path: Optional[Path] = None) -> None:
        """
        Resets adaptive read state and (optionally) swaps the bad-region map.

        Keeps object identity stable so background monitor threads can keep
        referencing the same RecoveryState instance.
        """
        with self._lock:
            if map_path is not None:
                self.bad_map = BadRegionMap(map_path)
            self.skip_size = self.block_size
            self.consecutive_errors = 0
            self.pause_until = 0.0
            self._panic_level = 0
            self._dirty_counter = 0
            self._clamp_skip()

    def register_error(self, offset: int, size: int) -> None:
        with self._lock:
            self.bad_map.add(offset, max(size, 1))
            self.consecutive_errors += 1
            self.skip_size = min(self.skip_size * 2, self.max_skip_size)
            self._dirty_counter += 1
            if self._dirty_counter >= 50:
                self._dirty_counter = 0
                self.bad_map.save()
            self._clamp_skip()

    def register_success(self) -> None:
        with self._lock:
            if self.consecutive_errors:
                self.consecutive_errors = 0
                self.skip_size = self.block_size
            if self._panic_level > 0:
                self._panic_level -= 1
            self._clamp_skip()

    def register_controller_panic(self, log_cb: Optional[LogCb] = None) -> None:
        """
        Called when OS logs indicate a device reset/controller panic.
        On Linux we avoid auto-stopping; we just back off and skip aggressively
        (DMDE-style persistence on weak media).
        """
        with self._lock:
            self._panic_level = min(self._panic_level + 1, 30)
            # Increase skip size but keep it bounded so we don't leap past partitions.
            self.skip_size = max(self.skip_size, min(self.max_skip_size, 16 * 1024 * 1024))
            self._clamp_skip()
            # Do not pause; keep streaming while marking panic for logging.
            self.pause_until = 0.0

        if log_cb:
            try:
                log_cb("WARNING", f"Controller Panic #{self._panic_level} detected! Aggressive skip enabled (skip_size={self.skip_size} bytes).")
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
            # Sleep in short chunks so stop/pause state stays responsive.
            remaining = until - now
            time.sleep(max(0.05, min(0.25, remaining)))
