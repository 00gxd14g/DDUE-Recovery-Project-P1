from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .io.base import DiskSource
from .state import RecoveryState


LogCb = Callable[[str, str], None]


@dataclass(frozen=True)
class ScanProgress:
    offset: int
    total: int


def iter_offsets(total_size: int, step: int) -> Iterable[int]:
    off = 0
    while off < total_size:
        yield off
        off += step


def safe_read(
    src: DiskSource,
    state: RecoveryState,
    offset: int,
    size: int,
    log_cb: Optional[LogCb] = None,
) -> bytes:
    state.wait_if_paused()
    if state.stop_requested or not state.is_alive:
        return b"\x00" * size
    total = src.size() or 0
    if total > 0 and offset >= total:
        return b"\x00" * size
    if state.bad_map.contains(offset, size):
        return b"\x00" * size
    try:
        data = src.read_at(offset, size)
        if len(data) < size:
            data += b"\x00" * (size - len(data))
        state.register_success()
        return data
    except OSError as e:
        state.register_error(offset, size)
        if log_cb:
            log_cb("bad_sector", f"I/O error @{offset} (+{size}): {e}")
        return b"\x00" * size


def safe_read_granular(
    src: DiskSource,
    state: RecoveryState,
    offset: int,
    size: int,
    log_cb: Optional[LogCb] = None,
    *,
    sector_size: Optional[int] = None,
) -> bytes:
    """
    Best-effort read that preserves size and tries to salvage good data:
    - Fast path: read the whole range at once.
    - On I/O error: retry sector-by-sector; zero-fill unreadable sectors.
    """
    state.wait_if_paused()
    if state.stop_requested or not state.is_alive:
        return b"\x00" * size
    total = src.size() or 0
    if total > 0 and offset >= total:
        return b"\x00" * size

    if state.bad_map.contains(offset, size):
        return b"\x00" * size

    refreshed = False

    def maybe_panic(e: OSError) -> None:
        nonlocal refreshed
        winerr = getattr(e, "winerror", None)
        err = int(winerr) if winerr is not None else int(getattr(e, "errno", 0) or 0)
        if err in (6, 21, 31, 55, 995, 1117, 1167):
            try:
                state.register_controller_panic()  # type: ignore[attr-defined]
            except Exception:
                pass
            if log_cb:
                log_cb("CRITICAL", f"Controller panic detected (err={err}) @ {offset} (+{size})")
            if not refreshed:
                refreshed = True
                try:
                    refresh = getattr(src, "refresh", None)
                    if callable(refresh):
                        refresh()
                except Exception:
                    pass

    try:
        data = src.read_at(offset, size)
        if len(data) < size:
            data += b"\x00" * (size - len(data))
        state.register_success()
        return data
    except OSError as e:
        maybe_panic(e)
        if log_cb:
            log_cb("bad_sector", f"I/O error @{offset} (+{size}): {e}; falling back to sector scan")

    sec = int(sector_size or (src.sector_size() or 512) or 512)
    if sec <= 0:
        sec = 512

    buf = bytearray(b"\x00" * size)
    end = offset + size
    cur = offset
    while cur < end and not state.stop_requested and state.is_alive:
        state.wait_if_paused()
        to_read = min(sec, end - cur)
        rel = cur - offset
        if state.bad_map.contains(cur, to_read):
            cur += to_read
            continue
        try:
            chunk = src.read_at(cur, to_read)
            if chunk:
                buf[rel : rel + len(chunk)] = chunk
                if len(chunk) < to_read:
                    # keep zeros for remainder
                    pass
            state.register_success()
        except OSError as e:
            maybe_panic(e)
            state.register_error(cur, to_read)
            if log_cb:
                log_cb("bad_sector", f"I/O error @{cur} (+{to_read}): {e}; zero-filled")
        cur += to_read

    return bytes(buf)
