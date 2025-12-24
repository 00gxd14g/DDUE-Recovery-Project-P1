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
        # Error codes that indicate controller/device reset:
        # 21: device not ready, 55: resource unavailable, 1117: device request failed
        # 1460: timeout, 87: invalid parameter (sometimes after reset)
        if err in (21, 55, 1117, 1460, 87):
            try:
                state.register_controller_panic(log_cb=log_cb)
            except Exception:
                pass
            # Try to refresh handle ONLY ONCE, and don't fail if it times out
            if not refreshed:
                refreshed = True
                try:
                    refresh = getattr(src, "refresh_with_timeout", None)
                    if callable(refresh):
                        # Use short timeout - don't block forever
                        ok = refresh(timeout_s=2.0)
                        if not ok and log_cb:
                            log_cb("WARNING", "Disk handle refresh timed out; will retry on next reset.")
                    else:
                        # Fallback to regular refresh with try/catch
                        refresh2 = getattr(src, "refresh", None)
                        if callable(refresh2):
                            try:
                                refresh2()
                            except Exception as re:
                                if log_cb:
                                    log_cb("WARNING", f"Disk handle refresh failed: {re}")
                except Exception as outer_e:
                    if log_cb:
                        log_cb("WARNING", f"Disk refresh error ignored: {outer_e}")

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

    cfg = getattr(state, "config", None)
    retries = int(getattr(cfg, "retries", 0) or 0)
    deviojump_sectors = int(getattr(cfg, "deviojump_sectors", 0) or 0)
    bad_filler = getattr(cfg, "deviobadfiller", None)
    skip_filler = getattr(cfg, "devioskipfiller", None)

    def fill_pattern(dst: bytearray, start: int, length: int, pattern_u32: Optional[int]) -> None:
        if length <= 0:
            return
        if pattern_u32 is None:
            return
        pat = int(pattern_u32) & 0xFFFFFFFF
        p = pat.to_bytes(4, "little", signed=False)
        end2 = start + length
        i = start
        while i < end2:
            chunk = min(4, end2 - i)
            dst[i : i + chunk] = p[:chunk]
            i += chunk

    buf = bytearray(b"\x00" * size)
    end = offset + size
    cur = offset
    while cur < end and not state.stop_requested and state.is_alive:
        state.wait_if_paused()
        to_read = min(sec, end - cur)
        rel = cur - offset
        if state.bad_map.contains(cur, to_read):
            fill_pattern(buf, int(rel), int(to_read), skip_filler)
            cur += to_read
            continue

        last_err: Optional[OSError] = None
        ok = False
        attempt = 0
        while attempt <= retries:
            try:
                chunk = src.read_at(cur, to_read)
                if chunk:
                    buf[rel : rel + len(chunk)] = chunk
                if len(chunk) < to_read:
                    # keep remainder filled (zeros/pattern)
                    pass
                state.register_success()
                ok = True
                break
            except OSError as e:
                last_err = e
                maybe_panic(e)
                state.register_error(cur, to_read)
            attempt += 1

        if not ok:
            fill_pattern(buf, int(rel), int(to_read), bad_filler)
            if log_cb:
                log_cb(
                    "bad_sector",
                    f"I/O error @{cur} (+{to_read}) retries={retries}: {last_err}; filled",
                )

            if deviojump_sectors > 0:
                jump_bytes = deviojump_sectors * sec
                # Fill the skipped area (best-effort) and advance.
                remaining = end - (cur + to_read)
                to_skip = min(jump_bytes, max(0, remaining))
                if to_skip > 0:
                    rel2 = (cur + to_read) - offset
                    fill_pattern(buf, int(rel2), int(to_skip), skip_filler)
                    cur += to_read + to_skip
                    continue

        cur += to_read

    return bytes(buf)
