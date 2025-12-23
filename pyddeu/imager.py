from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from .io.base import DiskSource
from .scan import safe_read_granular
from .state import RecoveryState


LogCb = Callable[[str, str], None]
ProgressCb = Callable[[int, int], None]


def create_image(
    src: DiskSource,
    state: RecoveryState,
    out_path: Path,
    *,
    start: int = 0,
    end: Optional[int] = None,
    block: int = 1024 * 1024,
    log_cb: Optional[LogCb] = None,
    progress_cb: Optional[ProgressCb] = None,
) -> None:
    """
    Read-only imaging: reads from src and writes to out_path (different disk recommended).
    On read errors, safe_read returns zeros so image size/layout remains consistent.
    """
    total = src.size() or 0
    if end is None:
        end = total if total > 0 else 0
    end = min(end, total) if total > 0 else end

    out_path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    last_log = t0
    written = 0

    with open(out_path, "wb") as out:
        offset = start
        while offset < end and not state.stop_requested and state.is_alive:
            to_read = min(block, end - offset)
            data = safe_read_granular(src, state, offset, to_read, log_cb=log_cb)
            out.write(data)
            written += to_read
            offset += to_read

            if progress_cb:
                try:
                    progress_cb(offset, end)
                except Exception:
                    pass

            now = time.time()
            if log_cb and (now - last_log) >= 2.0:
                mb = written / (1024 * 1024)
                dt = max(0.001, now - t0)
                speed = mb / dt
                log_cb("INFO", f"Imaging: {mb:.1f} MiB written ({speed:.1f} MiB/s)")
                last_log = now
