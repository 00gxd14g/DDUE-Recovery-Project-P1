from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from .io.base import DiskSource
from .scan import safe_read_granular
from .state import RecoveryState


LogCb = Callable[[str, str], None]


def recover_nonresident_runs(
    src: DiskSource,
    state: RecoveryState,
    out_path: Path,
    *,
    part_offset: int,
    cluster_size: int,
    runs: list[tuple[Optional[int], int]],
    expected_size: Optional[int],
    log_cb: Optional[LogCb] = None,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    remaining = expected_size
    with open(out_path, "wb") as f:
        for lcn, length in runs:
            if state.stop_requested or not state.is_alive:
                break
            bytes_len = length * cluster_size
            if remaining is not None:
                bytes_len = min(bytes_len, remaining)
            if bytes_len <= 0:
                break
            if lcn is None:
                f.write(b"\x00" * bytes_len)
            else:
                abs_off = part_offset + (lcn * cluster_size)
                # stream in 1MB chunks
                chunk = 1024 * 1024
                written = 0
                while written < bytes_len and not state.stop_requested and state.is_alive:
                    to_read = min(chunk, bytes_len - written)
                    data = safe_read_granular(src, state, abs_off + written, to_read, log_cb=log_cb)
                    f.write(data)
                    written += to_read
            if remaining is not None:
                remaining -= bytes_len
                if remaining <= 0:
                    break
