from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from .state import RecoveryState


LogCb = Callable[[str, str], None]
ProgressCb = Callable[[int, int], None]


class RobustExporter:
    """
    Ultra-robust export for unstable disks/controllers:
    - Read in 4KiB chunks (SSD-friendly).
    - On error: zero-fill the chunk, cooldown (seconds), and quickly skip out of dead zones.
    - Skip size grows exponentially up to a cap; skipped areas are also zero-filled to preserve file size.
    """

    def __init__(
        self,
        fs_info: object,
        state: RecoveryState,
        *,
        log_cb: Optional[LogCb] = None,
        cluster_size: int = 4096,
        base_skip_size: int = 1024 * 1024,
        max_skip_size: int = 1024 * 1024 * 50,
        cooldown_s: float = 2.0,
    ):
        self.fs = fs_info
        self.state = state
        self.log_cb = log_cb
        self.cluster_size = int(cluster_size)
        self.base_skip_size = int(base_skip_size)
        self.max_skip_size = int(max_skip_size)
        self.cooldown_s = float(cooldown_s)

    def export_inode(self, inode: int, out_path: Path, *, progress_cb: Optional[ProgressCb] = None) -> bool:
        try:
            f = self.fs.open_meta(inode=int(inode))
            size = int(f.info.meta.size or 0)
        except Exception as e:
            self._log("ERROR", f"open_meta failed (inode={inode}): {e}")
            return False

        out_path.parent.mkdir(parents=True, exist_ok=True)
        self._log("INFO", f"Export started (inode={inode}, size={size}) -> {out_path}")

        try:
            with open(out_path, "wb") as out_file:
                offset = 0
                consecutive_errors = 0
                current_skip = max(0, self.base_skip_size)
                while offset < size:
                    if self.state.stop_requested or not self.state.is_alive:
                        self._log("WARNING", "Export aborted (stop requested).")
                        return False

                    to_read = min(self.cluster_size, size - offset)
                    prev_state_err = int(getattr(self.state, "consecutive_errors", 0))
                    try:
                        self.state.wait_if_paused()
                        data = f.read_random(offset, to_read)
                        out_file.write(data if data else b"\x00" * to_read)
                        offset += to_read
                        state_err_now = int(getattr(self.state, "consecutive_errors", 0))
                        error_hit = state_err_now > prev_state_err
                        err_msg = None
                    except Exception as e:
                        error_hit = True
                        err_msg = str(e)
                        out_file.write(b"\x00" * to_read)
                        offset += to_read

                    if error_hit:
                        consecutive_errors += 1
                        wait_time = self.cooldown_s * (1 if consecutive_errors < 5 else 2)
                        self._log(
                            "CRITICAL",
                            f"I/O error @{max(0, offset - to_read)} (+{to_read}); cooling down ({wait_time:.2f}s). err={err_msg or 'read returned error zeros'}",
                        )
                        if wait_time > 0:
                            time.sleep(wait_time)

                        if consecutive_errors >= 2 and current_skip > 0:
                            skip_amount = min(current_skip, size - offset)
                            if skip_amount > 0:
                                self._log(
                                    "bad_sector",
                                    f"Dead zone: skipping {skip_amount // 1024} KiB (zero-fill), next_skip={min(current_skip * 2, self.max_skip_size) // 1024} KiB",
                                )
                                written = 0
                                zero_chunk = 1024 * 1024
                                while written < skip_amount and not self.state.stop_requested and self.state.is_alive:
                                    z = min(zero_chunk, skip_amount - written)
                                    out_file.write(b"\x00" * z)
                                    written += z
                                offset += skip_amount
                                current_skip = min(max(1, current_skip * 2), max(1, self.max_skip_size))
                    else:
                        if consecutive_errors > 0:
                            consecutive_errors = 0
                            current_skip = max(0, self.base_skip_size)

                    if progress_cb:
                        try:
                            progress_cb(offset, size)
                        except Exception:
                            pass
            self._log("INFO", f"Export finished -> {out_path}")
            return True
        except Exception as e:
            self._log("CRITICAL", f"Write failed ({out_path}): {e}")
            return False

    def _log(self, level: str, msg: str) -> None:
        if self.log_cb:
            self.log_cb(level, msg)
