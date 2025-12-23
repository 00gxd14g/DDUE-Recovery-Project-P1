from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .io.base import DiskSource
from .scan import safe_read
from .state import RecoveryState


LogCb = Callable[[str, str], None]


@dataclass(frozen=True)
class Signature:
    ext: str
    header: bytes
    footer: Optional[bytes] = None
    max_size: int = 64 * 1024 * 1024


SIGS: list[Signature] = [
    Signature(ext="jpg", header=b"\xFF\xD8\xFF", footer=b"\xFF\xD9", max_size=64 * 1024 * 1024),
    Signature(ext="pdf", header=b"%PDF", footer=b"%%EOF", max_size=128 * 1024 * 1024),
    Signature(ext="zip", header=b"PK\x03\x04", footer=None, max_size=256 * 1024 * 1024),
]


def carve_signatures(
    src: DiskSource,
    state: RecoveryState,
    out_dir: Path,
    *,
    step: int = 1024 * 1024,
    window: int = 8 * 1024 * 1024,
    read_chunk: int = 1024 * 1024,
    log_cb: Optional[LogCb] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> int:
    """
    Read-only signature scan. Writes recovered files to out_dir (NOT the source disk).
    For footered formats (jpg/pdf), reads forward until footer or max_size.
    For zip, writes a window-sized chunk (best-effort).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    total = src.size() or 0
    if total <= 0:
        return 0

    found = 0
    offset = 0
    while offset < total and not state.stop_requested and state.is_alive:
        if progress_cb:
            try:
                progress_cb(offset, total)
            except Exception:
                pass
        head = safe_read(src, state, offset, 16, log_cb=log_cb)
        for sig in SIGS:
            if head.startswith(sig.header):
                found += 1
                file_name = f"carve_{sig.ext}_{offset}.{sig.ext}"
                out_path = out_dir / file_name
                if log_cb:
                    log_cb("INFO", f"Found {sig.ext} signature at {offset}, writing {out_path}")
                _carve_one(
                    src,
                    state,
                    sig,
                    offset,
                    out_path,
                    window=window,
                    read_chunk=read_chunk,
                    log_cb=log_cb,
                )
                break
        if state.consecutive_errors >= 8:
            jump = max(step, state.skip_size)
            if log_cb:
                log_cb("WARNING", f"Adaptive skip: +{jump} bytes after consecutive I/O errors")
            offset += jump
        else:
            offset += step
    return found


def _carve_one(
    src: DiskSource,
    state: RecoveryState,
    sig: Signature,
    start: int,
    out_path: Path,
    *,
    window: int,
    read_chunk: int,
    log_cb: Optional[LogCb],
) -> None:
    max_len = min(sig.max_size, src.size() - start if src.size() else sig.max_size)
    written = 0
    try:
        with open(out_path, "wb") as f:
            if sig.footer is None:
                to_read = min(window, max_len)
                data = safe_read(src, state, start, to_read, log_cb=log_cb)
                f.write(data)
                return

            scan_off = start
            tail = b""
            footer = sig.footer
            while written < max_len and not state.stop_requested and state.is_alive:
                to_read = min(read_chunk, max_len - written)
                chunk = safe_read(src, state, scan_off, to_read, log_cb=log_cb)
                if not chunk:
                    break
                f.write(chunk)
                written += len(chunk)
                scan_off += len(chunk)

                hay = tail + chunk
                idx = hay.find(footer)
                if idx != -1:
                    end_pos = idx + len(footer)
                    # Trim file to exact end (best-effort)
                    trim_to = written - (len(hay) - end_pos)
                    f.flush()
                    f.truncate(trim_to)
                    return
                tail = hay[-max(len(footer) * 2, 64) :]
    except OSError as e:
        if log_cb:
            log_cb("WARNING", f"Carve write failed for {out_path}: {e}")
        try:
            os.remove(out_path)
        except Exception:
            pass
