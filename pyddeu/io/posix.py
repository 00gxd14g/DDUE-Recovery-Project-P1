from __future__ import annotations

import os
import threading
from dataclasses import dataclass

from .base import DiskSource


@dataclass
class PosixPreadSource(DiskSource):
    path: str
    _fd: int
    _size: int
    _sector_size: int = 512

    def size(self) -> int:
        return self._size

    def sector_size(self) -> int:
        return self._sector_size

    def read_at(self, offset: int, size: int) -> bytes:
        return os.pread(self._fd, size, offset)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except Exception:
            return


@dataclass
class PosixSeekSource(DiskSource):
    path: str
    _fp: object
    _size: int
    _lock: threading.Lock
    _sector_size: int = 512

    def size(self) -> int:
        return self._size

    def sector_size(self) -> int:
        return self._sector_size

    def read_at(self, offset: int, size: int) -> bytes:
        with self._lock:
            self._fp.seek(offset)
            return self._fp.read(size)

    def close(self) -> None:
        try:
            self._fp.close()
        except Exception:
            return


def open_posix_source(path: str) -> DiskSource:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    fd = os.open(path, flags)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        size = 0

    if size <= 0:
        try:
            import fcntl
            import struct

            BLKGETSIZE64 = 0x80081272
            buf = bytearray(8)
            fcntl.ioctl(fd, BLKGETSIZE64, buf, True)
            size = int(struct.unpack("<Q", buf)[0])
        except Exception:
            pass

    sector_size = 512
    try:
        import fcntl
        import struct

        BLKSSZGET = 0x1268
        buf = bytearray(4)
        fcntl.ioctl(fd, BLKSSZGET, buf, True)
        sector_size = int(struct.unpack("<I", buf)[0]) or 512
    except Exception:
        sector_size = 512

    if hasattr(os, "pread"):
        return PosixPreadSource(path=path, _fd=fd, _size=size, _sector_size=sector_size)

    fp = os.fdopen(fd, "rb", buffering=0)
    return PosixSeekSource(
        path=path, _fp=fp, _size=size, _lock=threading.Lock(), _sector_size=sector_size
    )
