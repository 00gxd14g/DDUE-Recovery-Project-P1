"""
POSIX/Linux disk I/O layer with timeout support, sector alignment, and O_DIRECT.

This module provides Linux-specific disk access capabilities that match the
Windows implementation features:
- Timeout-protected reads to prevent blocking on faulty media
- Sector-aligned reads for raw block devices
- O_DIRECT support for bypassing kernel cache
- Device refresh/reconnect handling
- Configuration-driven behavior
"""
from __future__ import annotations

import errno
import os
import signal
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .base import DiskSource, SourceInfo
from ..config import PyddeuConfig


# Linux ioctl constants for block devices
BLKGETSIZE64 = 0x80081272  # Get device size in bytes
BLKSSZGET = 0x1268         # Get logical sector size
BLKBSZGET = 0x80041270     # Get block size
BLKPBSZGET = 0x127B        # Get physical sector size (kernel 2.6.32+)
BLKFLSBUF = 0x1261         # Flush buffer cache

# Error codes that indicate device issues (Linux errno values)
DEVICE_ERROR_CODES = frozenset({
    errno.EIO,        # 5: I/O error
    errno.ENXIO,      # 6: No such device or address
    errno.ENODEV,     # 19: No such device
    errno.EBUSY,      # 16: Device or resource busy
    errno.ETIMEDOUT,  # 110: Connection timed out
    errno.ENOMEDIUM,  # 123: No medium found
    errno.EMEDIUMTYPE,# 124: Wrong medium type
})


class ReadTimeoutError(OSError):
    """Raised when a read operation times out."""
    def __init__(self, offset: int, size: int, timeout_ms: int):
        self.offset = offset
        self.size = size
        self.timeout_ms = timeout_ms
        super().__init__(
            errno.ETIMEDOUT,
            f"Read timeout @ {offset} (+{size}) after {timeout_ms}ms"
        )


def _ioctl_with_retry(fd: int, request: int, buf: bytearray, retries: int = 3) -> bool:
    """Execute an ioctl with retry logic for transient failures."""
    import fcntl

    last_error = None
    for attempt in range(retries):
        try:
            fcntl.ioctl(fd, request, buf, True)
            return True
        except OSError as e:
            last_error = e
            if e.errno not in (errno.EAGAIN, errno.EINTR, errno.EBUSY):
                break
            time.sleep(0.1 * (attempt + 1))
    return False


def _query_device_size(fd: int, path: str, retries: int = 3) -> int:
    """
    Query device size using multiple methods with retry.

    Order of attempts:
    1. BLKGETSIZE64 ioctl (most accurate for block devices)
    2. lseek to end (works for files and some devices)
    3. stat (for regular files)
    """
    import fcntl

    # Method 1: BLKGETSIZE64 ioctl
    buf = bytearray(8)
    if _ioctl_with_retry(fd, BLKGETSIZE64, buf, retries):
        size = struct.unpack("<Q", buf)[0]
        if size > 0:
            return size

    # Method 2: lseek to end
    for attempt in range(retries):
        try:
            current = os.lseek(fd, 0, os.SEEK_CUR)
            size = os.lseek(fd, 0, os.SEEK_END)
            os.lseek(fd, current, os.SEEK_SET)
            if size > 0:
                return size
        except OSError:
            time.sleep(0.1 * (attempt + 1))

    # Method 3: stat (for regular files)
    try:
        st = os.fstat(fd)
        if st.st_size > 0:
            return st.st_size
    except OSError:
        pass

    return 0


def _query_sector_size(fd: int, retries: int = 3) -> int:
    """
    Query device sector size using ioctl.

    Tries physical sector size first, then logical sector size.
    Returns 512 as default if queries fail.
    """
    import fcntl

    # Try physical sector size first (more accurate for 4K drives)
    buf = bytearray(4)
    if _ioctl_with_retry(fd, BLKPBSZGET, buf, retries):
        size = struct.unpack("<I", buf)[0]
        if size in (512, 1024, 2048, 4096):
            return size

    # Fall back to logical sector size
    buf = bytearray(4)
    if _ioctl_with_retry(fd, BLKSSZGET, buf, retries):
        size = struct.unpack("<I", buf)[0]
        if size in (512, 1024, 2048, 4096):
            return size

    return 512


def _is_block_device(path: str) -> bool:
    """Check if path is a block device."""
    try:
        mode = os.stat(path).st_mode
        import stat
        return stat.S_ISBLK(mode)
    except OSError:
        return False


def _read_with_timeout_thread(fd: int, offset: int, size: int, timeout_ms: int) -> bytes:
    """
    Read with timeout using a helper thread.

    This approach works reliably for block devices where select/poll
    don't work as expected.
    """
    if timeout_ms <= 0:
        timeout_ms = 5000  # Default 5 second timeout

    result: dict[str, object] = {}
    done = threading.Event()

    def worker() -> None:
        try:
            if hasattr(os, 'pread'):
                data = os.pread(fd, size, offset)
            else:
                # Fallback for systems without pread
                current = os.lseek(fd, 0, os.SEEK_CUR)
                os.lseek(fd, offset, os.SEEK_SET)
                data = os.read(fd, size)
                os.lseek(fd, current, os.SEEK_SET)
            result["data"] = data
        except OSError as e:
            result["error"] = e
        finally:
            done.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    timeout_s = timeout_ms / 1000.0
    if not done.wait(timeout=max(0.1, timeout_s)):
        # Timeout occurred - we can't safely cancel the read,
        # but we can return an error
        raise ReadTimeoutError(offset, size, timeout_ms)

    err = result.get("error")
    if err is not None:
        raise err

    return result.get("data", b"")


def _align_read(offset: int, size: int, sector_size: int, device_size: int) -> tuple[int, int, int, int]:
    """
    Calculate aligned read parameters for raw device access.

    Returns (aligned_start, aligned_size, data_offset, data_size) where:
    - aligned_start: sector-aligned starting offset
    - aligned_size: sector-aligned read size
    - data_offset: offset within the read buffer where requested data starts
    - data_size: actual size of requested data (may be clamped)
    """
    if sector_size <= 0:
        sector_size = 512

    # Calculate aligned boundaries
    aligned_start = offset - (offset % sector_size)
    end_offset = offset + size
    aligned_end = ((end_offset + sector_size - 1) // sector_size) * sector_size
    aligned_size = aligned_end - aligned_start

    # Clamp to device size if known
    if device_size > 0:
        if aligned_start >= device_size:
            return aligned_start, 0, 0, 0
        if (aligned_start + aligned_size) > device_size:
            aligned_size = device_size - aligned_start
            # Re-align to sector boundary
            aligned_size -= aligned_size % sector_size

    if aligned_size <= 0:
        return aligned_start, 0, 0, 0

    data_offset = offset - aligned_start
    # Actual data size might be less if we hit device boundary
    if device_size > 0 and offset + size > device_size:
        data_size = max(0, device_size - offset)
    else:
        data_size = size

    return aligned_start, aligned_size, data_offset, data_size


@dataclass
class LinuxDiskSource(DiskSource):
    """
    Linux disk source with timeout support, sector alignment, and O_DIRECT.

    Provides the same capabilities as the Windows implementation:
    - Timeout-protected reads using threading
    - Sector-aligned reads for raw block devices
    - O_DIRECT mode for bypassing kernel cache
    - Device refresh/reconnect handling
    """
    path: str
    _fd: int
    _size: int
    _sector_size: int = 512
    _timeout_ms: int = 5000
    _use_direct: bool = False
    _is_block_device: bool = False
    _config: Optional[PyddeuConfig] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def size(self) -> int:
        return self._size

    def sector_size(self) -> int:
        return self._sector_size

    def read_at(self, offset: int, size: int) -> bytes:
        """
        Read data with timeout protection and sector alignment.

        For block devices:
        - Reads are aligned to sector boundaries
        - Timeout protection prevents blocking on faulty sectors

        Raises OSError on I/O errors or timeout.
        """
        if size <= 0:
            return b""

        with self._lock:
            if self._fd < 0:
                raise OSError(errno.EBADF, "Bad file descriptor")

            # For block devices, enforce sector alignment
            if self._is_block_device:
                aligned_start, aligned_size, data_offset, data_size = _align_read(
                    offset, size, self._sector_size, self._size
                )

                if aligned_size <= 0:
                    return b""

                # Read with timeout
                if self._timeout_ms > 0:
                    data = _read_with_timeout_thread(
                        self._fd, aligned_start, aligned_size, self._timeout_ms
                    )
                else:
                    if hasattr(os, 'pread'):
                        data = os.pread(self._fd, aligned_size, aligned_start)
                    else:
                        os.lseek(self._fd, aligned_start, os.SEEK_SET)
                        data = os.read(self._fd, aligned_size)

                # Extract the requested portion
                if not data:
                    return b""
                if data_offset >= len(data):
                    return b""
                return data[data_offset:data_offset + data_size]

            # For regular files, just read directly with timeout
            if self._timeout_ms > 0:
                data = _read_with_timeout_thread(self._fd, offset, size, self._timeout_ms)
            else:
                if hasattr(os, 'pread'):
                    data = os.pread(self._fd, size, offset)
                else:
                    os.lseek(self._fd, offset, os.SEEK_SET)
                    data = os.read(self._fd, size)

            return data

    def refresh(self) -> None:
        """Refresh handle after device reset."""
        if not self.refresh_with_timeout(timeout_s=5.0):
            raise OSError(errno.ETIMEDOUT, "Refresh timed out")

    def refresh_with_timeout(self, timeout_s: float = 5.0) -> bool:
        """
        Attempts to refresh the device handle with a timeout.

        Re-opens the device to get a fresh file descriptor after
        device reset or reconnection.
        """
        result: dict[str, object] = {}
        done = threading.Event()

        def worker() -> None:
            try:
                flags = os.O_RDONLY
                if hasattr(os, 'O_BINARY'):
                    flags |= os.O_BINARY
                if self._use_direct and hasattr(os, 'O_DIRECT'):
                    flags |= os.O_DIRECT

                new_fd = os.open(self.path, flags)
                try:
                    new_size = _query_device_size(new_fd, self.path)
                    new_sector = _query_sector_size(new_fd)
                    result["fd"] = new_fd
                    result["size"] = new_size
                    result["sector_size"] = new_sector
                except Exception:
                    try:
                        os.close(new_fd)
                    except Exception:
                        pass
                    raise
            except Exception as e:
                result["error"] = e
            finally:
                done.set()

        threading.Thread(target=worker, daemon=True).start()
        if not done.wait(timeout=max(0.1, timeout_s)):
            return False

        err = result.get("error")
        if err is not None:
            raise err

        new_fd = result["fd"]
        with self._lock:
            old_fd = self._fd
            self._fd = new_fd
            self._size = result.get("size", 0) or 0
            self._sector_size = result.get("sector_size", 512) or 512
            try:
                if old_fd >= 0:
                    os.close(old_fd)
            except Exception:
                pass

        return True

    def flush_cache(self) -> bool:
        """Flush kernel buffer cache for this device."""
        if not self._is_block_device:
            return True

        try:
            import fcntl
            buf = bytearray(0)
            fcntl.ioctl(self._fd, BLKFLSBUF, buf)
            return True
        except Exception:
            return False

    def close(self) -> None:
        with self._lock:
            if self._fd >= 0:
                try:
                    os.close(self._fd)
                except Exception:
                    pass
                self._fd = -1


@dataclass
class PosixPreadSource(DiskSource):
    """
    Simple POSIX source using pread for non-critical file access.

    This is a simpler implementation for regular files that don't need
    timeout protection or sector alignment.
    """
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
            pass


@dataclass
class PosixSeekSource(DiskSource):
    """
    Fallback POSIX source using seek+read for systems without pread.

    Thread-safe via locking.
    """
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
            pass


def open_posix_source(path: str, *, config: PyddeuConfig | None = None) -> DiskSource:
    """
    Open a POSIX disk source with appropriate features based on path type.

    For block devices (/dev/sdX, /dev/nvmeXnY):
    - Uses timeout-protected reads
    - Enforces sector alignment
    - Optionally uses O_DIRECT

    For regular files:
    - Uses simple pread or seek+read

    Config options used:
    - deviowait_ms: Read timeout in milliseconds (0 = no timeout)
    - buffer: Read buffer size hints
    """
    cfg = config or PyddeuConfig()
    timeout_ms = int(getattr(cfg, "deviowait_ms", 5000) or 5000)

    is_block = _is_block_device(path)
    use_direct = False

    # Build open flags
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    # Use O_DIRECT for block devices if available (bypasses kernel cache)
    # O_DIRECT may not be available on all systems (e.g., older kernels, some filesystems)
    if is_block and hasattr(os, "O_DIRECT"):
        # O_DIRECT requires sector-aligned buffers, which we handle
        try:
            test_fd = os.open(path, flags | os.O_DIRECT)
            os.close(test_fd)
            flags |= os.O_DIRECT
            use_direct = True
        except (OSError, AttributeError):
            # O_DIRECT not supported for this device or not available, use normal mode
            pass

    fd = os.open(path, flags)
    try:
        size = _query_device_size(fd, path, retries=3)
        sector_size = _query_sector_size(fd, retries=3) if is_block else 512
    except Exception:
        size = 0
        sector_size = 512

    # For block devices, use the full-featured LinuxDiskSource
    if is_block:
        return LinuxDiskSource(
            path=path,
            _fd=fd,
            _size=size,
            _sector_size=sector_size,
            _timeout_ms=timeout_ms,
            _use_direct=use_direct,
            _is_block_device=True,
            _config=cfg,
        )

    # For regular files with timeout configured, also use LinuxDiskSource
    if timeout_ms > 0:
        return LinuxDiskSource(
            path=path,
            _fd=fd,
            _size=size,
            _sector_size=sector_size,
            _timeout_ms=timeout_ms,
            _use_direct=False,
            _is_block_device=False,
            _config=cfg,
        )

    # For regular files without timeout, use simple implementations
    if hasattr(os, "pread"):
        return PosixPreadSource(path=path, _fd=fd, _size=size, _sector_size=sector_size)

    fp = os.fdopen(fd, "rb", buffering=0)
    return PosixSeekSource(
        path=path, _fp=fp, _size=size, _lock=threading.Lock(), _sector_size=sector_size
    )


def list_linux_devices() -> list[SourceInfo]:
    """
    List available block devices on Linux.

    Scans /sys/block for devices, filtering out virtual devices like
    loop and ram devices.
    """
    from pathlib import Path

    sources: list[SourceInfo] = []
    sys_block = Path("/sys/block")

    if not sys_block.exists():
        return sources

    for dev in sys_block.iterdir():
        name = dev.name

        # Skip virtual devices
        if name.startswith(("loop", "ram", "dm-", "md", "nbd", "zram")):
            continue

        # Get device size
        size_path = dev / "size"
        if not size_path.exists():
            continue

        try:
            sectors = int(size_path.read_text(encoding="utf-8").strip())
        except Exception:
            continue

        # Get model/description if available
        model_path = dev / "device" / "model"
        description = "block device"
        try:
            if model_path.exists():
                description = model_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass

        # Get rotational status (SSD vs HDD)
        rotational_path = dev / "queue" / "rotational"
        try:
            if rotational_path.exists():
                is_rotational = rotational_path.read_text(encoding="utf-8").strip() == "1"
                description += " (HDD)" if is_rotational else " (SSD)"
        except Exception:
            pass

        path = f"/dev/{name}"
        size_bytes = sectors * 512

        if size_bytes > 0:
            sources.append(SourceInfo(
                path=path,
                size=size_bytes,
                description=description
            ))

    return sources
