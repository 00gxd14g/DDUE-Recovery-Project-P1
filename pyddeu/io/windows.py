from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import threading
import os

from .base import DiskSource, SourceInfo


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_OVERLAPPED = 0x40000000

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class GET_LENGTH_INFORMATION(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_longlong)]

class DISK_GEOMETRY(ctypes.Structure):
    _fields_ = [
        ("Cylinders", ctypes.c_longlong),
        ("MediaType", wintypes.DWORD),
        ("TracksPerCylinder", wintypes.DWORD),
        ("SectorsPerTrack", wintypes.DWORD),
        ("BytesPerSector", wintypes.DWORD),
    ]


class DISK_GEOMETRY_EX(ctypes.Structure):
    _fields_ = [
        ("Geometry", DISK_GEOMETRY),
        ("DiskSize", ctypes.c_longlong),
        ("Data", ctypes.c_byte * 1),
    ]


IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0


kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(OVERLAPPED),
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.GetOverlappedResult.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(OVERLAPPED),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]
kernel32.GetOverlappedResult.restype = wintypes.BOOL

kernel32.DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.DeviceIoControl.restype = wintypes.BOOL

kernel32.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
kernel32.GetFileSizeEx.restype = wintypes.BOOL

kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
kernel32.CancelIoEx.restype = wintypes.BOOL

WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
INFINITE = 0xFFFFFFFF


def _raise_last_error(prefix: str) -> None:
    err = ctypes.get_last_error()
    raise OSError(err, f"{prefix} (winerr={err})")


def _query_size(handle: wintypes.HANDLE) -> int:
    size = ctypes.c_longlong()
    if kernel32.GetFileSizeEx(handle, ctypes.byref(size)):
        return int(size.value)

    out = GET_LENGTH_INFORMATION()
    returned = wintypes.DWORD()
    ok = kernel32.DeviceIoControl(
        handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        None,
        0,
        ctypes.byref(out),
        ctypes.sizeof(out),
        ctypes.byref(returned),
        None,
    )
    if ok:
        return int(out.Length)

    return 0


def _query_sector_size(handle: wintypes.HANDLE) -> int:
    geom = DISK_GEOMETRY_EX()
    returned = wintypes.DWORD()
    ok = kernel32.DeviceIoControl(
        handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        None,
        0,
        ctypes.byref(geom),
        ctypes.sizeof(geom),
        ctypes.byref(returned),
        None,
    )
    if ok:
        bps = int(geom.Geometry.BytesPerSector)
        if bps in (512, 4096):
            return bps
        if bps > 0:
            return bps
    return 512


@dataclass
class WindowsOverlappedSource(DiskSource):
    path: str
    _handle: wintypes.HANDLE
    _size: int
    _sector_size: int
    _timeout_ms: int = 3000
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def size(self) -> int:
        return self._size

    def sector_size(self) -> int:
        return self._sector_size

    def refresh(self) -> None:
        """
        Best-effort handle refresh after a device reset.
        """
        with self._lock:
            try:
                if self._handle and self._handle != INVALID_HANDLE_VALUE:
                    kernel32.CloseHandle(self._handle)
            except Exception:
                pass

            handle = kernel32.CreateFileW(
                self.path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
            if handle == INVALID_HANDLE_VALUE:
                _raise_last_error(f"CreateFileW failed for {self.path!r}")

            self._handle = handle
            self._size = _query_size(handle)
            self._sector_size = _query_sector_size(handle)

    def _read_aligned(self, offset: int, size: int) -> bytes:
        if size <= 0:
            return b""

        buf = ctypes.create_string_buffer(size)
        ov = OVERLAPPED()
        ov.Offset = wintypes.DWORD(offset & 0xFFFFFFFF)
        ov.OffsetHigh = wintypes.DWORD((offset >> 32) & 0xFFFFFFFF)
        ov.hEvent = kernel32.CreateEventW(None, True, False, None)
        if not ov.hEvent:
            _raise_last_error("CreateEventW failed")
        read = wintypes.DWORD(0)

        try:
            ok = kernel32.ReadFile(self._handle, buf, size, ctypes.byref(read), ctypes.byref(ov))
            if not ok:
                err = ctypes.get_last_error()
                if err != 997:  # ERROR_IO_PENDING
                    _raise_last_error(f"ReadFile failed at offset={offset} size={size}")

                timeout = int(self._timeout_ms) if int(self._timeout_ms) > 0 else INFINITE
                w = kernel32.WaitForSingleObject(ov.hEvent, timeout)
                if w == WAIT_TIMEOUT:
                    try:
                        kernel32.CancelIoEx(self._handle, ctypes.byref(ov))
                    except Exception:
                        pass
                    raise OSError(995, f"Read timed out at offset={offset} size={size}")
                if w != WAIT_OBJECT_0:
                    _raise_last_error(f"WaitForSingleObject failed at offset={offset} size={size}")

                ok2 = kernel32.GetOverlappedResult(self._handle, ctypes.byref(ov), ctypes.byref(read), False)
                if not ok2:
                    _raise_last_error(f"GetOverlappedResult failed at offset={offset} size={size}")

            return buf.raw[: int(read.value)]
        finally:
            try:
                if ov.hEvent:
                    kernel32.CloseHandle(ov.hEvent)
            except Exception:
                pass

    def read_at(self, offset: int, size: int) -> bytes:
        """
        DMDE-style aligned buffering:
        Many Windows disk devices reject unaligned or sub-sector reads with ERROR_INVALID_PARAMETER (87).
        We always read whole sectors from an aligned offset, then slice the requested bytes from RAM.
        """
        with self._lock:
            if size <= 0:
                return b""

            sector = int(self._sector_size or 512)
            if sector <= 0:
                sector = 512

            dev_size = int(self._size or 0)
            if dev_size > 0 and offset >= dev_size:
                return b""

            aligned_off = offset - (offset % sector)
            end = offset + size
            aligned_end = ((end + sector - 1) // sector) * sector
            aligned_size = aligned_end - aligned_off

            if dev_size > 0:
                max_read = dev_size - aligned_off
                if max_read <= 0:
                    return b""
                if aligned_size > max_read:
                    aligned_size = max_read
                    aligned_size -= aligned_size % sector
                    if aligned_size <= 0:
                        return b""

            # Fast path: already aligned
            if aligned_off == offset and aligned_size == size:
                return self._read_aligned(offset, size)

            data = self._read_aligned(aligned_off, aligned_size)
            rel = offset - aligned_off
            sliced = data[rel : rel + size]
            if len(sliced) < size:
                sliced += b"\x00" * (size - len(sliced))
            return sliced

    def close(self) -> None:
        with self._lock:
            if self._handle and self._handle != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(self._handle)
                self._handle = wintypes.HANDLE(INVALID_HANDLE_VALUE)


def open_windows_source(path: str) -> DiskSource:
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        _raise_last_error(f"CreateFileW failed for {path!r}")

    size = _query_size(handle)
    sector_size = _query_sector_size(handle)
    try:
        timeout_ms = int(os.getenv("PYDDEU_TIMEOUT_MS", "3000").strip() or "3000")
    except Exception:
        timeout_ms = 3000
    return WindowsOverlappedSource(
        path=path, _handle=handle, _size=size, _sector_size=sector_size, _timeout_ms=timeout_ms
    )


def list_physical_drives(max_index: int = 32) -> list[SourceInfo]:
    drives: list[SourceInfo] = []
    for idx in range(max_index):
        path = rf"\\.\PhysicalDrive{idx}"
        try:
            src = open_windows_source(path)
            size = src.size()
            src.close()
            if size > 0:
                drives.append(SourceInfo(path=path, size=size, description="PhysicalDrive"))
        except OSError:
            continue
    return drives
