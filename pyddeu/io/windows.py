from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import threading

from .base import DiskSource, SourceInfo

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# --- Sabitler ---
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_BEGIN = 0

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# --- Yapılar ---


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

# --- Kernel32 Tanımları ---
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
    wintypes.LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.SetFilePointerEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_longlong,
    ctypes.POINTER(ctypes.c_longlong),
    wintypes.DWORD,
]
kernel32.SetFilePointerEx.restype = wintypes.BOOL

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


def _raise_last_error(prefix: str) -> None:
    err = ctypes.get_last_error()
    raise OSError(err, f"{prefix} (winerr={err})")


def _query_size(handle: int) -> int:
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


def _query_sector_size(handle: int) -> int:
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
        if bps in (512, 1024, 2048, 4096):
            return bps
    return 512


@dataclass
class WindowsSyncSource(DiskSource):
    path: str
    _handle: int
    _size: int
    _sector_size: int
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def size(self) -> int:
        return self._size

    def sector_size(self) -> int:
        return self._sector_size

    def refresh(self) -> None:
        """
        Best-effort handle refresh after a device reset/controller panic.
        """
        with self._lock:
            try:
                if self._handle != INVALID_HANDLE_VALUE:
                    kernel32.CloseHandle(self._handle)
            except Exception:
                pass

            handle = kernel32.CreateFileW(
                self.path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if handle == INVALID_HANDLE_VALUE:
                self._handle = INVALID_HANDLE_VALUE
                _raise_last_error(f"CreateFileW failed for {self.path!r}")

            self._handle = handle
            self._size = _query_size(handle)
            self._sector_size = _query_sector_size(handle)

    def read_at(self, offset: int, size: int) -> bytes:
        """
        Senkron ve Sektör Hizalı Okuma (Synchronous Aligned Read).
        Error 87/22'yi önlemek için her zaman sektör hizalı okuma yapar.
        """
        if size <= 0:
            return b""

        with self._lock:
            if self._handle == INVALID_HANDLE_VALUE:
                return b""

            sector = int(self._sector_size or 512)
            if sector <= 0:
                sector = 512

            # Hizalama Hesaplaması
            aligned_start = offset - (offset % sector)
            end_offset = offset + size
            aligned_end = ((end_offset + sector - 1) // sector) * sector
            aligned_read_len = aligned_end - aligned_start

            if self._size > 0 and aligned_start >= self._size:
                return b""

            # Disk sonunu aşma kontrolü (ve 87 önlemek için sektöre hizala)
            if self._size > 0 and (aligned_start + aligned_read_len) > self._size:
                aligned_read_len = self._size - aligned_start
                aligned_read_len -= aligned_read_len % sector

            if aligned_read_len <= 0:
                return b""

            # ReadFile DWORD size sınırı
            max_dword = 0xFFFFFFFF
            if aligned_read_len > max_dword:
                aligned_read_len = max_dword - (max_dword % sector)
                if aligned_read_len <= 0:
                    return b""

            # 1. İmleci ayarla
            ptr = ctypes.c_longlong(aligned_start)
            if not kernel32.SetFilePointerEx(self._handle, ptr, None, FILE_BEGIN):
                _raise_last_error(f"SetFilePointerEx failed @ {aligned_start}")

            # 2. Oku
            buf = ctypes.create_string_buffer(aligned_read_len)
            read_bytes = wintypes.DWORD()

            ok = kernel32.ReadFile(self._handle, buf, aligned_read_len, ctypes.byref(read_bytes), None)
            if not ok:
                # Okuma başarısız olursa OSError fırlat (Üst katman bunu Bad Sector olarak işaretler)
                _raise_last_error(f"ReadFile failed @ {aligned_start}")

            actual_len = int(read_bytes.value)
            if actual_len <= 0:
                return b""

            # 3. İstenen veriyi kesip al
            data_start = offset - aligned_start
            data_end = data_start + size
            available_data = buf.raw[:actual_len]

            if data_start >= len(available_data):
                return b""
            return available_data[data_start:data_end]

    def close(self) -> None:
        with self._lock:
            if self._handle != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(self._handle)
                self._handle = INVALID_HANDLE_VALUE


def open_windows_source(path: str) -> DiskSource:
    # FILE_FLAG_OVERLAPPED yok -> Senkron Mod (Daha güvenli)
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )

    if handle == INVALID_HANDLE_VALUE:
        _raise_last_error(f"CreateFileW failed for {path!r}")

    size = _query_size(handle)
    sector_size = _query_sector_size(handle)

    return WindowsSyncSource(path=path, _handle=handle, _size=size, _sector_size=sector_size)


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
