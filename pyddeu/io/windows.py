from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import struct
import threading

from .base import DiskSource, SourceInfo
from ..config import PyddeuConfig

# ULONG_PTR wintypes modülünde her zaman mevcut değil (Python 3.11+).
# Platform mimarisine göre doğru türü tanımlıyoruz.
if not hasattr(wintypes, 'ULONG_PTR'):
    # 64-bit sistemlerde 8 byte, 32-bit sistemlerde 4 byte pointer
    if struct.calcsize('P') == 8:
        wintypes.ULONG_PTR = ctypes.c_ulonglong
    else:
        wintypes.ULONG_PTR = ctypes.c_ulong

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# --- Sabitler ---
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_BEGIN = 0
FILE_FLAG_OVERLAPPED = 0x40000000

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# --- Privilege helpers ---
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x0002
ERROR_NOT_ALL_ASSIGNED = 1300

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
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

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

kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE

kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.GetOverlappedResult.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]
kernel32.GetOverlappedResult.restype = wintypes.BOOL

kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
kernel32.CancelIoEx.restype = wintypes.BOOL

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

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

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID), ("Attributes", wintypes.DWORD)]


kernel32.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
kernel32.GetFileSizeEx.restype = wintypes.BOOL

kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE

advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,
    wintypes.BOOL,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL


_PRIVS_TRIED = False


def _enable_privilege(name: str) -> bool:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)
    ):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES(1, luid, SE_PRIVILEGE_ENABLED)
        if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
            return False
        err = ctypes.get_last_error()
        if err == ERROR_NOT_ALL_ASSIGNED:
            return False
        return True
    finally:
        try:
            kernel32.CloseHandle(token)
        except Exception:
            pass


def _try_enable_privileges() -> None:
    global _PRIVS_TRIED
    if _PRIVS_TRIED:
        return
    _PRIVS_TRIED = True
    # Best-effort. These can improve raw disk access on Windows.
    _enable_privilege("SeBackupPrivilege")
    _enable_privilege("SeManageVolumePrivilege")


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", wintypes.ULONG_PTR),
        ("InternalHigh", wintypes.ULONG_PTR),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


def _read_overlapped_timeout(handle: int, offset: int, size: int, timeout_ms: int) -> bytes:
    if size <= 0:
        return b""
    if timeout_ms <= 0:
        timeout_ms = 1

    evt = kernel32.CreateEventW(None, True, False, None)
    if evt == 0:
        _raise_last_error("CreateEventW failed")

    try:
        ov = OVERLAPPED()
        ov.Offset = wintypes.DWORD(offset & 0xFFFFFFFF)
        ov.OffsetHigh = wintypes.DWORD((offset >> 32) & 0xFFFFFFFF)
        ov.hEvent = evt

        buf = ctypes.create_string_buffer(int(size))
        read_bytes = wintypes.DWORD(0)

        ok = kernel32.ReadFile(handle, buf, int(size), ctypes.byref(read_bytes), ctypes.byref(ov))
        if not ok:
            err = ctypes.get_last_error()
            if err != ERROR_IO_PENDING:
                raise OSError(err, f"ReadFile failed @ {offset} (winerr={err})")

            wait = kernel32.WaitForSingleObject(evt, int(timeout_ms))
            if wait == WAIT_TIMEOUT:
                try:
                    kernel32.CancelIoEx(handle, ctypes.byref(ov))
                except Exception:
                    pass
                raise OSError(1460, f"ReadFile timeout @ {offset} (+{size}) (winerr=1460)")
            if wait != WAIT_OBJECT_0:
                raise OSError(int(wait), f"WaitForSingleObject failed @ {offset} (code={wait})")

            ok2 = kernel32.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(read_bytes), False)
            if not ok2:
                _raise_last_error(f"GetOverlappedResult failed @ {offset}")

        actual = int(read_bytes.value)
        if actual <= 0:
            return b""
        return buf.raw[:actual]
    finally:
        try:
            kernel32.CloseHandle(evt)
        except Exception:
            pass


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
    _overlapped_timeout_ms: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def size(self) -> int:
        return self._size

    def sector_size(self) -> int:
        return self._sector_size

    def refresh(self) -> None:
        """
        Best-effort handle refresh after a device reset/controller panic.
        """
        if not self.refresh_with_timeout(timeout_s=5.0):
            raise OSError("Refresh timed out")

    def refresh_with_timeout(self, timeout_s: float = 5.0) -> bool:
        """
        Attempts a best-effort refresh but returns if it takes too long.

        Note: During controller resets, Windows storage APIs may block. This runs
        the open/query work in a helper thread and only swaps handles if it finishes.
        """
        timeout_s = float(timeout_s)
        result: dict[str, object] = {}
        done = threading.Event()

        def worker() -> None:
            try:
                _try_enable_privileges()
                flags = FILE_ATTRIBUTE_NORMAL
                if int(self._overlapped_timeout_ms or 0) > 0:
                    flags |= FILE_FLAG_OVERLAPPED

                handle = kernel32.CreateFileW(
                    self.path,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    flags,
                    None,
                )
                if handle == INVALID_HANDLE_VALUE:
                    _raise_last_error(f"CreateFileW failed for {self.path!r}")
                try:
                    size = _query_size(handle)
                    sector_size = _query_sector_size(handle)
                    result["handle"] = int(handle)
                    result["size"] = int(size)
                    result["sector_size"] = int(sector_size)
                except Exception:
                    try:
                        kernel32.CloseHandle(handle)
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
            raise err  # type: ignore[misc]

        new_handle = int(result["handle"])  # type: ignore[arg-type]
        new_size = int(result.get("size", 0) or 0)
        new_sector_size = int(result.get("sector_size", 512) or 512)

        with self._lock:
            old = self._handle
            self._handle = new_handle
            self._size = new_size
            self._sector_size = new_sector_size
            try:
                if old != INVALID_HANDLE_VALUE:
                    kernel32.CloseHandle(old)
            except Exception:
                pass
        return True

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

            # Timeout'lu overlapped okuma: controller reset aninda bloklanmayi azaltir.
            if int(self._overlapped_timeout_ms or 0) > 0:
                # Async modda sadece overlapped okuma denenir. Hata olursa fırlatılır.
                try:
                    available_data = _read_overlapped_timeout(
                        int(self._handle),
                        int(aligned_start),
                        int(aligned_read_len),
                        int(self._overlapped_timeout_ms),
                    )
                    if not available_data:
                        return b""
                    data_start = offset - aligned_start
                    data_end = data_start + size
                    if data_start >= len(available_data):
                        return b""
                    return available_data[data_start:data_end]
                except OSError:
                    # Async okuma yapılandırılmışsa ve hata aldıysak, senkron okumaya DÜŞMEMELİYİZ
                    # çünkü handle async modda açılmış olabilir ve senkron okuma beklenmedik davranabilir,
                    # veya hata timeout kaynaklıdır ve senkron okuma sonsuza kadar bloklayabilir.
                    raise

            # --- Senkron Okuma (Sadece timeout=0 ise buraya gelir) ---

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


def open_windows_source(path: str, *, config: PyddeuConfig | None = None) -> DiskSource:
    _try_enable_privileges()
    cfg = config or PyddeuConfig()
    timeout = int(getattr(cfg, "deviowait_ms", 0) or 0)

    flags = FILE_ATTRIBUTE_NORMAL
    if timeout > 0:
        flags |= FILE_FLAG_OVERLAPPED

    # FILE_FLAG_OVERLAPPED yok -> Senkron Mod (Daha güvenli)
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        flags,
        None,
    )

    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        # Access denied on PhysicalDrive: try GLOBALROOT path as a fallback.
        if err == 5 and path.lower().startswith(r"\\.\physicaldrive"):
            try:
                idx = int(path.split("PhysicalDrive", 1)[-1])
                alt_path = rf"\\?\GLOBALROOT\Device\Harddisk{idx}\DR0"
                handle = kernel32.CreateFileW(
                    alt_path,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    flags,
                    None,
                )
                if handle != INVALID_HANDLE_VALUE:
                    path = alt_path
                else:
                    ctypes.set_last_error(err)
                    _raise_last_error(f"CreateFileW failed for {path!r}")
            except Exception:
                ctypes.set_last_error(err)
                _raise_last_error(f"CreateFileW failed for {path!r}")
        else:
            ctypes.set_last_error(err)
            _raise_last_error(f"CreateFileW failed for {path!r}")

    size = _query_size(handle)
    sector_size = _query_sector_size(handle)

    # dmde.ini: deviowait=0 disables overlapped; deviowait>0 is cancel timeout (ms).
    return WindowsSyncSource(
        path=path,
        _handle=handle,
        _size=size,
        _sector_size=sector_size,
        _overlapped_timeout_ms=timeout,
    )


def list_physical_drives(max_index: int = 32) -> list[SourceInfo]:
    _try_enable_privileges()
    drives: list[SourceInfo] = []
    for idx in range(max_index):
        path = rf"\\.\PhysicalDrive{idx}"
        try:
            src = open_windows_source(path)
            size = src.size()
            src.close()
            # Even if size is unknown, keep the device so the user can select it.
            drives.append(SourceInfo(path=path, size=size, description="PhysicalDrive"))
        except OSError:
            continue
    if drives:
        return drives

    # Fallback: use WMI via PowerShell to list disks without opening raw handles.
    # This helps when CreateFileW is blocked by policy or antivirus.
    try:
        import json
        import subprocess

        ps_cmd = (
            "Get-CimInstance Win32_DiskDrive | "
            "Select-Object DeviceID, Size, Model | "
            "ConvertTo-Json -Compress"
        )
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            text=True,
            errors="ignore",
        )
        if not out.strip():
            return drives
        data = json.loads(out)
        items = data if isinstance(data, list) else [data]
        for item in items:
            device = str(item.get("DeviceID") or "").strip()
            if not device:
                continue
            # Normalize to \\.\PhysicalDriveN when possible.
            if device.upper().startswith("\\\\.\\PHYSICALDRIVE"):
                path = "\\\\.\\" + "PhysicalDrive" + device.split("PHYSICALDRIVE", 1)[-1]
            elif device.upper().startswith("PHYSICALDRIVE"):
                path = "\\\\.\\" + "PhysicalDrive" + device.split("PHYSICALDRIVE", 1)[-1]
            else:
                path = device
            try:
                size_val = int(item.get("Size") or 0)
            except Exception:
                size_val = 0
            model = str(item.get("Model") or "Disk").strip()
            drives.append(SourceInfo(path=path, size=size_val, description=model))
    except Exception:
        return drives

    return drives
