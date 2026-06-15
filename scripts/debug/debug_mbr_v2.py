import sys
import ctypes
from ctypes import wintypes
import struct

# Constants
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_OVERLAPPED = 0x40000000

def hex_dump(data, start_curr=0):
    for i in range(0, min(len(data), 512), 16):
        chunk = data[i:i+16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{start_curr + i:08X}  {hex_bytes:<48}  {ascii_chars}")

def read_test(path, use_no_buffering=False, size=512):
    print(f"\n--- Testing read on {path} (NoBuffering={use_no_buffering}, Size={size}) ---")
    
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, 
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
    ]
    k32.CreateFileW.restype = wintypes.HANDLE
    
    k32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, 
        ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
    ]
    k32.ReadFile.restype = wintypes.BOOL

    k32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k32.VirtualAlloc.restype = wintypes.LPVOID
    
    k32.VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
    k32.VirtualFree.restype = wintypes.BOOL

    flags = 0
    if use_no_buffering:
        flags |= FILE_FLAG_NO_BUFFERING
        
    handle = k32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        flags,
        None
    )
    
    if handle == -1:
        print(f"CreateFile failed. Error: {ctypes.get_last_error()}")
        return

    try:
        # Buffer alignment for NO_BUFFERING (safe bet: 4096 alignment)
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04
        
        alloc_size = max(size, 4096)
        
        buf_addr = k32.VirtualAlloc(None, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not buf_addr:
             print("VirtualAlloc failed")
             return

        bytes_read = wintypes.DWORD(0)
        
        print(f"Reading {size} bytes to {buf_addr}...")
        success = k32.ReadFile(handle, buf_addr, size, ctypes.byref(bytes_read), None)
        
        if success:
            print(f"Read success! Bytes read: {bytes_read.value}")
            data = ctypes.string_at(buf_addr, bytes_read.value)
            hex_dump(data)
            if len(data) >= 512:
                 print(f"Sig: {data[510:512].hex()}")
        else:
            print(f"ReadFile failed. Error: {ctypes.get_last_error()}")
            
        k32.VirtualFree(buf_addr, 0, 0x8000) # MEM_RELEASE
        
    finally:
        k32.CloseHandle(handle)

if __name__ == "__main__":
    path = r"\\.\PhysicalDrive0" 
    if len(sys.argv) > 1: path = sys.argv[1]
    
    # read_test(path, use_no_buffering=False, size=4096) # Likely to hang if buffered hangs
    read_test(path, use_no_buffering=True, size=512)
    read_test(path, use_no_buffering=True, size=4096)
