import sys
import ctypes
import struct

def hex_dump(data, start_curr=0):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{start_curr + i:08X}  {hex_bytes:<48}  {ascii_chars}")

def read_sector0(path):
    print(f"Opening {path}...")
    try:
        handle = ctypes.windll.kernel32.CreateFileW(
            path,
            0x80000000, # GENERIC_READ
            1 | 2,      # FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            3,          # OPEN_EXISTING
            0,
            None
        )
        if handle == -1:
            print(f"Failed to open {path}. Error: {ctypes.get_last_error()}")
            return
        
        print("Reading 512 bytes...")
        buf = ctypes.create_string_buffer(512)
        bytes_read = ctypes.c_ulong(0)
        success = ctypes.windll.kernel32.ReadFile(handle, buf, 512, ctypes.byref(bytes_read), None)
        
        ctypes.windll.kernel32.CloseHandle(handle)
        
        if not success:
            print(f"ReadFile failed. Error: {ctypes.get_last_error()}")
            return
            
        data = buf.raw[:bytes_read.value]
        print(f"Read {len(data)} bytes.")
        hex_dump(data)
        
        if len(data) >= 512:
            sig = data[510:512]
            print(f"Signature: {sig.hex()}")
            
            # Check partition entries
            print("\nPartition Table Entries:")
            for i in range(4):
                offset = 446 + i*16
                entry = data[offset : offset+16]
                p_type = entry[4]
                lba = struct.unpack_from("<I", entry, 8)[0]
                size = struct.unpack_from("<I", entry, 12)[0]
                print(f"Entry {i}: Type={p_type:02X}, LBA={lba}, Size={size}")
                
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = r"\\.\PhysicalDrive0"
    
    read_sector0(path)
