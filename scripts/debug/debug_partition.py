"""
Debug script to check the NTFS boot sector at LBA 327682048 ($Noname 03)
"""
import sys
sys.path.insert(0, r"c:\Users\oguza\DDUE Recovery Project P1")

from pyddeu.io import open_source
from pyddeu.ntfs_boot import parse_ntfs_boot_sector
from pyddeu.config import PyddeuConfig

def hex_dump(data, start=0, limit=256):
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i+16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{start + i:08X}  {hex_bytes:<48}  {ascii_chars}")

def main():
    from pyddeu.config import default_config_path
    config = PyddeuConfig.load(default_config_path())
    
    target_lba = 327682048
    sector_size = 512
    target_offset = target_lba * sector_size
    
    print(f"Opening PhysicalDrive0...")
    src = open_source(r"\\.\PhysicalDrive0", config=config)
    print(f"Disk size: {src.size()} bytes ({src.size() / (1024**3):.2f} GB)")
    print(f"Sector size: {src.sector_size()}")
    
    print(f"\n=== Reading boot sector at LBA {target_lba} (offset {target_offset}) ===")
    
    try:
        data = src.read_at(target_offset, 512)
        print(f"Read {len(data)} bytes")
        
        if len(data) >= 512:
            print("\nHex dump of first 256 bytes:")
            hex_dump(data, target_offset, 256)
            
            print(f"\nSignature at 510-511: {data[510:512].hex()}")
            print(f"OEM ID at 3-10: {data[3:11]}")
            
            # Try to parse as NTFS
            boot = parse_ntfs_boot_sector(data)
            if boot:
                print("\n=== NTFS BOOT SECTOR PARSED SUCCESSFULLY ===")
                print(f"  Bytes per sector: {boot.bytes_per_sector}")
                print(f"  Sectors per cluster: {boot.sectors_per_cluster}")
                print(f"  Total sectors: {boot.total_sectors}")
                print(f"  Volume size: {boot.volume_size_bytes / (1024**3):.2f} GB")
                print(f"  MFT LCN: {boot.mft_lcn}")
                print(f"  MFT Mirror LCN: {boot.mftmirr_lcn}")
                print(f"  File record size: {boot.file_record_size}")
                print(f"  Cluster size: {boot.cluster_size}")
                
                # Check MFT location
                mft_offset = target_offset + (boot.mft_lcn * boot.cluster_size)
                print(f"\n=== Checking MFT at offset {mft_offset} ===")
                mft_data = src.read_at(mft_offset, 1024)
                print(f"Read {len(mft_data)} bytes from MFT")
                if mft_data and len(mft_data) >= 4:
                    print(f"MFT signature: {mft_data[:4]}")
                    if mft_data[:4] == b"FILE":
                        print("MFT IS ACCESSIBLE!")
                    else:
                        print("MFT signature mismatch - MFT may be damaged or at different location")
                    hex_dump(mft_data, mft_offset, 64)
            else:
                print("\n=== NTFS PARSE FAILED ===")
                print("This boot sector does not appear to be valid NTFS")
                
                # Check what might be wrong
                if data[3:7] != b"NTFS":
                    print(f"  - OEM ID is not 'NTFS': {data[3:7]}")
                if data[510:512] != b"\x55\xAA":
                    print(f"  - Boot signature is not 55AA: {data[510:512].hex()}")
        else:
            print(f"Read returned only {len(data)} bytes - READ FAILURE")
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        src.close()

if __name__ == "__main__":
    main()
