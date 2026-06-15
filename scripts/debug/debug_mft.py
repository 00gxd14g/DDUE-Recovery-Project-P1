"""
Debug script to analyze the $MFT file and its data runs in detail
"""
import sys
import struct
sys.path.insert(0, r"c:\Users\oguza\DDUE Recovery Project P1")

from pyddeu.io import open_source
from pyddeu.ntfs_boot import parse_ntfs_boot_sector
from pyddeu.config import PyddeuConfig, default_config_path
from pyddeu.mft import _decode_runlist_to_lcns

def hex_dump(data, start=0, limit=128):
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i+16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{start + i:08X}  {hex_bytes:<48}  {ascii_chars}")

def safe_read(src, offset, size, retries=3):
    """Read with retry logic for flaky disks"""
    import time
    for attempt in range(retries):
        try:
            return src.read_at(offset, size)
        except OSError as e:
            print(f"  Read error at offset {offset}: {e} (attempt {attempt+1}/{retries})")
            time.sleep(1)
    return None

def main():
    config = PyddeuConfig.load(default_config_path())
    
    target_lba = 327682048
    sector_size = 512
    target_offset = target_lba * sector_size
    
    print(f"Opening PhysicalDrive0...")
    src = open_source(r"\\.\PhysicalDrive0", config=config)
    
    # Parse NTFS boot sector
    boot_data = safe_read(src, target_offset, 512)
    if not boot_data:
        print("ERROR: Could not read boot sector")
        return
        
    boot = parse_ntfs_boot_sector(boot_data)
    
    if not boot:
        print("ERROR: Could not parse NTFS boot sector")
        return
        
    print(f"NTFS Boot Info:")
    print(f"  Volume size: {boot.volume_size_bytes / (1024**3):.2f} GB")
    print(f"  Cluster size: {boot.cluster_size} bytes")
    print(f"  MFT LCN: {boot.mft_lcn}")
    print(f"  File record size: {boot.file_record_size} bytes")
    
    # Read $MFT (record 0)
    mft_offset = target_offset + (boot.mft_lcn * boot.cluster_size)
    print(f"\n=== Reading $MFT at offset {mft_offset} ===")
    
    mft_record = safe_read(src, mft_offset, boot.file_record_size)
    if not mft_record:
        print("ERROR: Could not read $MFT record")
        return
    
    if mft_record[:4] != b"FILE":
        print("ERROR: $MFT signature not found")
        return
    
    print("$MFT record found!")
    
    # Parse $MFT attributes to find $DATA
    attr_off = struct.unpack_from("<H", mft_record, 20)[0]
    print(f"First attribute offset: {attr_off}")
    
    off = attr_off
    data_attr_count = 0
    total_mft_size = 0
    all_runs = []
    
    while off + 16 <= len(mft_record):
        attr_type = struct.unpack_from("<I", mft_record, off)[0]
        if attr_type == 0xFFFFFFFF:
            print(f"  End of attributes marker at offset {off}")
            break
            
        attr_len = struct.unpack_from("<I", mft_record, off + 4)[0]
        if attr_len <= 0 or off + attr_len > len(mft_record):
            print(f"  Invalid attribute length at offset {off}")
            break
            
        non_res = mft_record[off + 8]
        name_len = mft_record[off + 9]
        
        attr_names = {
            0x10: "$STANDARD_INFORMATION",
            0x30: "$FILE_NAME",
            0x40: "$OBJECT_ID",
            0x50: "$SECURITY_DESCRIPTOR",
            0x60: "$VOLUME_NAME",
            0x70: "$VOLUME_INFORMATION",
            0x80: "$DATA",
            0x90: "$INDEX_ROOT",
            0xA0: "$INDEX_ALLOCATION",
            0xB0: "$BITMAP",
        }
        
        attr_name = attr_names.get(attr_type, f"0x{attr_type:02X}")
        resident_str = "Non-Resident" if non_res else "Resident"
        
        print(f"  Attr @ {off}: {attr_name} ({resident_str}, len={attr_len})")
        
        if attr_type == 0x80:  # $DATA
            data_attr_count += 1
            
            if non_res == 1:
                # Parse non-resident data attribute
                run_off = struct.unpack_from("<H", mft_record, off + 32)[0]
                alloc_size = struct.unpack_from("<Q", mft_record, off + 40)[0]
                real_size = struct.unpack_from("<Q", mft_record, off + 48)[0]
                
                print(f"    $DATA is non-resident:")
                print(f"      Allocated size: {alloc_size:,} bytes ({alloc_size / (1024**2):.2f} MB)")
                print(f"      Real size: {real_size:,} bytes ({real_size / (1024**2):.2f} MB)")
                print(f"      Run list offset: {run_off}")
                
                # Decode runlist
                runlist = mft_record[off + run_off : off + attr_len]
                print(f"      Runlist raw ({len(runlist)} bytes):")
                hex_dump(runlist[:64], 0, 64)
                
                runs = _decode_runlist_to_lcns(runlist)
                print(f"      Decoded {len(runs)} run(s):")
                
                total_clusters = 0
                for i, (lcn, length) in enumerate(runs):
                    size_bytes = length * boot.cluster_size
                    records = size_bytes // boot.file_record_size
                    total_clusters += length
                    print(f"        Run {i}: LCN={lcn}, Length={length} clusters ({size_bytes:,} bytes, ~{records} records)")
                    all_runs.append((lcn, length))
                
                total_size = total_clusters * boot.cluster_size
                total_mft_size += total_size
                print(f"      Total in this $DATA: {total_clusters} clusters = {total_size:,} bytes ({total_size / (1024**2):.2f} MB)")
            else:
                print(f"    $DATA is resident (small)")
                
        off += attr_len
    
    print(f"\n=== SUMMARY ===")
    print(f"Found {data_attr_count} $DATA attribute(s)")
    print(f"Total MFT size: {total_mft_size:,} bytes ({total_mft_size / (1024**2):.2f} MB)")
    expected_records = total_mft_size // boot.file_record_size
    print(f"Expected MFT records: {expected_records:,}")
    print(f"Total runs: {len(all_runs)}")
    
    # Check if there might be more MFT data in attribute list
    # (MFT can have multiple $DATA attributes or use attribute list for large MFT)
    if data_attr_count == 1 and expected_records < 10000:
        print("\nWARNING: MFT seems small. Checking for $ATTRIBUTE_LIST...")
        
        # Re-scan for $ATTRIBUTE_LIST (0x20)
        off = attr_off
        while off + 16 <= len(mft_record):
            attr_type = struct.unpack_from("<I", mft_record, off)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack_from("<I", mft_record, off + 4)[0]
            if attr_len <= 0:
                break
                
            if attr_type == 0x20:  # $ATTRIBUTE_LIST
                print("  Found $ATTRIBUTE_LIST - MFT has extended attributes in other records!")
                non_res = mft_record[off + 8]
                if non_res:
                    print("  $ATTRIBUTE_LIST is non-resident - need to read more data")
                else:
                    value_len = struct.unpack_from("<I", mft_record, off + 16)[0]
                    value_off = struct.unpack_from("<H", mft_record, off + 20)[0]
                    print(f"  $ATTRIBUTE_LIST is resident, {value_len} bytes")
                    # Parse attribute list entries
                    al_data = mft_record[off + value_off : off + value_off + value_len]
                    al_off = 0
                    while al_off + 26 <= len(al_data):
                        al_type = struct.unpack_from("<I", al_data, al_off)[0]
                        al_rec_len = struct.unpack_from("<H", al_data, al_off + 4)[0]
                        if al_rec_len == 0:
                            break
                        al_mft_ref = struct.unpack_from("<Q", al_data, al_off + 16)[0] & 0xFFFFFFFFFFFF
                        if al_type == 0x80:
                            print(f"    $DATA attr in MFT record #{al_mft_ref}")
                        al_off += al_rec_len
                        
            off += attr_len
    
    src.close()
    print("\nDone!")

if __name__ == "__main__":
    main()
