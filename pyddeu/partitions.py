from __future__ import annotations

import binascii
import errno
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from .io.base import DiskSource
from .io import open_source
from .ntfs_boot import parse_ntfs_boot_sector, NtfsBoot
from .scan import safe_read_granular
from .state import RecoveryState
from .config import PyddeuConfig


DEFAULT_SECTOR_SIZE = 512
_MBR_SIG = b"\x55\xAA"


@dataclass(frozen=True)
class Partition:
    index: int
    start_offset: int
    length: int
    scheme: str
    type_str: str
    name: str = ""
    # Cache NTFS boot info for partitions found via Smart Scan
    # Allows NTFS deep scan to work even if boot sector becomes unreadable
    ntfs_boot: Optional[NtfsBoot] = None

    @property
    def end_offset(self) -> int:
        return self.start_offset + self.length


def _is_mbr(boot: bytes) -> bool:
    return len(boot) >= 512 and boot[510:512] == _MBR_SIG


def _is_exfat_boot(buf: bytes) -> bool:
    # exFAT: jump(3) + OEMName "EXFAT   " at offset 3, signature 0x55AA.
    return len(buf) >= 512 and buf[3:11] == b"EXFAT   " and buf[510:512] == _MBR_SIG


def _parse_exfat_size(buf: bytes) -> Optional[int]:
    # VolumeLength is in sectors; BytesPerSectorPow is 2^n.
    try:
        vol_len_sectors = int(struct.unpack_from("<Q", buf, 0x48)[0])
        bps_pow = int(buf[0x6C])
        bps = 1 << bps_pow
        if bps < 512 or bps > 4096:
            return None
        if vol_len_sectors <= 0:
            return None
        return vol_len_sectors * bps
    except Exception:
        return None


def _is_fat32_boot(buf: bytes) -> bool:
    # FAT32: "FAT32   " at offset 0x52 (82), signature 0x55AA.
    return len(buf) >= 512 and buf[0x52:0x5A] == b"FAT32   " and buf[510:512] == _MBR_SIG


def _parse_fat32_size(buf: bytes) -> Optional[int]:
    try:
        bps = int(struct.unpack_from("<H", buf, 0x0B)[0])
        if bps < 512 or bps > 4096:
            return None
        tot16 = int(struct.unpack_from("<H", buf, 0x13)[0])
        tot32 = int(struct.unpack_from("<I", buf, 0x20)[0])
        total_sectors = tot32 if tot32 else tot16
        if total_sectors <= 0:
            return None
        return total_sectors * bps
    except Exception:
        return None


def _parse_mbr(boot: bytes) -> list[Partition]:
    parts: list[Partition] = []
    for i in range(4):
        entry = boot[446 + i * 16 : 446 + (i + 1) * 16]
        p_type = entry[4]
        lba_start = struct.unpack_from("<I", entry, 8)[0]
        sectors = struct.unpack_from("<I", entry, 12)[0]
        if p_type == 0 or sectors == 0:
            continue
        start_offset = lba_start * DEFAULT_SECTOR_SIZE
        length = sectors * DEFAULT_SECTOR_SIZE
        type_str = f"MBR 0x{p_type:02X}"
        if p_type in (0x07,):
            type_str += " (NTFS/exFAT)"
        elif p_type in (0x0B, 0x0C):
            type_str += " (FAT32)"
        elif p_type in (0x83,):
            type_str += " (Linux)"
        elif p_type == 0xEE:
            type_str += " (GPT Protective)"
        parts.append(
            Partition(
                index=i + 1,
                start_offset=start_offset,
                length=length,
                scheme="MBR",
                type_str=type_str,
            )
        )
    return parts


def _guid_to_str(g: bytes) -> str:
    if len(g) != 16:
        return ""
    d1, d2, d3, d4 = struct.unpack("<IHH8s", g)
    d4_hex = binascii.hexlify(d4).decode("ascii")
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4_hex[:4]}-{d4_hex[4:]}"


def _parse_gpt(
    src: DiskSource,
    *,
    sector_size: int = DEFAULT_SECTOR_SIZE,
    state: Optional[RecoveryState] = None,
    log_cb: Optional[Callable[[str, str], None]] = None,
) -> list[Partition]:
    sector_size = int(sector_size or DEFAULT_SECTOR_SIZE)
    if sector_size not in (512, 1024, 2048, 4096):
        sector_size = DEFAULT_SECTOR_SIZE
    header = safe_read_granular(src, state or _NULL_STATE, sector_size, sector_size, log_cb=log_cb, sector_size=DEFAULT_SECTOR_SIZE)
    if len(header) < sector_size or header[:8] != b"EFI PART":
        return []

    part_entry_lba = struct.unpack_from("<Q", header, 72)[0]
    num_entries = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    if entry_size < 128 or num_entries == 0:
        return []

    table_bytes = num_entries * entry_size
    table = safe_read_granular(
        src,
        state or _NULL_STATE,
        part_entry_lba * sector_size,
        table_bytes,
        log_cb=log_cb,
        sector_size=DEFAULT_SECTOR_SIZE,
    )
    parts: list[Partition] = []

    idx = 1
    for i in range(num_entries):
        off = i * entry_size
        entry = table[off : off + entry_size]
        if len(entry) < 128:
            break
        type_guid = entry[0:16]
        if type_guid == b"\x00" * 16:
            continue
        first_lba = struct.unpack_from("<Q", entry, 32)[0]
        last_lba = struct.unpack_from("<Q", entry, 40)[0]
        if first_lba == 0 or last_lba < first_lba:
            continue
        name = entry[56:128].decode("utf-16le", errors="replace").rstrip("\x00")
        start_offset = first_lba * sector_size
        length = (last_lba - first_lba + 1) * sector_size
        type_str = f"GPT {_guid_to_str(type_guid)}"
        parts.append(
            Partition(
                index=idx,
                start_offset=start_offset,
                length=length,
                scheme="GPT",
                type_str=type_str,
                name=name,
            )
        )
        idx += 1

    return parts


class _NullState:
    stop_requested = False
    is_alive = True

    # minimal API used by safe_read_granular
    bad_map = type("_Bad", (), {"contains": staticmethod(lambda _o, _s: False)})()
    consecutive_errors = 0
    skip_size = DEFAULT_SECTOR_SIZE

    def wait_if_paused(self) -> None:
        return

    def register_success(self) -> None:
        return

    def register_error(self, _offset: int, _size: int) -> None:
        return


_NULL_STATE = _NullState()


def scan_partitions(
    src: DiskSource,
    *,
    state: Optional[RecoveryState] = None,
    log_cb: Optional[Callable[[str, str], None]] = None,
) -> list[Partition]:
    # DMDE-style addressing: treat "LBA" as 512-byte units for scanning/probing,
    # even if the device reports 4K logical/physical sectors (common on USB enclosures).
    lba_size = DEFAULT_SECTOR_SIZE
    disk_size = int(src.size() or 0)
    disk_lbas = (disk_size // lba_size) if disk_size > 0 else 0

    # 1. Try MBR at Sector 0
    boot = b""
    mbr_valid = False
    
    # Try multiple times since Sector 0 is critical
    for attempt in range(3):
        boot = safe_read_granular(src, state or _NULL_STATE, 0, lba_size, log_cb=log_cb, sector_size=lba_size)
        if _is_mbr(boot[:DEFAULT_SECTOR_SIZE]):
            mbr_valid = True
            break
        if log_cb and attempt < 2 and not boot:
             # Just a debug note if we plan to retry
             pass

    mbr_parts: list[Partition] = []
    
    if mbr_valid:
        mbr_parts = _parse_mbr(boot)
        # Check for GPT Protective MBR -> Go for GPT
        if any("GPT Protective" in p.type_str for p in mbr_parts):
            gpt_parts = _parse_gpt(src, sector_size=DEFAULT_SECTOR_SIZE, state=state, log_cb=log_cb)
            if not gpt_parts:
                # Some devices expose 4K logical sectors; try again at that stride.
                gpt_parts = _parse_gpt(src, sector_size=int(src.sector_size() or 0), state=state, log_cb=log_cb)
            if gpt_parts:
                return gpt_parts
            # If GPT parse failed, return protective MBR entry (better than nothing)
            return mbr_parts
            
        # If we found standard MBR partitions, return them
        # BUT: if MBR table is empty (all zeros) but signature is valid, 
        # we might want to probe anyway in case it's a "super floppy" or wiped table.
        if mbr_parts:
            return mbr_parts

    # 2. If MBR invalid (read error) or Empty, TRY GPT Header directly at LBA 1
    # (Some disks might have bad LBA 0 but valid LBA 1)
    if disk_size > lba_size * 2:
        try:
            # We bypass _parse_gpt's protective check by calling logic manually here?
            # actually _parse_gpt reads LBA 1.
            gpt_parts = _parse_gpt(src, sector_size=DEFAULT_SECTOR_SIZE, state=state, log_cb=log_cb)
            if not gpt_parts:
                gpt_parts = _parse_gpt(src, sector_size=int(src.sector_size() or 0), state=state, log_cb=log_cb)
            if gpt_parts:
                if log_cb: log_cb("INFO", "Found valid GPT despite missing/bad MBR.")
                return gpt_parts
        except Exception:
            pass

    # 3. Fallback: Quick Probe with Chain Probing (Smart Scan)
    # This mimics DMDE "Found" behavior: finding one partition leads to the next.
    if log_cb:
        log_cb("WARNING", "Partition table not found. Starting Smart Quick Scan (Chain Probing)...")

    found_parts: list[Partition] = []
    
    # Priority queue of LBAs to check. 
    # We use a set for visited to avoid loops/dups.
    # Start with standard alignments AND known common Windows partition LBAs.
    # These are based on typical Windows partition layouts:
    initial_lbas = [
        63,          # Legacy DOS alignment
        2048,        # Windows 7+ 1MB alignment (System Reserved typically starts here)
        2952,        # Alternate NTFS boot candidate seen on some disks (DMDE may list)
        104448,      # Common start after 50MB System Reserved
        206848,      # Common start after 100MB System Reserved  
        264192,      # Another common alignment
        326635520,   # Known from user's DMDE output
        327680000,   # Near 160GB (common partition boundary)
        327682048,   # Known from user's DMDE output - $Noname 03 (TARGET!)
        409640,      # ~200MB offset
    ]
    
    candidates = sorted(set(initial_lbas))
    seen_lbas: set[int] = set()
    
    idx_found = 1
    
    while candidates:
        lba = candidates.pop(0)
        
        if lba in seen_lbas:
            continue
        seen_lbas.add(lba)
        
        offset = int(lba) * lba_size
        if offset < 0 or (disk_size > 0 and offset >= disk_size):
            continue

        # Read boot sector candidate
        if log_cb:
            log_cb("DEBUG", f"Smart Scan: probing LBA {lba} (offset {offset})")
            
        data = safe_read_granular(src, state or _NULL_STATE, offset, 512, log_cb=None, sector_size=lba_size)
        if not data:
            continue
            
        found_len = 0
        p_type = ""
        p_name = ""
        cached_ntfs_boot: Optional[NtfsBoot] = None
        
        # Check NTFS
        parsed_ntfs = parse_ntfs_boot_sector(data)
        if parsed_ntfs and parsed_ntfs.total_sectors > 0:
            found_len = parsed_ntfs.volume_size_bytes
            # Convert to 512-byte LBA units regardless of NTFS bytes-per-sector.
            s_len = int(found_len // lba_size) if found_len > 0 else 0
            p_type = "NTFS (Smart Scan)"
            p_name = "Found NTFS"
            cached_ntfs_boot = parsed_ntfs  # Cache for later use in deep scan
            
            # CHAIN: Add next partition start
            next_lba = int(lba + s_len) if s_len > 0 else int(lba)
            if next_lba not in seen_lbas:
                candidates.append(next_lba)
                # Sometimes there's a 1MB alignment gap (2048 sectors)
                # Align next_lba to 2048 boundary if not already
                aligned_next = ((next_lba + 2047) // 2048) * 2048
                if aligned_next != next_lba and aligned_next not in seen_lbas:
                     candidates.append(aligned_next)

        # Check FAT32
        elif _is_fat32_boot(data[:512]):
            fsize = _parse_fat32_size(data[:512])
            if fsize:
                found_len = fsize
                s_len = int(fsize // lba_size)
                p_type = "FAT32 (Smart Scan)"
                p_name = "Found FAT32"
                
                next_lba = lba + s_len
                if next_lba not in seen_lbas:
                    candidates.append(next_lba)

        # Check exFAT
        elif _is_exfat_boot(data[:512]):
            xsize = _parse_exfat_size(data[:512])
            if xsize:
                found_len = xsize
                s_len = int(xsize // lba_size)
                p_type = "exFAT (Smart Scan)"
                p_name = "Found exFAT"
                
                next_lba = lba + s_len
                if next_lba not in seen_lbas:
                    candidates.append(next_lba)
        
        if found_len > 0:
            # We found something valid!
            found_parts.append(Partition(
                index=idx_found,
                start_offset=offset,
                length=found_len,
                scheme="FOUND",
                type_str=p_type,
                name=p_name,
                ntfs_boot=cached_ntfs_boot,  # Save cached NTFS boot info
            ))
            idx_found += 1
            # Sort candidates to prioritize lower LBAs (sequential scan)
            candidates.sort()

    if found_parts:
        # DMDE-style extra: if a very large NTFS volume overlaps another found start,
        # add a "bounded" variant ending at the next start (matches DMDE's dual listings).
        starts = sorted({int(p.start_offset // DEFAULT_SECTOR_SIZE) for p in found_parts if p.start_offset >= 0})
        by_start: dict[int, Partition] = {}
        for p in found_parts:
            by_start.setdefault(int(p.start_offset), p)

        augmented = list(found_parts)
        min_large_bytes = 1024 * 1024 * 1024  # 1GB
        for p in found_parts:
            if "NTFS" not in str(p.type_str or "").upper():
                continue
            if int(p.length) < min_large_bytes:
                continue
            start_lba = int(p.start_offset // DEFAULT_SECTOR_SIZE)
            end_lba = start_lba + int(p.length // DEFAULT_SECTOR_SIZE) - 1
            inner = [s for s in starts if s > start_lba and s <= end_lba]
            if not inner:
                continue
            next_start = min(inner)
            bounded_len = int(max(0, (next_start - start_lba) * DEFAULT_SECTOR_SIZE))
            if bounded_len <= 0 or bounded_len >= int(p.length):
                continue
            augmented.append(
                Partition(
                    index=int(p.index) + 1000,
                    start_offset=int(p.start_offset),
                    length=bounded_len,
                    scheme=str(p.scheme),
                    type_str=str(p.type_str) + " (bounded)",
                    name=str(p.name),
                    ntfs_boot=p.ntfs_boot,
                )
            )

        augmented.sort(key=lambda pp: int(pp.start_offset))
        if log_cb:
            log_cb("INFO", f"Smart Quick Scan found {len(found_parts)} partition(s).")
            for p in augmented:
                lba0 = int(p.start_offset // DEFAULT_SECTOR_SIZE)
                lba1 = int((p.start_offset + max(0, p.length)) // DEFAULT_SECTOR_SIZE - 1) if p.length > 0 else lba0
                gb = float(p.length) / (1024**3) if p.length > 0 else 0.0
                log_cb("INFO", f"FOUND: {p.type_str} LBA {lba0}..{lba1} ({gb:.2f} GB)")
        return augmented

    return []


def carve_ntfs_partitions(
    src: DiskSource,
    *,
    state: Optional[RecoveryState] = None,
    max_hits: int = 32,
    step_bytes: int = 1024 * 1024,
    validate_backup_boot: bool = True,
    log_cb: Optional[Callable[[str, str], None]] = None,
    progress_cb: Optional[Callable[[int, int, int], None]] = None,
    source_path: Optional[str] = None,
    config: PyddeuConfig | None = None,
) -> list[Partition]:
    """
    Read-only scan that looks for NTFS boot sectors when the partition table is missing/corrupt.
    This does not modify the disk.
    """
    sector_size = src.sector_size() or DEFAULT_SECTOR_SIZE
    size = src.size() or 0
    if size <= 0:
        return []

    hits: list[Partition] = []
    seen_offsets: set[int] = set()
    offset = 0
    idx = 1
    chunk_size = max(int(step_bytes), 16 * 1024 * 1024)
    overlap = 512
    min_chunk = 1024 * 1024
    max_chunk = chunk_size
    current_chunk = chunk_size
    success_streak = 0
    cur_src = src
    owns_src = False

    if source_path:
        try:
            cur_src = open_source(source_path, config=config)
            owns_src = True
        except Exception:
            cur_src = src
            owns_src = False

    def reopen_source() -> bool:
        nonlocal cur_src, owns_src
        if not source_path:
            refresh = getattr(cur_src, "refresh", None)
            if callable(refresh):
                try:
                    refresh()
                    return True
                except Exception:
                    return False
            return False
        try:
            new_src = open_source(source_path, config=config)
        except Exception:
            return False
        try:
            if owns_src:
                cur_src.close()
        except Exception:
            pass
        cur_src = new_src
        owns_src = True
        return True

    def read_chunk(off: int, size_bytes: int) -> tuple[bytes, bool]:
        nonlocal cur_src
        sec = src.sector_size() or DEFAULT_SECTOR_SIZE
        if sec <= 0:
            sec = DEFAULT_SECTOR_SIZE
        if state:
            state.wait_if_paused()
            if state.stop_requested or not state.is_alive:
                return b"", False
            if state.bad_map.contains(off, size_bytes):
                return b"", True
        # Align to sector boundaries to avoid EINVAL on some controllers/O_DIRECT
        aligned_off = off - (off % sec)
        delta = off - aligned_off
        aligned_size = ((size_bytes + delta + sec - 1) // sec) * sec
        if aligned_size <= 0:
            return b"", False
        for attempt in range(2):
            try:
                data = cur_src.read_at(aligned_off, aligned_size)
                if len(data) < aligned_size:
                    data += b"\x00" * (aligned_size - len(data))
                start = delta
                end = min(delta + size_bytes, len(data))
                if start >= end:
                    return b"", False
                return data[start:end], False
            except OSError as e:
                # Timeouts are treated as media faults; don't escalate to controller panic
                if state and getattr(e, "errno", None) not in (errno.ETIMEDOUT,):
                    try:
                        state.register_controller_panic(log_cb=log_cb)
                    except Exception:
                        pass
                if log_cb:
                    log_cb(
                        "CRITICAL",
                        f"Carve chunk read failed @{off} (+{size_bytes}) attempt {attempt + 1}: {e}",
                    )
                if attempt == 0 and reopen_source():
                    continue
                return b"", True
        return b"", True

    def try_ntfs_at(off: int) -> None:
        nonlocal idx
        if off in seen_offsets:
            return
        seen_offsets.add(off)
        boot = safe_read_granular(cur_src, state or _NULL_STATE, off, sector_size, log_cb=log_cb)
        if len(boot) < max(90, sector_size):
            return
        parsed = parse_ntfs_boot_sector(boot)
        if not parsed:
            return

        bps = parsed.bytes_per_sector
        total_sectors = parsed.total_sectors
        length = parsed.volume_size_bytes

        type_str = "NTFS (carved boot sector)"
        if validate_backup_boot and total_sectors > 0:
            backup_off = off + (total_sectors - 1) * bps
            if 0 <= backup_off < size:
                backup = safe_read_granular(cur_src, state or _NULL_STATE, backup_off, bps, log_cb=log_cb)
                if parse_ntfs_boot_sector(backup):
                    type_str = "NTFS (carved boot sector + backup validated)"
                else:
                    type_str = "NTFS (carved, backup boot not validated)"

        hits.append(
            Partition(
                index=idx,
                start_offset=off,
                length=length,
                scheme="CARVE",
                type_str=type_str,
                name="",
            )
        )
        idx += 1

    last_log = 0
    try:
        while offset < size and len(hits) < max_hits:
            if state and (state.stop_requested or not state.is_alive):
                break
            if progress_cb:
                try:
                    progress_cb(offset, size, len(hits))
                except Exception:
                    pass
            if log_cb and offset - last_log >= 256 * 1024 * 1024:
                log_cb("INFO", f"NTFS carve progress: offset={offset} hits={len(hits)}")
                last_log = offset

            base_len = min(current_chunk, size - offset)
            if base_len <= 0:
                break
            read_len = min(base_len + overlap, size - offset)
            # Fast path: avoid granular sector fallback on huge chunks (prevents UI freeze).
            buf, had_error = read_chunk(offset, read_len)
            if had_error or not buf:
                if state:
                    state.register_error(offset, max(1, base_len))
                success_streak = 0
                current_chunk = max(min_chunk, current_chunk // 2)
                # CRITICAL: Guarantee minimum 1MB skip on error to prevent infinite loop
                # Without this, we could loop forever on same offset
                min_skip = max(1024 * 1024, base_len, 1)  # At least 1MB or base_len, never 0
                step = min_skip
                if state:
                    state_skip = int(getattr(state, "skip_size", 0) or 0)
                    # More aggressive skip on consecutive errors (check largest first)
                    if state.consecutive_errors >= 5:
                        step = max(step, state_skip, 16 * 1024 * 1024)  # 16MB minimum
                    elif state.consecutive_errors >= 3:
                        step = max(step, state_skip, 4 * 1024 * 1024)  # 4MB minimum
                    else:
                        step = max(step, state_skip)
                # Final safety check: never skip 0 bytes
                step = max(1, step)
                if log_cb:
                    log_cb("WARNING", f"Carve read error @ {offset}; skipping {step // (1024 * 1024)}MB, chunk={current_chunk // (1024 * 1024)}MB")
                offset += step
                continue

            success_streak += 1
            if success_streak >= 4 and current_chunk < max_chunk:
                current_chunk = min(max_chunk, current_chunk * 2)
                success_streak = 0
            if buf:
                start = 0
                while True:
                    pos = buf.find(b"NTFS ", start)
                    if pos == -1:
                        break
                    if pos >= 3:
                        cand = offset + pos - 3
                        if 0 <= cand < size:
                            try_ntfs_at(cand)
                    start = pos + 1

                step = base_len
                if state:
                    skip_cap = int(getattr(state, "max_skip_size", DEFAULT_SECTOR_SIZE)) or DEFAULT_SECTOR_SIZE
                    step = max(step, min(skip_cap, int(getattr(state, "skip_size", 0) or 0)))
                offset += step
    finally:
        if owns_src:
            try:
                cur_src.close()
            except Exception:
                pass

    return hits


def carve_exfat_partitions(
    src: DiskSource,
    *,
    state: Optional[RecoveryState] = None,
    log_cb: Optional[Callable[[str, str], None]] = None,
    progress_cb: Optional[Callable[[int, int, int], None]] = None,
    min_chunk: int = 4 * 1024 * 1024,
    max_chunk: int = 128 * 1024 * 1024,
    max_hits: int = 64,
    source_path: str = "",
    config: PyddeuConfig | None = None,
) -> list[Partition]:
    """
    Read-only scan to locate exFAT boot sectors when partition tables are missing/corrupt.
    Looks for OEMName "EXFAT   " and validates the 0x55AA signature.
    """
    size = int(src.size() or 0)
    if size <= 0:
        return []

    sector_size = src.sector_size() or DEFAULT_SECTOR_SIZE
    offset = 0
    idx = 1
    hits: list[Partition] = []
    seen_offsets: set[int] = set()

    cur_src = src
    owns_src = False

    def reopen_source() -> bool:
        nonlocal cur_src, owns_src
        if not source_path:
            return False
        try:
            new_src = open_source(source_path, config=config)
        except Exception:
            return False
        try:
            if owns_src:
                cur_src.close()
        except Exception:
            pass
        cur_src = new_src
        owns_src = True
        return True

    def read_chunk(off: int, size_bytes: int) -> tuple[bytes, bool]:
        nonlocal cur_src
        sec = src.sector_size() or DEFAULT_SECTOR_SIZE
        if sec <= 0:
            sec = DEFAULT_SECTOR_SIZE
        if state:
            state.wait_if_paused()
            if state.stop_requested or not state.is_alive:
                return b"", False
            if state.bad_map.contains(off, size_bytes):
                return b"", True
        aligned_off = off - (off % sec)
        delta = off - aligned_off
        aligned_size = ((size_bytes + delta + sec - 1) // sec) * sec
        if aligned_size <= 0:
            return b"", False
        for attempt in range(2):
            try:
                data = cur_src.read_at(aligned_off, aligned_size)
                if len(data) < aligned_size:
                    data += b"\x00" * (aligned_size - len(data))
                start = delta
                end = min(delta + size_bytes, len(data))
                if start >= end:
                    return b"", False
                return data[start:end], False
            except OSError as e:
                if state and getattr(e, "errno", None) not in (errno.ETIMEDOUT,):
                    try:
                        state.register_controller_panic(log_cb=log_cb)
                    except Exception:
                        pass
                if log_cb:
                    log_cb("CRITICAL", f"Carve chunk read failed @{off} (+{size_bytes}) attempt {attempt + 1}: {e}")
                if attempt == 0 and reopen_source():
                    continue
                return b"", True
        return b"", True

    def try_exfat_at(off: int) -> None:
        nonlocal idx
        if off in seen_offsets:
            return
        seen_offsets.add(off)
        boot = safe_read_granular(cur_src, state or _NULL_STATE, off, sector_size, log_cb=log_cb)
        if len(boot) < 512 or not _is_exfat_boot(boot[:512]):
            return
        length = _parse_exfat_size(boot[:512])
        if not length:
            return
        hits.append(
            Partition(
                index=idx,
                start_offset=off,
                length=int(length),
                scheme="CARVE",
                type_str="exFAT (carved boot sector)",
                name="",
            )
        )
        idx += 1

    current_chunk = min_chunk
    success_streak = 0
    overlap = 4096
    last_log = 0
    try:
        while offset < size and len(hits) < max_hits:
            if state and (state.stop_requested or not state.is_alive):
                break
            if progress_cb:
                try:
                    progress_cb(offset, size, len(hits))
                except Exception:
                    pass
            if log_cb and offset - last_log >= 256 * 1024 * 1024:
                log_cb("INFO", f"exFAT carve progress: offset={offset} hits={len(hits)}")
                last_log = offset

            base_len = min(current_chunk, size - offset)
            if base_len <= 0:
                break
            read_len = min(base_len + overlap, size - offset)
            buf, had_error = read_chunk(offset, read_len)
            if had_error or not buf:
                if state:
                    state.register_error(offset, max(1, base_len))
                success_streak = 0
                current_chunk = max(min_chunk, current_chunk // 2)
                # CRITICAL: Guarantee minimum 1MB skip on error to prevent infinite loop
                min_skip = max(1024 * 1024, base_len, 1)  # At least 1MB or base_len, never 0
                step = min_skip
                if state:
                    state_skip = int(getattr(state, "skip_size", 0) or 0)
                    if state.consecutive_errors >= 5:
                        step = max(step, state_skip, 16 * 1024 * 1024)
                    elif state.consecutive_errors >= 3:
                        step = max(step, state_skip, 4 * 1024 * 1024)
                    else:
                        step = max(step, state_skip)
                # Final safety check: never skip 0 bytes
                step = max(1, step)
                if log_cb:
                    log_cb("WARNING", f"exFAT carve read error @ {offset}; skipping {step // (1024 * 1024)}MB")
                offset += step
                continue

            success_streak += 1
            if success_streak >= 4 and current_chunk < max_chunk:
                current_chunk = min(max_chunk, current_chunk * 2)
                success_streak = 0

            start = 0
            while True:
                pos = buf.find(b"EXFAT   ", start)
                if pos == -1:
                    break
                cand = offset + pos - 3
                if 0 <= cand < size:
                    try_exfat_at(cand)
                start = pos + 1

            step = base_len
            if state:
                step = max(step, int(getattr(state, "skip_size", 0) or 0))
            offset += step
    finally:
        if owns_src:
            try:
                cur_src.close()
            except Exception:
                pass

    return hits


def carve_fat32_partitions(
    src: DiskSource,
    *,
    state: Optional[RecoveryState] = None,
    log_cb: Optional[Callable[[str, str], None]] = None,
    progress_cb: Optional[Callable[[int, int, int], None]] = None,
    min_chunk: int = 4 * 1024 * 1024,
    max_chunk: int = 128 * 1024 * 1024,
    max_hits: int = 64,
    source_path: str = "",
    config: PyddeuConfig | None = None,
) -> list[Partition]:
    """
    Read-only scan to locate FAT32 boot sectors when partition tables are missing/corrupt.
    Looks for "FAT32   " marker (offset 0x52) and validates the 0x55AA signature.
    """
    size = int(src.size() or 0)
    if size <= 0:
        return []

    sector_size = src.sector_size() or DEFAULT_SECTOR_SIZE
    offset = 0
    idx = 1
    hits: list[Partition] = []
    seen_offsets: set[int] = set()

    cur_src = src
    owns_src = False

    def reopen_source() -> bool:
        nonlocal cur_src, owns_src
        if not source_path:
            return False
        try:
            new_src = open_source(source_path, config=config)
        except Exception:
            return False
        try:
            if owns_src:
                cur_src.close()
        except Exception:
            pass
        cur_src = new_src
        owns_src = True
        return True

    def read_chunk(off: int, size_bytes: int) -> tuple[bytes, bool]:
        nonlocal cur_src
        sec = src.sector_size() or DEFAULT_SECTOR_SIZE
        if sec <= 0:
            sec = DEFAULT_SECTOR_SIZE
        if state:
            state.wait_if_paused()
            if state.stop_requested or not state.is_alive:
                return b"", False
            if state.bad_map.contains(off, size_bytes):
                return b"", True
        aligned_off = off - (off % sec)
        delta = off - aligned_off
        aligned_size = ((size_bytes + delta + sec - 1) // sec) * sec
        if aligned_size <= 0:
            return b"", False
        for attempt in range(2):
            try:
                data = cur_src.read_at(aligned_off, aligned_size)
                if len(data) < aligned_size:
                    data += b"\x00" * (aligned_size - len(data))
                start = delta
                end = min(delta + size_bytes, len(data))
                if start >= end:
                    return b"", False
                return data[start:end], False
            except OSError as e:
                if state and getattr(e, "errno", None) not in (errno.ETIMEDOUT,):
                    try:
                        state.register_controller_panic(log_cb=log_cb)
                    except Exception:
                        pass
                if log_cb:
                    log_cb("CRITICAL", f"Carve chunk read failed @{off} (+{size_bytes}) attempt {attempt + 1}: {e}")
                if attempt == 0 and reopen_source():
                    continue
                return b"", True
        return b"", True

    def try_fat32_at(off: int) -> None:
        nonlocal idx
        if off in seen_offsets:
            return
        seen_offsets.add(off)
        boot = safe_read_granular(cur_src, state or _NULL_STATE, off, sector_size, log_cb=log_cb)
        if len(boot) < 512 or not _is_fat32_boot(boot[:512]):
            return
        length = _parse_fat32_size(boot[:512])
        if not length:
            return
        hits.append(
            Partition(
                index=idx,
                start_offset=off,
                length=int(length),
                scheme="CARVE",
                type_str="FAT32 (carved boot sector)",
                name="",
            )
        )
        idx += 1

    current_chunk = min_chunk
    success_streak = 0
    overlap = 4096
    last_log = 0
    try:
        while offset < size and len(hits) < max_hits:
            if state and (state.stop_requested or not state.is_alive):
                break
            if progress_cb:
                try:
                    progress_cb(offset, size, len(hits))
                except Exception:
                    pass
            if log_cb and offset - last_log >= 256 * 1024 * 1024:
                log_cb("INFO", f"FAT32 carve progress: offset={offset} hits={len(hits)}")
                last_log = offset

            base_len = min(current_chunk, size - offset)
            if base_len <= 0:
                break
            read_len = min(base_len + overlap, size - offset)
            buf, had_error = read_chunk(offset, read_len)
            if had_error or not buf:
                if state:
                    state.register_error(offset, max(1, base_len))
                success_streak = 0
                current_chunk = max(min_chunk, current_chunk // 2)
                # CRITICAL: Guarantee minimum 1MB skip on error to prevent infinite loop
                min_skip = max(1024 * 1024, base_len, 1)  # At least 1MB or base_len, never 0
                step = min_skip
                if state:
                    state_skip = int(getattr(state, "skip_size", 0) or 0)
                    if state.consecutive_errors >= 5:
                        step = max(step, state_skip, 16 * 1024 * 1024)
                    elif state.consecutive_errors >= 3:
                        step = max(step, state_skip, 4 * 1024 * 1024)
                    else:
                        step = max(step, state_skip)
                # Final safety check: never skip 0 bytes
                step = max(1, step)
                if log_cb:
                    log_cb("WARNING", f"FAT32 carve read error @ {offset}; skipping {step // (1024 * 1024)}MB")
                offset += step
                continue

            success_streak += 1
            if success_streak >= 4 and current_chunk < max_chunk:
                current_chunk = min(max_chunk, current_chunk * 2)
                success_streak = 0

            start = 0
            while True:
                pos = buf.find(b"FAT32   ", start)
                if pos == -1:
                    break
                cand = offset + pos - 0x52
                if 0 <= cand < size:
                    try_fat32_at(cand)
                start = pos + 1

            step = base_len
            if state:
                step = max(step, int(getattr(state, "skip_size", 0) or 0))
            offset += step
    finally:
        if owns_src:
            try:
                cur_src.close()
            except Exception:
                pass

    return hits
