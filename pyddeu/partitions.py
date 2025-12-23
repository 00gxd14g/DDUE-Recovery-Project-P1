from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from .io.base import DiskSource
from .scan import safe_read_granular
from .state import RecoveryState


DEFAULT_SECTOR_SIZE = 512


@dataclass(frozen=True)
class Partition:
    index: int
    start_offset: int
    length: int
    scheme: str
    type_str: str
    name: str = ""

    @property
    def end_offset(self) -> int:
        return self.start_offset + self.length


def _is_mbr(boot: bytes) -> bool:
    return len(boot) >= 512 and boot[510:512] == b"\x55\xAA"


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


def _parse_gpt(src: DiskSource, *, state: Optional[RecoveryState] = None, log_cb: Optional[Callable[[str, str], None]] = None) -> list[Partition]:
    sector_size = src.sector_size() or DEFAULT_SECTOR_SIZE
    header = safe_read_granular(src, state or _NULL_STATE, sector_size, sector_size, log_cb=log_cb)
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
    sector_size = src.sector_size() or DEFAULT_SECTOR_SIZE

    boot = safe_read_granular(src, state or _NULL_STATE, 0, sector_size, log_cb=log_cb)
    if not _is_mbr(boot[:DEFAULT_SECTOR_SIZE]):
        if sector_size != DEFAULT_SECTOR_SIZE:
            boot512 = boot[:DEFAULT_SECTOR_SIZE]
            if not _is_mbr(boot512):
                return []
        else:
            return []
    mbr_parts = _parse_mbr(boot)
    if any("GPT Protective" in p.type_str for p in mbr_parts):
        gpt_parts = _parse_gpt(src, state=state, log_cb=log_cb)
        if gpt_parts:
            return gpt_parts
    return mbr_parts


def carve_ntfs_partitions(
    src: DiskSource,
    *,
    state: Optional[RecoveryState] = None,
    max_hits: int = 32,
    step_bytes: int = 1024 * 1024,
    validate_backup_boot: bool = True,
    log_cb: Optional[Callable[[str, str], None]] = None,
    progress_cb: Optional[Callable[[int, int, int], None]] = None,
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

    def try_ntfs_at(off: int) -> None:
        nonlocal idx
        if off in seen_offsets:
            return
        seen_offsets.add(off)
        boot = safe_read_granular(src, state or _NULL_STATE, off, sector_size, log_cb=log_cb)
        if len(boot) < max(90, sector_size):
            return
        if boot[3:7] != b"NTFS":
            return
        if boot[510:512] != b"\x55\xAA":
            return

        bps = int(struct.unpack_from("<H", boot, 11)[0]) or sector_size
        total_sectors = int(struct.unpack_from("<Q", boot, 40)[0])
        length = total_sectors * bps if total_sectors > 0 else 0

        type_str = "NTFS (carved boot sector)"
        if validate_backup_boot and total_sectors > 0:
            backup_off = off + (total_sectors - 1) * bps
            if 0 <= backup_off < size:
                backup = safe_read_granular(src, state or _NULL_STATE, backup_off, bps, log_cb=log_cb)
                if len(backup) >= 512 and backup[3:7] == b"NTFS" and backup[510:512] == b"\x55\xAA":
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
        try_ntfs_at(offset)
        if state:
            offset += max(int(step_bytes), int(getattr(state, "skip_size", step_bytes) or step_bytes))
        else:
            offset += step_bytes

    return hits
