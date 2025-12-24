from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

from .io.base import DiskSource
from .scan import safe_read
from .state import RecoveryState


LogCb = Callable[[str, str], None]


@dataclass(frozen=True)
class MftCandidate:
    offset: int
    signature: bytes


@dataclass(frozen=True)
class MftFileName:
    name: str
    parent_ref: int


@dataclass(frozen=True)
class MftRecordSummary:
    record_offset: int
    inode: int
    is_deleted: bool
    file_names: list[MftFileName]
    resident_data: Optional[bytes]
    parent_ref: Optional[int]
    data_runs: Optional[list[tuple[Optional[int], int]]]
    data_size: Optional[int]


def scan_for_mft_records(
    src: DiskSource,
    state: RecoveryState,
    *,
    start: int = 0,
    end: Optional[int] = None,
    step: int = 4096,
    record_size: int = 1024,
    log_cb: Optional[LogCb] = None,
) -> Iterator[MftCandidate]:
    """
    Best-effort scan for NTFS MFT record signature ("FILE").
    DMDE scans many alignments; we default to 4K steps (typical cluster/page).
    """
    total = src.size() if end is None else min(src.size(), end)
    off = start
    while off + record_size <= total:
        if state.stop_requested or not state.is_alive:
            return
        data = safe_read(src, state, off, 4, log_cb=log_cb)
        if data == b"FILE":
            yield MftCandidate(offset=off, signature=data)
        if state.consecutive_errors >= 8:
            jump = max(step, state.skip_size)
            if log_cb:
                log_cb("WARNING", f"Adaptive skip: +{jump} bytes after consecutive I/O errors")
            off += jump
        else:
            off += step


def _parse_attr_header(buf: bytes, off: int) -> tuple[int, int, int, int, int, int]:
    """
    Returns: (attr_type, attr_len, non_res, name_len, name_off, flags)
    """
    attr_type = struct.unpack_from("<I", buf, off)[0]
    attr_len = struct.unpack_from("<I", buf, off + 4)[0]
    non_res = buf[off + 8]
    name_len = buf[off + 9]
    name_off = struct.unpack_from("<H", buf, off + 10)[0]
    flags = struct.unpack_from("<H", buf, off + 12)[0]
    return attr_type, attr_len, non_res, name_len, name_off, flags


def _parse_file_name_attr(buf: bytes, value_off: int, value_len: int) -> Optional[MftFileName]:
    if value_len < 66:
        return None
    parent_ref = struct.unpack_from("<Q", buf, value_off)[0] & 0xFFFFFFFFFFFF
    name_len = buf[value_off + 64]
    name_ns = buf[value_off + 65]
    if name_len == 0:
        return None
    name_off = value_off + 66
    name_bytes = buf[name_off : name_off + name_len * 2]
    try:
        name = name_bytes.decode("utf-16le", errors="replace")
    except Exception:
        name = ""
    if not name:
        return None
    _ = name_ns
    return MftFileName(name=name, parent_ref=int(parent_ref))


def _parse_resident_data(buf: bytes, value_off: int, value_len: int) -> bytes:
    return buf[value_off : value_off + value_len]


def parse_mft_record_best_effort(
    record: bytes,
    *,
    record_offset: int,
    mft_record_number: Optional[int] = None,
) -> Optional[MftRecordSummary]:
    """
    Best-effort NTFS MFT record parser (no fixup/USN repair).
    Enough for:
      - $FILE_NAME (0x30) extraction
      - resident $DATA (0x80) extraction (small files)
      - deletion heuristic: flags == 0 or !in-use bit
    
    Args:
        record: Raw MFT record bytes
        record_offset: Absolute disk offset where record was read
        mft_record_number: If known, the actual MFT record index (inode).
                          If None, will be guessed from record_offset.
    """
    if len(record) < 48:
        return None
    if record[0:4] != b"FILE":
        return None

    # MFT record header (partial)
    fixup_off, fixup_cnt = struct.unpack_from("<HH", record, 4)
    _ = (fixup_off, fixup_cnt)
    flags = struct.unpack_from("<H", record, 22)[0]
    is_deleted = (flags & 0x0001) == 0  # FILE_RECORD_SEGMENT_IN_USE
    attr_off = struct.unpack_from("<H", record, 20)[0]

    file_names: list[MftFileName] = []
    resident_data: Optional[bytes] = None
    parent_ref: Optional[int] = None
    data_runs: Optional[list[tuple[Optional[int], int]]] = None
    data_size: Optional[int] = None

    off = attr_off
    while off + 16 <= len(record):
        attr_type = struct.unpack_from("<I", record, off)[0]
        if attr_type == 0xFFFFFFFF:
            break
        attr_type, attr_len, non_res, _name_len, _name_off, _flags = _parse_attr_header(record, off)
        if attr_len <= 0 or off + attr_len > len(record):
            break

        if non_res == 0:
            # resident header:
            # value_len (4) @ +16, value_off (2) @ +20
            value_len = struct.unpack_from("<I", record, off + 16)[0]
            value_off = struct.unpack_from("<H", record, off + 20)[0]
            value_abs = off + value_off
            if value_abs + value_len <= len(record):
                if attr_type == 0x30:  # FILE_NAME
                    fn = _parse_file_name_attr(record, value_abs, value_len)
                    if fn:
                        file_names.append(fn)
                        if parent_ref is None:
                            parent_ref = fn.parent_ref
                elif attr_type == 0x80 and resident_data is None:  # DATA
                    resident_data = _parse_resident_data(record, value_abs, value_len)
                    data_size = len(resident_data)
        else:
            # non-resident: parse runlist (best-effort) so we can recover content without pytsk3
            if attr_type == 0x80 and data_runs is None:
                # nonresident header: runlist offset @ +32, alloc/real sizes at +40/+48
                run_off = struct.unpack_from("<H", record, off + 32)[0]
                real_size = struct.unpack_from("<Q", record, off + 48)[0]
                data_size = int(real_size)
                runlist = record[off + run_off : off + attr_len]
                decoded = _decode_runlist_to_lcns(runlist)
                if decoded:
                    data_runs = decoded

        off += attr_len

    # Use provided mft_record_number if available, otherwise guess from offset
    if mft_record_number is not None:
        inode = int(mft_record_number)
    else:
        inode = record_offset // 1024 if record_offset >= 0 else 0
        
    return MftRecordSummary(
        record_offset=record_offset,
        inode=inode,
        is_deleted=bool(is_deleted),
        file_names=file_names,
        resident_data=resident_data,
        parent_ref=parent_ref,
        data_runs=data_runs,
        data_size=data_size,
    )


def _decode_runlist_to_lcns(runlist_bytes: bytes) -> list[tuple[Optional[int], int]]:
    """
    Convert NTFS runlist bytes into absolute LCN runs.
    Returns list of (lcn or None for sparse, length_in_clusters).
    """
    runs: list[tuple[Optional[int], int]] = []
    i = 0
    current_lcn = 0
    while i < len(runlist_bytes):
        header = runlist_bytes[i]
        i += 1
        if header == 0:
            break
        len_bytes = header & 0x0F
        off_bytes = (header >> 4) & 0x0F
        if len_bytes == 0 or i + len_bytes + off_bytes > len(runlist_bytes):
            break
        length = int.from_bytes(runlist_bytes[i : i + len_bytes], "little", signed=False)
        i += len_bytes
        offset_delta = int.from_bytes(runlist_bytes[i : i + off_bytes], "little", signed=True)
        i += off_bytes
        if off_bytes == 0:
            break
        if offset_delta == 0:
            # treat as sparse run (best-effort)
            runs.append((None, int(length)))
        else:
            current_lcn += int(offset_delta)
            runs.append((int(current_lcn), int(length)))
    return runs


def build_paths(records: list[MftRecordSummary]) -> dict[int, str]:
    """
    Build best-effort full paths using Parent Directory references from FILE_NAME.
    This is a simplified DMDE-like reconstruction (no index parsing).
    """
    name_by_inode: dict[int, str] = {}
    parent_by_inode: dict[int, int] = {}

    for r in records:
        if r.file_names:
            # Prefer the first file name (often Win32) for display.
            name_by_inode[r.inode] = r.file_names[0].name
        if r.parent_ref is not None:
            parent_by_inode[r.inode] = int(r.parent_ref)

    def resolve(inode: int) -> str:
        seen: set[int] = set()
        parts: list[str] = []
        cur = inode
        while cur not in seen and cur in name_by_inode:
            seen.add(cur)
            parts.append(name_by_inode[cur])
            if cur not in parent_by_inode:
                break
            nxt = parent_by_inode[cur]
            if nxt == cur:
                break
            cur = nxt
            if len(parts) > 128:
                break
        parts.reverse()
        return "/".join(parts) if parts else f"inode_{inode}"

    return {r.inode: resolve(r.inode) for r in records}


def scan_and_parse_mft(
    src: DiskSource,
    state: RecoveryState,
    *,
    start: int = 0,
    end: Optional[int] = None,
    step: int = 4096,
    record_size: int = 1024,
    log_cb: Optional[LogCb] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Iterator[MftRecordSummary]:
    total = src.size() if end is None else min(src.size(), end)
    for cand in scan_for_mft_records(
        src,
        state,
        start=start,
        end=end,
        step=step,
        record_size=record_size,
        log_cb=log_cb,
    ):
        if progress_cb:
            try:
                progress_cb(cand.offset, total)
            except Exception:
                pass
        rec = safe_read(src, state, cand.offset, record_size, log_cb=log_cb)
        summary = parse_mft_record_best_effort(rec, record_offset=cand.offset)
        if summary and (summary.file_names or summary.resident_data is not None):
            yield summary
