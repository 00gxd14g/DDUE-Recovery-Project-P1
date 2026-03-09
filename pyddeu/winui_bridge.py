from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import struct
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import pytsk3
except Exception:
    pytsk3 = None  # type: ignore[assignment]

from .carve import carve_signatures
from .config import PyddeuConfig, default_config_path
from .imager import create_image
from .io import list_sources, open_source
from .mft import (
    _decode_runlist_to_lcns,
    build_paths,
    parse_mft_record_best_effort,
    scan_and_parse_mft,
)
from .ntfs_boot import parse_ntfs_boot_sector
from .partitions import (
    Partition,
    carve_exfat_partitions,
    carve_fat32_partitions,
    carve_ntfs_partitions,
    scan_partitions,
)
from .recover import recover_nonresident_runs
from .scan import safe_read_granular
from .state import RecoveryState, map_path_for_source


JsonObj = dict[str, Any]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config() -> PyddeuConfig:
    return PyddeuConfig.load(default_config_path())


def _emit(payload: JsonObj) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def _log(level: str, message: str) -> None:
    _emit({"type": "log", "level": str(level), "message": str(message)})


def _progress(operation: str, current: int, total: int) -> None:
    _emit(
        {
            "type": "progress",
            "operation": operation,
            "current": int(max(0, current)),
            "total": int(max(0, total)),
        }
    )


def _result(payload: JsonObj) -> int:
    _emit({"type": "result", **payload})
    return 0


def _error(message: str, *, code: str = "bridge_error", details: Optional[str] = None) -> int:
    event: JsonObj = {"type": "error", "code": code, "message": message}
    if details:
        event["details"] = details
    _emit(event)
    return 1


def _read_payload_from_stdin() -> JsonObj:
    try:
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except Exception as e:
        raise ValueError(f"Invalid JSON payload: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("Payload must be a JSON object")
    return data


def _partition_to_json(p: Partition) -> JsonObj:
    return {
        "index": int(p.index),
        "start_offset": int(p.start_offset),
        "length": int(p.length),
        "scheme": str(p.scheme or ""),
        "type_str": str(p.type_str or ""),
        "name": str(p.name or ""),
    }


def _safe_rel_path(path_text: str) -> str:
    t = str(path_text or "").strip().replace("\\", "/").lstrip("/")
    for prefix in ("[DEEP]", "[MFT]", "[FAST]", "[DEEP] ", "[MFT] ", "[FAST] "):
        if t.startswith(prefix):
            t = t[len(prefix) :].strip()
    if not t:
        return ""
    parts: list[str] = []
    for p in t.split("/"):
        p = p.strip().strip(".")
        if not p or p in (".", ".."):
            continue
        for ch in '<>:"|?*':
            p = p.replace(ch, "_")
        parts.append(p)
    return "/".join(parts)


def _normalize_display_path(path_text: str) -> tuple[str, str]:
    normalized = str(path_text or "").strip().replace("\\", "/").strip("/")
    if not normalized:
        return "", ""
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return "", ""
    normalized = "/".join(parts)
    return normalized, parts[-1]


def _pick_name_source(file_names: list[Any] | None) -> str:
    if not file_names:
        return "inode_fallback"
    priority = {1: (0, "win32"), 3: (1, "win32_dos"), 0: (2, "posix"), 2: (3, "dos83")}
    picked = sorted(file_names, key=lambda fn: priority.get(int(getattr(fn, "namespace", -1)), (99, "unknown")))[0]
    return priority.get(int(getattr(picked, "namespace", -1)), (99, "unknown"))[1]


def _make_file_item(
    *,
    path: str,
    size: int,
    status: str,
    inode: int,
    part_offset: int,
    is_dir: bool,
    resident_data_b64: str | None = None,
    data_runs: list[JsonObj] | None = None,
    data_size: int | None = None,
    cluster_size: int | None = None,
    source: str,
    name_source: str,
) -> JsonObj:
    display_path, file_name = _normalize_display_path(path)
    if not display_path:
        display_path = f"inode_{int(inode)}" if int(inode) > 0 else "unknown"
    if not file_name:
        file_name = display_path.rsplit("/", 1)[-1]
    dedupe_path = display_path.casefold()
    return {
        "path": display_path,
        "display_path": display_path,
        "file_name": file_name,
        "name_source": str(name_source or "unknown"),
        "dedupe_key": f"{str(source)}|{int(part_offset)}|{int(inode)}|{dedupe_path}",
        "size": int(size),
        "status": str(status),
        "inode": int(inode),
        "part_offset": int(part_offset),
        "is_dir": bool(is_dir),
        "resident_data_b64": resident_data_b64,
        "data_runs": list(data_runs or []),
        "data_size": (None if data_size is None else int(data_size)),
        "cluster_size": (None if cluster_size is None else int(cluster_size)),
        "source": str(source),
    }


def _serialize_runs(runs: list[tuple[int | None, int]] | None) -> list[JsonObj]:
    out: list[JsonObj] = []
    if not runs:
        return out
    for lcn, length in runs:
        out.append({"lcn": (None if lcn is None else int(lcn)), "length": int(length)})
    return out


def _deserialize_runs(items: Any) -> list[tuple[int | None, int]]:
    runs: list[tuple[int | None, int]] = []
    if not isinstance(items, list):
        return runs
    for row in items:
        if not isinstance(row, dict):
            continue
        lcn = row.get("lcn")
        length = int(row.get("length", 0) or 0)
        if length <= 0:
            continue
        if lcn is None:
            runs.append((None, length))
        else:
            runs.append((int(lcn), length))
    return runs


def _records_to_files(
    records: list,
    part_start: int,
    cluster_size: int | None,
    include_deleted: bool,
    include_active: bool,
    max_resident: int,
    source: str = "mft",
) -> list[JsonObj]:
    """Convert MFT record summaries to bridge-compatible file list."""
    paths = build_paths(records)
    files: list[JsonObj] = []
    for rec in records:
        status = "DELETED" if rec.is_deleted else "ACTIVE"
        if status == "DELETED" and not include_deleted:
            continue
        if status == "ACTIVE" and not include_active:
            continue

        resident_data_b64: str | None = None
        if rec.resident_data is not None and len(rec.resident_data) <= max_resident:
            resident_data_b64 = base64.b64encode(rec.resident_data).decode("ascii")

        size = int(rec.data_size or (len(rec.resident_data) if rec.resident_data is not None else 0))
        files.append(
            _make_file_item(
                path=paths.get(rec.inode, f"inode_{rec.inode}"),
                size=size,
                status=status,
                inode=int(rec.inode),
                part_offset=int(part_start),
                is_dir=False,
                resident_data_b64=resident_data_b64,
                data_runs=_serialize_runs(rec.data_runs),
                data_size=(None if rec.data_size is None else int(rec.data_size)),
                cluster_size=(None if cluster_size is None else int(cluster_size)),
                source=source,
                name_source=_pick_name_source(getattr(rec, "file_names", None)),
            )
        )
    return files


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _command_list_disks(_: JsonObj) -> int:
    disks: list[JsonObj] = []
    for d in list_sources():
        disks.append(
            {
                "path": str(d.path),
                "size": int(d.size or 0),
                "description": str(d.description or ""),
            }
        )
    return _result({"command": "list_disks", "disks": disks})


def _command_scan_partitions(payload: JsonObj) -> int:
    source_path = str(payload.get("source_path") or "").strip()
    if not source_path:
        return _error("source_path is required", code="invalid_payload")

    config = _load_config()
    aggressive = bool(payload.get("aggressive", False))
    state = RecoveryState(map_path=map_path_for_source(source_path))
    src = None
    try:
        src = open_source(source_path, config=config)
        parts = scan_partitions(src, state=state, log_cb=_log, aggressive=aggressive)

        if aggressive or not parts:
            total = int(src.size() or 0)

            def carve_progress(off: int, total_size: int, hits: int) -> None:
                _progress("scan_partitions", int(off), int(total_size or total))
                _emit(
                    {
                        "type": "status",
                        "operation": "scan_partitions",
                        "message": f"Carving boot sectors (hits={int(hits)})",
                    }
                )

            carved: list[Partition] = []
            carved.extend(
                carve_ntfs_partitions(
                    src,
                    state=state,
                    log_cb=_log,
                    progress_cb=carve_progress,
                    source_path=source_path,
                    config=config,
                )
            )
            carved.extend(
                carve_exfat_partitions(
                    src,
                    state=state,
                    log_cb=_log,
                    progress_cb=carve_progress,
                    source_path=source_path,
                    config=config,
                )
            )
            carved.extend(
                carve_fat32_partitions(
                    src,
                    state=state,
                    log_cb=_log,
                    progress_cb=carve_progress,
                    source_path=source_path,
                    config=config,
                )
            )

            dedup: dict[tuple[int, int], Partition] = {}
            for p in parts:
                dedup.setdefault((int(p.start_offset), int(p.length)), p)
            for p in carved:
                dedup.setdefault((int(p.start_offset), int(p.length)), p)
            parts = sorted(dedup.values(), key=lambda x: int(x.start_offset))

        return _result(
            {
                "command": "scan_partitions",
                "partitions": [_partition_to_json(p) for p in parts],
                "count": len(parts),
            }
        )
    except Exception as e:
        return _error(f"scan_partitions failed: {e}", details=traceback.format_exc())
    finally:
        try:
            if src is not None:
                src.close()
        except Exception:
            pass


def _command_deep_scan(payload: JsonObj) -> int:
    source_path = str(payload.get("source_path") or "").strip()
    if not source_path:
        return _error("source_path is required", code="invalid_payload")

    part_start = int(payload.get("partition_start", 0) or 0)
    part_length = int(payload.get("partition_length", 0) or 0)
    include_deleted = bool(payload.get("include_deleted", True))
    include_active = bool(payload.get("include_active", True))
    max_records = int(payload.get("max_records", 50000) or 50000)
    max_resident = int(payload.get("max_resident_bytes", 1024 * 1024) or (1024 * 1024))

    if not include_deleted and not include_active:
        return _error("At least one of include_deleted/include_active must be true", code="invalid_payload")

    config = _load_config()
    state = RecoveryState(map_path=map_path_for_source(source_path))
    src = None
    try:
        src = open_source(source_path, config=config)

        # --- NTFS boot sector validation ---
        boot_buf = safe_read_granular(src, state, int(part_start), 512, log_cb=_log)
        boot = parse_ntfs_boot_sector(boot_buf)
        if not boot:
            return _error(
                "Selected partition does not look like NTFS boot sector.",
                code="not_ntfs",
            )

        cluster_size = int(boot.cluster_size)
        record_size = int(boot.file_record_size)
        volume_end = int(part_start + int(boot.volume_size_bytes))
        if part_length > 0:
            volume_end = min(volume_end, int(part_start + part_length))

        _log("INFO", f"NTFS boot parsed: cluster={cluster_size} record={record_size} MFT_LCN={boot.mft_lcn}")

        def progress(off: int, total: int) -> None:
            _progress("deep_scan", int(off), int(total))

        records: list = []

        # --- SMART APPROACH: Read MFT record 0 and extract data runs ---
        mft_offset = part_start + (boot.mft_lcn * cluster_size)
        _log("INFO", f"Trying direct MFT read at offset {mft_offset} (LCN {boot.mft_lcn})")

        mft_record0 = safe_read_granular(src, state, mft_offset, record_size, log_cb=_log)
        mft_summary0 = None
        if mft_record0 and len(mft_record0) >= 4 and mft_record0[:4] == b"FILE":
            mft_summary0 = parse_mft_record_best_effort(
                mft_record0,
                record_offset=int(mft_offset),
                mft_record_number=0,
                record_size=record_size,
            )

        mft_accessible = mft_summary0 is not None

        if mft_accessible:
            _log("INFO", "MFT is accessible. Parsing $MFT data runs for fragmented MFT support...")

            # Extract MFT data runs
            mft_runs: list[tuple[int | None, int]] = []
            mft_data_size = 0

            if mft_summary0 and mft_summary0.data_runs:
                mft_runs = list(mft_summary0.data_runs)
                mft_data_size = int(mft_summary0.data_size or 0)
                _log("INFO", f"Found {len(mft_runs)} MFT data runs (via parsed record)")
            else:
                # Manual extraction: find non-resident $DATA attribute (type 0x80)
                try:
                    attr_off = struct.unpack_from("<H", mft_record0, 20)[0]
                    off = attr_off
                    while off + 16 <= len(mft_record0):
                        attr_type = struct.unpack_from("<I", mft_record0, off)[0]
                        if attr_type == 0xFFFFFFFF:
                            break
                        attr_len = struct.unpack_from("<I", mft_record0, off + 4)[0]
                        if attr_len <= 0 or off + attr_len > len(mft_record0):
                            break
                        non_res = mft_record0[off + 8]

                        if attr_type == 0x80 and non_res == 1 and attr_len >= 56:  # Non-resident $DATA
                            run_off = struct.unpack_from("<H", mft_record0, off + 32)[0]
                            real_size = struct.unpack_from("<Q", mft_record0, off + 48)[0]
                            mft_data_size = int(real_size)
                            runlist = mft_record0[off + run_off : off + attr_len]
                            mft_runs = _decode_runlist_to_lcns(runlist)
                            _log("INFO", f"Found {len(mft_runs)} MFT data runs (manual parse)")
                            break
                        off += attr_len
                except Exception as e:
                    _log("WARNING", f"Failed to parse $MFT data runs: {e}")

            mft_record_num = 0

            if mft_runs:
                # Walk MFT following data runs (fragmented MFT support)
                for run_idx, (lcn, length_clusters) in enumerate(mft_runs):
                    if state.stop_requested or mft_record_num >= max_records:
                        break
                    if lcn is None:
                        # Sparse run: skip but count records for inode numbering
                        sparse_records = (length_clusters * cluster_size) // record_size
                        mft_record_num += sparse_records
                        continue

                    run_offset = part_start + (lcn * cluster_size)
                    run_size = length_clusters * cluster_size
                    records_in_run = run_size // record_size

                    _log("DEBUG", f"MFT run {run_idx}: LCN={lcn}, {records_in_run} records (inode {mft_record_num})")

                    for i in range(records_in_run):
                        if state.stop_requested or mft_record_num >= max_records:
                            break

                        offset = run_offset + (i * record_size)
                        rec_data = safe_read_granular(src, state, offset, record_size, log_cb=None)

                        if not rec_data or len(rec_data) < record_size:
                            mft_record_num += 1
                            continue
                        if rec_data[:4] != b"FILE":
                            mft_record_num += 1
                            continue

                        summary = parse_mft_record_best_effort(
                            rec_data,
                            record_offset=offset,
                            mft_record_number=mft_record_num,
                            record_size=record_size,
                        )
                        if summary and (summary.file_names or summary.resident_data is not None or summary.data_runs is not None):
                            records.append(summary)

                        mft_record_num += 1

                        if mft_record_num % 1000 == 0:
                            _log("INFO", f"MFT progress: {mft_record_num} records, {len(records)} with data")
                            progress(mft_record_num, max_records)
            else:
                # No data runs: sequential read from MFT offset
                _log("WARNING", "No MFT data runs found, trying sequential read...")
                offset = mft_offset
                while mft_record_num < max_records:
                    if state.stop_requested:
                        break
                    rec_data = safe_read_granular(src, state, offset, record_size, log_cb=None)
                    if not rec_data or len(rec_data) < record_size:
                        break
                    if rec_data[:4] != b"FILE":
                        break

                    summary = parse_mft_record_best_effort(
                        rec_data,
                        record_offset=offset,
                        mft_record_number=mft_record_num,
                        record_size=record_size,
                    )
                    if summary and (summary.file_names or summary.resident_data is not None or summary.data_runs is not None):
                        records.append(summary)

                    mft_record_num += 1
                    offset += record_size

                    if mft_record_num % 500 == 0:
                        _log("INFO", f"Sequential MFT: {len(records)} records parsed")
                        progress(mft_record_num, max_records)

            _log("INFO", f"MFT scan complete: {len(records)} files in {mft_record_num} records")

            # Check if MFT result is too small (corrupt/partial) → fallback to brute-force
            expected_records = 0
            if mft_data_size > 0 and record_size > 0:
                expected_records = int(mft_data_size // record_size)
            if expected_records and mft_record_num < max(256, expected_records // 2):
                _log("WARNING", f"MFT size mismatch (expected~{expected_records}, got {mft_record_num}); falling back to brute-force...")
                records = []
                for rec in scan_and_parse_mft(
                    src, state,
                    start=int(part_start),
                    end=int(volume_end),
                    step=4096,
                    record_size=record_size,
                    log_cb=_log,
                    progress_cb=progress,
                ):
                    if state.stop_requested:
                        break
                    records.append(rec)
                    if len(records) >= max_records:
                        break
            elif not expected_records and mft_record_num < 512 and len(records) < 200:
                _log("WARNING", "MFT appears too small; falling back to brute-force...")
                records = []
                for rec in scan_and_parse_mft(
                    src, state,
                    start=int(part_start),
                    end=int(volume_end),
                    step=4096,
                    record_size=record_size,
                    log_cb=_log,
                    progress_cb=progress,
                ):
                    if state.stop_requested:
                        break
                    records.append(rec)
                    if len(records) >= max_records:
                        break
        else:
            # MFT not accessible → full brute-force scan
            _log("WARNING", "MFT not accessible at expected location. Falling back to brute-force scan...")
            for rec in scan_and_parse_mft(
                src, state,
                start=int(part_start),
                end=int(volume_end),
                step=4096,
                record_size=record_size,
                log_cb=_log,
                progress_cb=progress,
            ):
                if state.stop_requested or not state.is_alive:
                    break
                records.append(rec)
                if len(records) >= max_records:
                    _log("WARNING", f"Reached max_records={max_records}, truncating.")
                    break

        files = _records_to_files(records, part_start, cluster_size, include_deleted, include_active, max_resident, source="deep_mft")

        return _result(
            {
                "command": "deep_scan",
                "files": files,
                "count": len(files),
                "raw_record_count": len(records),
                "truncated": len(records) >= max_records,
            }
        )
    except Exception as e:
        return _error(f"deep_scan failed: {e}", details=traceback.format_exc())
    finally:
        try:
            if src is not None:
                src.close()
        except Exception:
            pass


def _command_mft_scan(payload: JsonObj) -> int:
    source_path = str(payload.get("source_path") or "").strip()
    if not source_path:
        return _error("source_path is required", code="invalid_payload")

    include_deleted = bool(payload.get("include_deleted", True))
    include_active = bool(payload.get("include_active", True))
    max_records = int(payload.get("max_records", 50000) or 50000)
    max_resident = int(payload.get("max_resident_bytes", 1024 * 1024) or (1024 * 1024))
    record_size = int(payload.get("record_size", 1024) or 1024)
    step = int(payload.get("step", 4096) or 4096)

    # Optional partition bounds for scoped scan
    start = int(payload.get("start", 0) or 0)
    end_val = payload.get("end")
    end = int(end_val) if end_val is not None else None

    if not include_deleted and not include_active:
        return _error("At least one of include_deleted/include_active must be true", code="invalid_payload")

    config = _load_config()
    state = RecoveryState(map_path=map_path_for_source(source_path))
    src = None
    try:
        src = open_source(source_path, config=config)
        total = int(src.size() or 0)
        records = []

        # Determine cluster_size from NTFS boot sector if partition bounds given
        cluster_size: int | None = None
        part_start = start
        if start > 0:
            try:
                boot_buf = safe_read_granular(src, state, start, 512, log_cb=None)
                boot = parse_ntfs_boot_sector(boot_buf) if boot_buf else None
                if boot and boot.cluster_size:
                    cluster_size = int(boot.cluster_size)
                    _log("INFO", f"MFT scan: detected cluster_size={cluster_size} from boot sector at {start}")
            except Exception:
                pass

        def progress(off: int, all_total: int) -> None:
            _progress("mft_scan", int(off), int(all_total if all_total > 0 else total))

        for rec in scan_and_parse_mft(
            src, state,
            start=start,
            end=end,
            step=step,
            record_size=record_size,
            log_cb=_log,
            progress_cb=progress,
        ):
            records.append(rec)
            if len(records) >= max_records:
                _log("WARNING", f"Reached max_records={max_records}, truncating mft scan results.")
                break

        files = _records_to_files(records, part_start, cluster_size, include_deleted, include_active, max_resident, source="brute_mft")

        return _result(
            {
                "command": "mft_scan",
                "files": files,
                "count": len(files),
                "raw_record_count": len(records),
                "truncated": len(records) >= max_records,
            }
        )
    except Exception as e:
        return _error(f"mft_scan failed: {e}", details=traceback.format_exc())
    finally:
        try:
            if src is not None:
                src.close()
        except Exception:
            pass


def _command_file_carve(payload: JsonObj) -> int:
    source_path = str(payload.get("source_path") or "").strip()
    out_dir = str(payload.get("out_dir") or "").strip()
    if not source_path:
        return _error("source_path is required", code="invalid_payload")
    if not out_dir:
        return _error("out_dir is required", code="invalid_payload")

    config = _load_config()
    state = RecoveryState(map_path=map_path_for_source(source_path))
    src = None
    try:
        src = open_source(source_path, config=config)

        def progress(off: int, total: int) -> None:
            _progress("file_carve", int(off), int(total))

        found = carve_signatures(src, state, Path(out_dir), log_cb=_log, progress_cb=progress)
        return _result({"command": "file_carve", "found": int(found), "out_dir": out_dir})
    except Exception as e:
        return _error(f"file_carve failed: {e}", details=traceback.format_exc())
    finally:
        try:
            if src is not None:
                src.close()
        except Exception:
            pass


def _command_create_image(payload: JsonObj) -> int:
    source_path = str(payload.get("source_path") or "").strip()
    out_path = str(payload.get("out_path") or "").strip()
    if not source_path:
        return _error("source_path is required", code="invalid_payload")
    if not out_path:
        return _error("out_path is required", code="invalid_payload")

    start = int(payload.get("start", 0) or 0)
    end = payload.get("end", None)
    end_int = int(end) if end is not None else None

    config = _load_config()
    state = RecoveryState(map_path=map_path_for_source(source_path))
    src = None
    try:
        src = open_source(source_path, config=config)

        def progress(off: int, total: int) -> None:
            _progress("create_image", int(off), int(total))

        create_image(
            src, state,
            Path(out_path),
            start=start,
            end=end_int,
            log_cb=_log,
            progress_cb=progress,
        )
        return _result({"command": "create_image", "out_path": out_path})
    except Exception as e:
        return _error(f"create_image failed: {e}", details=traceback.format_exc())
    finally:
        try:
            if src is not None:
                src.close()
        except Exception:
            pass


def _command_parse_fs(payload: JsonObj) -> int:
    """Browse filesystem via pytsk3 — lists directory tree with file metadata."""
    source_path = str(payload.get("source_path") or "").strip()
    if not source_path:
        return _error("source_path is required", code="invalid_payload")

    if pytsk3 is None:
        return _error(
            "pytsk3 is not installed. Install it to use filesystem browsing.",
            code="pytsk3_unavailable",
        )

    part_start = int(payload.get("partition_start", 0) or 0)
    part_length = int(payload.get("partition_length", 0) or 0)
    max_entries = int(payload.get("max_entries", 100000) or 100000)

    config = _load_config()
    state = RecoveryState(map_path=map_path_for_source(source_path))
    src = None
    try:
        src = open_source(source_path, config=config)

        from .tskimg import DDEUImg
        img = DDEUImg(src, state, log_cb=_log)

        # Try to open filesystem with offset correction (mirrors gui.py:_open_fs_smart)
        base = int(part_start)
        offsets_to_try: list[int] = []
        for delta in (0, 512, -512):
            off = base + delta
            if off >= 0:
                offsets_to_try.append(off)

        # For NTFS boot sectors, also try derived start offset
        start_candidates: list[int] = []
        for off in list(offsets_to_try):
            try:
                boot_buf = safe_read_granular(src, state, off, 512, log_cb=None)
            except Exception:
                boot_buf = b""
            boot = parse_ntfs_boot_sector(boot_buf) if boot_buf else None
            if not boot:
                continue
            vol_lba512 = int(boot.volume_size_bytes // 512) if boot.volume_size_bytes > 0 else 0
            if vol_lba512 <= 0:
                continue
            lba_hit = int(off // 512)
            start_lba = int(lba_hit - vol_lba512 + 1)
            if start_lba < 0 or start_lba >= lba_hit:
                continue
            start_off = start_lba * 512
            if start_off >= 0:
                start_candidates.append(start_off)

        candidates = start_candidates + offsets_to_try
        seen: set[int] = set()
        ordered: list[int] = []
        for off in candidates:
            if off in seen:
                continue
            seen.add(off)
            ordered.append(off)

        fs = None
        fs_offset = base
        last_err: Exception | None = None
        for off in ordered:
            try:
                fs = pytsk3.FS_Info(img, offset=int(off))
                fs_offset = int(off)
                if off != base:
                    _log("WARNING", f"Adjusted filesystem offset: {base} -> {off}")
                break
            except Exception as e:
                last_err = e
                continue

        if fs is None:
            # Fallback: try deep_scan if this is an NTFS partition
            err_msg = f"Failed to open filesystem: {last_err}"
            _log("WARNING", err_msg + " Falling back to deep scan.")
            # Attempt deep scan as fallback
            fallback_payload: JsonObj = dict(payload)
            fallback_payload.setdefault("max_records", max_entries)
            return _command_deep_scan(fallback_payload)

        # Walk directory tree recursively
        _log("INFO", f"Filesystem opened at offset {fs_offset}. Walking directory tree...")
        files: list[JsonObj] = []
        _SKIP_NAMES = {".", "..", "$MFT", "$LogFile", "$BadClus", "$Bitmap", "$Boot",
                        "$AttrDef", "$Volume", "$Secure", "$UpCase", "$Extend"}

        def walk_dir(directory: Any, base_path: str) -> None:
            if len(files) >= max_entries:
                return
            for entry in directory:
                if len(files) >= max_entries:
                    return
                try:
                    if not hasattr(entry.info, "name") or not entry.info.name:
                        continue
                    name_bytes = entry.info.name.name
                    if not name_bytes:
                        continue
                    name = name_bytes.decode("utf-8", errors="replace")
                    if name in _SKIP_NAMES:
                        continue
                    meta = entry.info.meta
                    if not meta:
                        continue
                    status = "DELETED" if (meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC) else "ACTIVE"
                    full_path = f"{base_path}/{name}" if base_path else name
                    inode = int(meta.addr)
                    is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                    size = int(meta.size or 0)
                    files.append(
                        _make_file_item(
                            path=full_path,
                            size=size,
                            status=status,
                            inode=inode,
                            part_offset=int(fs_offset),
                            is_dir=is_dir,
                            resident_data_b64=None,
                            data_runs=[],
                            data_size=(size if not is_dir else None),
                            cluster_size=None,
                            source="pytsk3",
                            name_source="pytsk3",
                        )
                    )
                    if is_dir:
                        try:
                            walk_dir(entry.as_directory(), full_path)
                        except Exception:
                            pass
                except Exception:
                    continue

        root_dir = fs.open_dir(path="/")
        walk_dir(root_dir, "")

        _log("INFO", f"Filesystem walk complete: {len(files)} entries")
        return _result(
            {
                "command": "parse_fs",
                "files": files,
                "count": len(files),
                "fs_offset": fs_offset,
                "truncated": len(files) >= max_entries,
            }
        )
    except Exception as e:
        return _error(f"parse_fs failed: {e}", details=traceback.format_exc())
    finally:
        try:
            if src is not None:
                src.close()
        except Exception:
            pass


def _should_skip_existing(path: Path, expected_size: int) -> bool:
    try:
        if not path.exists():
            return False
        st = path.stat()
        existing = int(getattr(st, "st_size", 0) or 0)
        if expected_size > 0:
            return existing == expected_size
        return existing > 0
    except Exception:
        return False


def _command_recover_items(payload: JsonObj) -> int:
    source_path = str(payload.get("source_path") or "").strip()
    output_root = str(payload.get("output_root") or "").strip()
    items = payload.get("items")
    skip_existing = bool(payload.get("skip_existing", True))
    overwrite = bool(payload.get("overwrite", False))

    if not source_path:
        return _error("source_path is required", code="invalid_payload")
    if not output_root:
        return _error("output_root is required", code="invalid_payload")
    if not isinstance(items, list):
        return _error("items must be an array", code="invalid_payload")

    config = _load_config()
    state = RecoveryState(map_path=map_path_for_source(source_path))
    src = None
    img = None
    exporters: dict[int, Any] = {}
    out_root = Path(output_root)
    ok_count = 0
    skipped = 0
    errors = 0
    total = len(items)
    try:
        src = open_source(source_path, config=config)

        for idx, item in enumerate(items, start=1):
            _progress("recover_items", idx, total if total > 0 else 1)
            if not isinstance(item, dict):
                skipped += 1
                continue

            is_dir = bool(item.get("is_dir", False))
            rel = _safe_rel_path(str(item.get("path") or ""))
            if not rel:
                inode_fallback = int(item.get("inode", 0) or 0)
                rel = f"inode_{inode_fallback}" if inode_fallback > 0 else f"file_{idx}"

            target = out_root / rel

            # Directories: just create the folder, don't try to recover as file
            if is_dir:
                try:
                    target.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                skipped += 1
                continue
            file_size = int(item.get("size", 0) or 0)
            if skip_existing and _should_skip_existing(target, file_size):
                skipped += 1
                continue
            if target.exists() and not overwrite:
                stem = target.stem
                suf = target.suffix
                parent = target.parent
                serial = 1
                while True:
                    cand = parent / f"{stem}_{serial}{suf}"
                    if not cand.exists():
                        target = cand
                        break
                    serial += 1

            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                resident_b64 = item.get("resident_data_b64")
                if isinstance(resident_b64, str) and resident_b64:
                    data = base64.b64decode(resident_b64.encode("ascii"))
                    target.write_bytes(data)
                    ok_count += 1
                    _log("INFO", f"Recovered (resident): {target}")
                    continue

                part_offset = int(item.get("part_offset", 0) or 0)
                cluster_size = item.get("cluster_size")
                runs = _deserialize_runs(item.get("data_runs"))
                data_size = item.get("data_size")
                expected_size = int(data_size) if data_size is not None else None
                if runs and cluster_size is not None:
                    recover_nonresident_runs(
                        src, state, target,
                        part_offset=part_offset,
                        cluster_size=int(cluster_size),
                        runs=runs,
                        expected_size=expected_size,
                        log_cb=_log,
                    )
                    ok_count += 1
                    _log("INFO", f"Recovered (non-resident): {target}")
                    continue

                inode = int(item.get("inode", 0) or 0)
                if inode > 0 and part_offset >= 0 and pytsk3 is not None:
                    if img is None:
                        from .tskimg import DDEUImg
                        img = DDEUImg(src, state, log_cb=_log)
                    exporter = exporters.get(part_offset)
                    if exporter is None:
                        from .exporter import RobustExporter
                        fs = pytsk3.FS_Info(img, offset=int(part_offset))
                        exporter = RobustExporter(fs, state, log_cb=_log)
                        exporters[part_offset] = exporter
                    ok = exporter.export_inode(inode, target)
                    if ok:
                        ok_count += 1
                        _log("INFO", f"Recovered: {target}")
                    else:
                        errors += 1
                        _log("WARNING", f"Could not recover inode={inode}: {target}")
                    continue

                errors += 1
                _log("WARNING", f"Insufficient metadata, skipped: {target}")
            except Exception as e:
                errors += 1
                _log("ERROR", f"Recover failed for {target}: {e}")

        return _result(
            {
                "command": "recover_items",
                "ok": ok_count,
                "skipped": skipped,
                "errors": errors,
                "total": total,
                "output_root": output_root,
            }
        )
    except Exception as e:
        return _error(f"recover_items failed: {e}", details=traceback.format_exc())
    finally:
        try:
            if src is not None:
                src.close()
        except Exception:
            pass


def _command_stop(_: JsonObj) -> int:
    return _result({"command": "stop", "status": "ok"})


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def _dispatch(command: str, payload: JsonObj) -> int:
    handlers: dict[str, Callable[[JsonObj], int]] = {
        "list_disks": _command_list_disks,
        "scan_partitions": _command_scan_partitions,
        "deep_scan": _command_deep_scan,
        "mft_scan": _command_mft_scan,
        "file_carve": _command_file_carve,
        "create_image": _command_create_image,
        "recover_items": _command_recover_items,
        "parse_fs": _command_parse_fs,
        "stop": _command_stop,
    }
    fn = handlers.get(command)
    if fn is None:
        return _error(f"Unknown command: {command}", code="unknown_command")
    return fn(payload)


def _health() -> int:
    details = {
        "python": sys.executable,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "pytsk3_available": pytsk3 is not None,
    }
    _emit({"type": "health", "ok": True, "details": details})
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pyddeu.winui_bridge", add_help=True)
    p.add_argument("--health", action="store_true", help="Emit bridge health JSON and exit")
    p.add_argument("--command", type=str, default="", help="Bridge command name")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.health:
        return _health()

    command = str(args.command or "").strip()
    if not command:
        return _error("Missing --command", code="invalid_cli")

    try:
        payload = _read_payload_from_stdin()
    except Exception as e:
        return _error(str(e), code="invalid_payload")

    try:
        return int(_dispatch(command, payload))
    except KeyboardInterrupt:
        return _error("Operation interrupted", code="interrupted")
    except Exception as e:
        return _error(f"Unhandled bridge error: {e}", details=traceback.format_exc())


if __name__ == "__main__":
    raise SystemExit(main())
