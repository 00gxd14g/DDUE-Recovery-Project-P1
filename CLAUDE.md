# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyDDEU is a cross-platform (Windows/Linux) forensic-oriented NTFS browsing and file recovery tool using `pytsk3`. It provides a safer raw/image read layer with a "bad region" map to handle weak/failing media gracefully.

## Commands

### Install dependencies
```bash
python -m pip install -r requirements.txt
```

### Run the GUI
```bash
python -m pyddeu gui
```

### CLI commands
```bash
python -m pyddeu list-disks
python -m pyddeu scan --source <path>
```

On Linux, source paths are `/dev/sdX` (requires root). On Windows, use `\\.\PhysicalDriveN` (requires Administrator).

## Architecture

### Core Modules

- **`pyddeu/io/`** - Platform-abstracted disk I/O layer
  - `base.py`: `DiskSource` protocol and `SourceInfo` dataclass
  - `factory.py`: `open_source()` and `list_sources()` - auto-selects platform implementation
  - `windows.py`: Windows-specific raw disk access with overlapped I/O and timeout support
  - `posix.py`: Linux/Unix disk access via standard file operations

- **`pyddeu/state.py`** - Recovery state management
  - `RecoveryState`: Tracks bad regions, adaptive skip sizes, pause/stop state, controller panic detection
  - `BadRegionMap`: Per-source JSON-based bad sector tracking with merge logic
  - `map_path_for_source()`: Generates stable per-disk map file paths

- **`pyddeu/scan.py`** - Safe read operations
  - `safe_read()`: Single read with bad-map checking and error registration
  - `safe_read_granular()`: Falls back to sector-by-sector reads on error, zero-fills bad sectors

- **`pyddeu/partitions.py`** - Partition table parsing and carving
  - `scan_partitions()`: MBR/GPT parsing with Smart Scan fallback (chain-probing NTFS/FAT32/exFAT boot sectors)
  - `carve_ntfs_partitions()`, `carve_exfat_partitions()`, `carve_fat32_partitions()`: Boot sector carving when tables are damaged

- **`pyddeu/mft.py`** - NTFS MFT record parsing
  - `scan_for_mft_records()`: Scans for "FILE" signatures
  - `parse_mft_record_best_effort()`: Extracts filenames, parent refs, resident data, and data runs

- **`pyddeu/ntfs.py`** - NTFS runlist decoder (`parse_runlist()`)

- **`pyddeu/ntfs_boot.py`** - NTFS boot sector parsing (`parse_ntfs_boot_sector()` returns `NtfsBoot` dataclass)

- **`pyddeu/recover.py`** - `recover_nonresident_runs()`: Reads data runs in 1MB chunks, zero-fills bad areas

- **`pyddeu/carve.py`** - Signature-based file carving (JPEG, PDF, ZIP headers/footers)

- **`pyddeu/exporter.py`** - `RobustExporter`: pytsk3-based export with exponential backoff for controller errors

- **`pyddeu/imager.py`** - `create_image()`: Raw disk imaging with progress callbacks

- **`pyddeu/monitor.py`** - OS-level disk error monitoring
  - `LinuxKernelMonitor`: Tails `dmesg -w` for I/O errors and controller resets
  - `WindowsDiskEventMonitor`: Polls Windows Event Log for disk/storage events

- **`pyddeu/config.py`** - `PyddeuConfig`: Loads settings from `pyddeu.ini` (DMDE-like format)

- **`pyddeu/gui.py`** - Tkinter-based GUI (`PyDDEUGui` class)

- **`pyddeu/tskimg.py`** - `DDEUImg`: pytsk3 `Img_Info` wrapper for `DiskSource`

### Key Design Patterns

1. **Defensive I/O**: All disk reads go through `safe_read`/`safe_read_granular` which handle timeouts, register errors in the bad map, and zero-fill unreadable regions.

2. **Adaptive Skip**: On consecutive errors, `skip_size` doubles exponentially to quickly escape dead zones.

3. **Controller Panic Detection**: Windows error codes (21, 55, 1117, 1460) and Linux kernel messages trigger pauses and handle refreshes.

4. **Per-Source Bad Maps**: Each disk/image gets its own `pyddeu.map.<name>.<hash>.json` file to avoid cross-contamination.

5. **Read-Only by Default**: Source disks are never written to; all output goes to separate paths.

## Configuration

Create `pyddeu.ini` in the working directory with DMDE-style settings:

```ini
[Setup]
readonly=1

[IO]
retries=1
seekretries=1
deviojump=0
deviowait=5000
scsitimeout=5
buffer=131072
dblbuffer=2097152
diskcache=16777216
```

## Logging

- GUI logs stream to the text widget and to `pyddeu_debug.log`
- Linux: kernel messages via `dmesg -w`
- Windows: System event log polling for disk/storage events (shown as `EVENTLOG:` lines)

## Dependencies

- Python >= 3.10
- pytsk3 >= 20230125
