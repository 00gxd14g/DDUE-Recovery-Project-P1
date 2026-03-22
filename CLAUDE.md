# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyDDEU is a cross-platform (Windows/Linux) forensic-oriented NTFS browsing and file recovery tool using `pytsk3`. It provides a safer raw/image read layer with a "bad region" map to handle weak/failing media gracefully. Inspired by DMDE's approach to defensive I/O and read-only scanning.

## Commands

### Install dependencies
```bash
python -m pip install -r requirements.txt
```

### Run the GUI (Tkinter)
```bash
python -m pyddeu gui
```

### CLI commands
```bash
python -m pyddeu list-disks
python -m pyddeu scan --source <path>
```

On Linux, source paths are `/dev/sdX` (requires root). On Windows, use `\\.\PhysicalDriveN` (requires Administrator).

### Run tests
```bash
python -m pytest tests/
python -m pytest tests/test_scan.py           # single test file
python -m pytest tests/test_scan.py -k "test_name"  # single test
```

Tests use `unittest` style (TestCase classes) but are runnable via pytest. Test files: `test_scan.py`, `test_state.py`, `test_partitions.py`, `test_posix_io.py`, `test_monitor.py`.

## Architecture

### Data Flow

```
DiskSource (io/) --> safe_read / safe_read_granular (scan.py)
                         |
                    RecoveryState + BadRegionMap (state.py)
                         |
         +---------------+----------------+
         |               |                |
   partitions.py      mft.py          carve.py
   (MBR/GPT/carve)   (MFT parse)     (sig carve)
         |               |
    ntfs_boot.py    recover.py
                    (data run recovery)
         |               |
    exporter.py     imager.py
    (pytsk3 export)  (raw imaging)
```

### Core Modules

- **`pyddeu/io/`** - Platform-abstracted disk I/O layer
  - `base.py`: `DiskSource` protocol (read_at, size, sector_size, close) and `SourceInfo` dataclass
  - `factory.py`: `open_source()` and `list_sources()` - auto-selects platform via `IS_WINDOWS`
  - `windows.py`: Windows raw disk access via `ctypes` (kernel32 overlapped I/O with timeout, sector alignment, GLOBALROOT fallback, WMI fallback for drive listing)
  - `posix.py`: Linux disk access with O_DIRECT, pread, timeout threads, ioctl for size/sector queries

- **`pyddeu/platform.py`** - Platform detection (`IS_WINDOWS`, `IS_LINUX`, `IS_MAC`), `is_admin()`, `format_source_hint()`

- **`pyddeu/state.py`** - Recovery state management
  - `BadRegionMap`: Thread-safe per-source JSON bad sector tracking with binary search and merge logic
  - `RecoveryState`: Tracks bad regions, adaptive skip sizes (exponential doubling), pause/stop state, controller panic detection
  - `map_path_for_source()`: Generates stable per-disk map file paths (`pyddeu.map.<name>.<hash>.json`)

- **`pyddeu/scan.py`** - Safe read operations (the core defensive I/O layer)
  - `safe_read()`: Single read with bad-map check, zero-fill on error
  - `safe_read_granular()`: Falls back to sector-by-sector on error, supports retries, deviojump, fill patterns from config
  - Controller panic detection: classifies OS errors (Windows winerror codes, Linux errno) to trigger handle refresh

- **`pyddeu/partitions.py`** - Partition table parsing and carving
  - `scan_partitions()`: MBR/GPT parsing with Smart Scan fallback (chain-probing NTFS/FAT32/exFAT boot sectors every 1MB)
  - `carve_ntfs_partitions()`, `carve_exfat_partitions()`, `carve_fat32_partitions()`: Boot sector signature carving when tables are damaged

- **`pyddeu/mft.py`** - NTFS MFT record parsing
  - `scan_for_mft_records()`: Scans for "FILE" signatures with adaptive skip on errors
  - `parse_mft_record_best_effort()`: Extracts filenames (with Win32/DOS namespace priority), parent refs, resident data, data runs, USA fixups
  - `build_paths()`: Reconstructs directory paths from parent refs
  - `_decode_runlist_to_lcns()`: Converts NTFS runlist bytes to absolute LCN runs

- **`pyddeu/ntfs.py`** - NTFS runlist decoder (`parse_runlist()`)
- **`pyddeu/ntfs_boot.py`** - NTFS boot sector parsing (`NtfsBoot` dataclass)
- **`pyddeu/recover.py`** - `recover_nonresident_runs()`: Streams data runs in 1MB chunks via `safe_read_granular`, zero-fills bad areas
- **`pyddeu/carve.py`** - Signature-based file carving (JPEG, PDF, ZIP headers/footers)
- **`pyddeu/exporter.py`** - `RobustExporter`: pytsk3-based export with exponential backoff
- **`pyddeu/imager.py`** - `create_image()`: Raw disk imaging with progress callbacks
- **`pyddeu/monitor.py`** - OS-level disk error monitoring (`LinuxKernelMonitor` via dmesg, `WindowsDiskEventMonitor` via Event Log)
- **`pyddeu/config.py`** - `PyddeuConfig`: Loads settings from `pyddeu.ini` (DMDE-like `[Setup]`/`[IO]` format with clamped ranges)
- **`pyddeu/gui.py`** - Tkinter-based GUI (`PyDDEUGui` class) - main user interface
- **`pyddeu/winui_bridge.py`** - JSON-RPC bridge for WinUI frontend (in `winui/`) - alternative to Tkinter GUI
- **`pyddeu/tskimg.py`** - `DDEUImg`: pytsk3 `Img_Info` wrapper for `DiskSource`
- **`pyddeu/cli.py`** - CLI entry point via argparse (`list-disks`, `scan`, `gui` subcommands)

### Key Design Patterns

1. **Defensive I/O**: All disk reads go through `safe_read`/`safe_read_granular` which handle timeouts, register errors in the bad map, and zero-fill unreadable regions. Never read raw disk directly.

2. **Adaptive Skip**: On consecutive errors, `skip_size` doubles exponentially (capped at 128MB) to escape dead zones quickly. Resets to `block_size` on first success.

3. **Controller Panic Detection**: Windows error codes (21, 55, 87, 1117, 1460) and Linux errno values (EIO, ENXIO, ENODEV, EBUSY) trigger handle refresh and aggressive skip. ETIMEDOUT is treated as recoverable (media slow, not controller dead).

4. **Per-Source Bad Maps**: Each disk/image gets its own `pyddeu.map.<name>.<hash>.json` file. Maps auto-save every 50 errors. Binary search for containment checks.

5. **Read-Only by Default**: Source disks are never written to; all output goes to separate paths.

6. **Platform Abstraction**: `DiskSource` protocol in `io/base.py` with platform-specific implementations selected at runtime via `io/factory.py`. Both Windows and Linux implementations support timeout-protected reads and sector alignment.

7. **Thread Safety**: `BadRegionMap`, `RecoveryState`, and both `DiskSource` implementations use threading locks. GUI operations dispatch to background threads.

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

`deviowait=0` is overridden to 5000ms for safety (prevents infinite hangs on bad sectors).

## Logging

- GUI logs stream to the text widget and to `pyddeu_debug.log`
- Linux: kernel messages via `dmesg -w`
- Windows: System event log polling for disk/storage events (shown as `EVENTLOG:` lines)

## Dependencies

- Python >= 3.10
- pytsk3 >= 20230125

## Engineering Preferences

- DRY is important — flag repetition aggressively.
- Well-tested code is non-negotiable; prefer too many tests over too few.
- Code should be "engineered enough" — not fragile/hacky, not over-abstracted.
- Handle more edge cases, not fewer; thoughtfulness > speed.
- Bias toward explicit over clever.

## Plan Mode

When entering Plan Mode for code review, follow the structured review process in `PLAN_MODE_PROMPT.md`.
