# Linux Implementation Documentation

This document describes the modifications and debugging steps taken to complete the Linux version of PyDDEU, a forensic-oriented NTFS browsing and file recovery tool.

## Overview of Changes

The Linux implementation has been enhanced to match the capabilities of the Windows version and align with DMDE's data recovery methods. Key improvements include:

1. **Timeout-Protected I/O Operations** - Prevents blocking on faulty sectors
2. **Sector-Aligned Reads** - Ensures proper access to raw block devices
3. **O_DIRECT Support** - Bypasses kernel buffer cache for direct disk access
4. **Device Refresh/Reconnect** - Handles device resets and reconnections
5. **Enhanced Error Detection** - Linux-specific error code handling
6. **Improved Kernel Monitoring** - Better detection of disk errors via dmesg
7. **DMDE-Style 512-byte LBA Probing** - Scans using 512-byte LBAs even on 4K-reporting USB bridges
8. **NTFS Backup-Boot Normalization** - Avoids off-by-one mounts (e.g., LBA-1 / backup boot sector)
9. **GUI Smart Mount Offsets** - Auto-corrects `pytsk3` mount offsets by ±1 sector / backup-boot math

## Detailed Changes

### 1. Linux I/O Layer (`pyddeu/io/posix.py`)

**Complete rewrite of the Linux I/O layer with the following features:**

#### Timeout Support
```python
def _read_with_timeout_thread(fd: int, offset: int, size: int, timeout_ms: int) -> bytes:
```
- Uses a helper thread to perform reads with configurable timeout
- Raises `ReadTimeoutError` if the read doesn't complete within the timeout
- Prevents infinite blocking on faulty/failing media
- Default timeout: 5000ms (configurable via `deviowait_ms` in config)

#### Sector Alignment
```python
def _align_read(offset: int, size: int, sector_size: int, device_size: int) -> tuple:
```
- Automatically aligns reads to sector boundaries for raw block devices
- Supports 512-byte and 4K sector drives
- Handles boundary cases at device end
- Extracts requested data from aligned buffer

#### O_DIRECT Support
- Automatically detects and uses `O_DIRECT` for block devices
- Bypasses kernel buffer cache for more reliable reads on failing drives
- Falls back to normal mode if O_DIRECT is not supported

#### Device Refresh
```python
def refresh_with_timeout(self, timeout_s: float = 5.0) -> bool:
```
- Re-opens device handle after controller reset
- Implements timeout to prevent infinite blocking during device recovery
- Thread-safe implementation with lock protection

#### New Linux-Specific Classes
- `LinuxDiskSource` - Full-featured block device source with all above capabilities
- `ReadTimeoutError` - Custom exception for timeout conditions

#### Improved Device Detection
```python
def list_linux_devices() -> list[SourceInfo]:
```
- Scans `/sys/block` for available devices
- Filters virtual devices (loop, ram, dm-, md, nbd, zram)
- Detects device model from sysfs
- Identifies SSD vs HDD via rotational status

### 2. Error Code Handling (`pyddeu/scan.py`)

**Added Linux-specific error code detection:**

```python
LINUX_PANIC_CODES = frozenset({
    errno.EIO,         # 5: I/O error
    errno.ENXIO,       # 6: No such device or address
    errno.ENODEV,      # 19: No such device
    errno.ENOMEDIUM,   # 123: No medium found
    errno.EBUSY,       # 16: Device or resource busy
})
```

**Note:** `ETIMEDOUT` (110) is treated as *recoverable bad/slow media* on Linux to avoid “panic/stop” on weak SSDs. The scanner bumps skip modestly and continues.

**Platform-aware error classification:**
```python
def _is_panic_error(e: OSError) -> bool:
```
- Checks `winerror` on Windows, `errno` on Linux
- Triggers controller panic handling for device issues
- Initiates device refresh on panic conditions

### 3. Kernel Monitor (`pyddeu/monitor.py`)

**Enhanced `LinuxKernelMonitor` with comprehensive error detection:**

#### Critical Patterns (trigger panic)
- reset, disconnected, offline
- controller is down, fatal error
- device removed, task abort
- hard reset, link down
- not responding, device not ready
- aborted command, host reset

#### Warning Patterns (logged but don't trigger panic)
- i/o error, buffer i/o
- medium error, read error, write error
- crc error, uncorrectable error
- sense data, command failed
- timeout, retry, bad sector

#### NVMe-Specific Detection
- Detects NVMe errors, timeouts, and aborts as critical
- Handles NVMe-specific error messages

#### SCSI/ATA Detection
- Recognizes ATA exception messages
- Handles SCSI sense data

#### Error Frequency Tracking
- Tracks error rate over time
- Triggers panic if >5 errors in <5 seconds

### 4. Factory Updates (`pyddeu/io/factory.py`)

**Config propagation to Linux:**
```python
def open_source(path: str, *, config: PyddeuConfig | None = None) -> DiskSource:
    # Now passes config to Linux implementation
    return open_posix_source(path, config=config)
```

**Improved device listing:**
- Uses enhanced `list_linux_devices()` function
- Provides more detailed device information

## DMDE Compatibility

The implementation follows DMDE's recovery principles:

### Volume Detection
- **Partition Table Reading**: MBR/GPT parsing in `partitions.py`
- **Volume Signature Scanning**: Smart Scan for finding NTFS/FAT32/exFAT boot sectors
- **Carving**: Boot sector carving when tables are damaged
- **Backup Boot Handling**: If an NTFS boot is found at the last sector of a volume, compute and use the real start (prevents `pytsk3` opening at the wrong offset).

### Deleted File Recovery
- **MFT Parsing**: Reads and interprets NTFS $MFT records
- **Deletion Detection**: Identifies deleted files via in-use flag
- **Directory Reconstruction**: Uses parent references for tree building

### Faulty Sector Handling
- **Bad Region Map**: Per-source JSON-based tracking (`pyddeu.map.*.json`)
- **Adaptive Skip**: Exponential backoff on consecutive errors
- **Sector-by-Sector Fallback**: Granular reads when bulk reads fail
- **Controller Panic Detection**: Auto-pause on device issues

## Configuration

The Linux implementation respects all config options from `pyddeu.ini`:

```ini
[IO]
deviowait=5000      # Read timeout in milliseconds
retries=1           # Retry attempts on error
seekretries=1       # Seek retry attempts
deviojump=2048      # Sectors to skip after error
deviobadfiller=0x20444142   # Pattern for bad sectors ("BAD ")
devioskipfiller=0x50494B53  # Pattern for skipped sectors ("SKIP")
```

## Test Suite

A comprehensive test suite has been created in `tests/`:

- `test_posix_io.py` - Tests for Linux I/O layer (37 tests)
- `test_scan.py` - Tests for scan module (21 tests)
- `test_state.py` - Tests for state management (22 tests)
- `test_monitor.py` - Tests for kernel monitoring (15 tests)
- `test_partitions.py` - Tests for DMDE-style partition scan normalization

Run tests with:
```bash
python3 -m unittest discover tests/
```

## Usage on Linux

### Requirements
- Python >= 3.10
- Root/sudo privileges for raw disk access
- pytsk3 >= 20230125

### Running
```bash
# List available disks
sudo python3 -m pyddeu list-disks

# Launch GUI
sudo python3 -m pyddeu gui

# Scan a device
sudo python3 -m pyddeu scan --source /dev/sdX
```

### Permissions
Raw disk access on Linux requires elevated privileges:
```bash
# Option 1: Run as root
sudo python3 -m pyddeu gui

# Option 2: Add user to disk group (less secure)
sudo usermod -a -G disk $USER
# Log out and back in
```

## Debugging

### Enable Debug Logging
The GUI logs to `pyddeu_debug.log` in the working directory.

### Kernel Message Monitoring
The program automatically monitors `dmesg` for disk errors. Manual monitoring:
```bash
sudo dmesg -w | grep -E "sd|nvme|ata|scsi|i/o"
```

### Bad Region Maps
Per-source bad region maps are stored as:
```
pyddeu.map.<device>.<hash>.json
```
Example: `pyddeu.map.sda.abc1234567.json`

## Known Limitations

1. **O_DIRECT Memory Alignment** - Some systems may require aligned memory buffers for O_DIRECT; the implementation handles this internally.

2. **NVMe Device Names** - NVMe devices use `/dev/nvmeXnY` naming; the implementation detects these correctly.

3. **Loop Devices** - Virtual devices (loop, dm-*) are filtered from device listing but can still be opened directly.

4. **USB Device Reconnection** - After USB device reconnection, may need to re-scan device list.

## Files Modified

| File | Changes |
|------|---------|
| `pyddeu/io/posix.py` | Complete rewrite with timeout, alignment, O_DIRECT |
| `pyddeu/io/factory.py` | Config propagation, improved listing |
| `pyddeu/scan.py` | Linux error code handling |
| `pyddeu/monitor.py` | Enhanced kernel error detection |
| `tests/*.py` | Comprehensive test suite (92 tests) |
| `LINUX_IMPLEMENTATION.md` | This documentation |

## Verification Checklist

- [x] Timeout-protected reads prevent blocking
- [x] Sector alignment works for all sector sizes
- [x] O_DIRECT support enabled when available
- [x] Device refresh handles controller resets
- [x] Linux error codes trigger appropriate handling
- [x] Kernel monitor detects all relevant errors
- [x] Bad region maps persist across sessions
- [x] Config options respected on Linux
- [x] All 92 unit tests pass
