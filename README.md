# PyDDEU (Prototype → Modular)

Cross-platform (Windows/Linux) forensic-oriented NTFS browsing + file recovery using `pytsk3`, with a safer raw/image read layer and a simple “bad region” map to survive weak media.

## Quick start

### Install
```bash
python -m pip install -r requirements.txt
```

### Run GUI
```bash
python -m pyddeu gui
```

## CLI helpers

```bash
python -m pyddeu list-disks
python -m pyddeu scan --source <path>
```

## DMDE-like read-only scans (GUI)

- `Scan Partitions`: MBR/GPT parse; if missing/corrupt, falls back to read-only NTFS boot-sector carving.
- `MFT Scan (RAW)`: scans the whole device/image for `FILE` MFT record signatures and lists best-effort results (including deleted) + can save resident data.
- `File Carve (RAW)`: signature-based carving (JPEG/PDF/ZIP) into a chosen output folder.
- `Deep Scan (NTFS)`: scans the selected NTFS partition, parses MFT records, rebuilds paths via Parent Directory refs, and enables recovery of resident + non-resident `$DATA` using decoded runlists (best-effort).

Logs stream live in the GUI and also to `pyddeu_debug.log`.
On Linux, kernel messages are tailed via `dmesg -w`. On Windows, recent System disk/storage events are polled (best-effort) and shown as `EVENTLOG:` lines.

## Output + Imaging

- Set `Output` to a folder on a different disk; recovered files are written under this folder (paths are preserved best-effort).
- Use `Create Image…` to write a raw `.img`/`.dd` image file to a different disk (source is never written).
- Use `Image Selected Part…` to image only the selected carved/parsed partition (recommended when the partition table is damaged).
- Use `Export All…` to bulk-save everything currently listed, optionally filtered by extension and Deleted/Active.

## Source types

- **Disk image file**: recommended for safety (RAW `.dd` / `.img`, etc.).
- **Raw device**:
  - Linux: `/dev/sdX` (root required).
  - Windows: `\\.\PhysicalDriveN` (Administrator required).

## Notes (SSD forensics)

- If TRIM/UNMAP already ran and the SSD returns deterministic zeros, software cannot recover those LBAs via normal reads.
- Avoid mounting the target disk read/write; prefer a write-blocked setup and image-first workflows.
