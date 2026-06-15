# PyDDEU

PyDDEU is a cross-platform, read-only disk inspection and recovery toolkit for
Windows and Linux. It combines NTFS browsing through `pytsk3` with defensive
raw-device reads, damaged-region tracking, partition discovery, imaging, and
file carving.

The project is intended for forensic analysis and recovery from media you own
or are authorized to examine.

## Capabilities

- Enumerate disks and inspect raw devices or image files
- Parse MBR and GPT partition tables
- Recover from damaged partition metadata with read-only boot-sector scanning
- Browse NTFS metadata and recover resident or non-resident file data
- Scan raw media for MFT records and common file signatures
- Create full-disk or selected-partition images
- Track weak or unreadable regions instead of repeatedly stalling on them
- Use either the Python GUI/CLI or the Windows WinUI host

## Safety Model

- Source devices are opened for reading only.
- Recovered files and images must be written to a different destination.
- Disk images are preferred over repeated work on failing physical media.
- SSD data that has already been discarded by TRIM/UNMAP cannot normally be
  recovered through software reads.

Use a hardware write blocker and an image-first workflow when evidence
preservation matters.

## Installation

Python 3.10 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Usage

Start the Python GUI:

```bash
python -m pyddeu gui
```

List disks or scan a source from the command line:

```bash
python -m pyddeu list-disks
python -m pyddeu scan --source /path/to/image.dd
```

Raw-device examples:

- Linux: `/dev/sdX` with appropriate privileges
- Windows: `\\.\PhysicalDriveN` from an elevated terminal

### Windows WinUI Host

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_winui.ps1 -BuildOnly
powershell -ExecutionPolicy Bypass -File scripts/run_winui.ps1
```

Use `-WhatIf` to inspect the launch process without executing it.

## Repository Layout

```text
.
├── pyddeu/              Python package and recovery engine
├── winui/               Windows WinUI application and tests
├── tests/               Python unit and integration tests
├── scripts/             Launch, diagnostics, and maintenance scripts
│   └── debug/           Low-level partition and MFT diagnostics
├── docs/                Design, implementation, and analysis notes
├── dmde-files/          Reference configuration material
├── pyproject.toml       Package metadata and CLI entry point
└── pyddeu.ini           Runtime configuration
```

## Development

Run the Python test suite:

```bash
python -m pytest tests
```

Useful implementation references:

- [Linux I/O implementation](docs/linux-implementation.md)
- [Linux analysis report](docs/reports/linux-analysis-report.md)
- [WinUI design and bridge plans](docs/plans/)
- [AI-assisted development notes](CLAUDE.md)

## Project Status

PyDDEU is an experimental recovery toolkit, not a replacement for validated
commercial forensic software. Test changes against disposable images before
using them with important media.

## License

No license has been declared for this repository. All rights remain with the
repository owner unless a license is added.
