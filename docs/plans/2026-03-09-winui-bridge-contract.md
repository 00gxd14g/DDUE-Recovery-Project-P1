# PyDDEU WinUI Bridge Contract

**Date:** 2026-03-09

## Purpose

This note records the command and event contract currently implemented by `pyddeu.winui_bridge` so the repo, tests, and Linear backlog use the same language.

## Event Types

- `health`
  - Emitted by `python -m pyddeu.winui_bridge --health`
  - Shape: `{ "type": "health", "ok": true, "details": { ... } }`
- `result`
  - Final success payload for a command
- `error`
  - Final failure payload
  - Shape includes `type`, `code`, `message`, and optional `details`
- `log`
  - Human-readable progress or diagnostic line
- `progress`
  - Numeric progress updates
  - Shape: `{ "type": "progress", "operation": "<name>", "current": <int>, "total": <int> }`
- `status`
  - Short non-terminal status updates

## Command Surface

- `list_disks`
- `scan_partitions`
- `deep_scan`
- `mft_scan`
- `file_carve`
- `create_image`
- `recover_items`
- `parse_fs`
- `stop`

## Naming Alignment vs Original Plan

The original implementation plan used some provisional names. The current implementation uses:

- Planned `deep_ntfs_scan` -> implemented `deep_scan`
- Planned `recover_selected` / `recover_folder` -> implemented `recover_items`
- Planned filesystem browse action -> implemented `parse_fs`

The WinUI host already calls the implemented names, so these should be treated as the source of truth unless a later migration explicitly renames them.

## Verification References

- Python protocol tests: `tests/test_winui_bridge_protocol.py`
- Python operation tests: `tests/test_winui_bridge_operations.py`
- C# bridge client tests: `winui/PyDDEU.WinUI.Tests/PythonBridgeClientTests.cs`

## Acceptance Standard

Bridge-related work is only considered complete when:

1. Command payloads and event shapes are covered by automated tests.
2. Error payloads preserve a machine-readable `code`.
3. WinUI client-side process invocation and event parsing are verified.
4. Verification evidence is written back to Linear.
