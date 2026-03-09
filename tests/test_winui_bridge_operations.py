from __future__ import annotations

import base64
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pyddeu import winui_bridge as bridge


class _FakeSource:
    def __init__(self, size: int = 16384) -> None:
        self._size = size
        self.closed = False

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        self.closed = True


class TestWinuiBridgeOperations(unittest.TestCase):
    def setUp(self) -> None:
        self.events: list[dict[str, object]] = []
        self.emit_patch = patch.object(bridge, "_emit", side_effect=lambda payload: self.events.append(payload))
        self.config_patch = patch.object(bridge, "_load_config", return_value=object())
        self.emit_patch.start()
        self.config_patch.start()
        self.addCleanup(self.emit_patch.stop)
        self.addCleanup(self.config_patch.stop)

    def test_stop_returns_ok_result(self) -> None:
        exit_code = bridge._command_stop({})

        self.assertEqual(exit_code, 0)
        self.assertEqual(self.events, [{"type": "result", "command": "stop", "status": "ok"}])

    def test_scan_partitions_returns_result_shape(self) -> None:
        source = _FakeSource()
        parts = [SimpleNamespace(index=1, start_offset=2048, length=8192, scheme="GPT", type_str="Basic", name="Data")]

        with patch.object(bridge, "open_source", return_value=source), patch.object(
            bridge, "scan_partitions", return_value=parts
        ):
            exit_code = bridge._command_scan_partitions({"source_path": "disk.img"})

        self.assertEqual(exit_code, 0)
        self.assertTrue(source.closed)
        self.assertEqual(self.events[-1]["type"], "result")
        self.assertEqual(self.events[-1]["command"], "scan_partitions")
        self.assertEqual(
            self.events[-1]["partitions"],
            [{"index": 1, "start_offset": 2048, "length": 8192, "scheme": "GPT", "type_str": "Basic", "name": "Data"}],
        )

    def test_list_disks_returns_result_shape(self) -> None:
        fake_disks = [
            SimpleNamespace(path="disk0.img", size=1024, description="Disk 0"),
            SimpleNamespace(path="disk1.img", size=2048, description="Disk 1"),
        ]

        with patch.object(bridge, "list_sources", return_value=fake_disks):
            exit_code = bridge._command_list_disks({})

        self.assertEqual(exit_code, 0)
        self.assertEqual(self.events[-1]["type"], "result")
        self.assertEqual(self.events[-1]["command"], "list_disks")
        self.assertEqual(
            self.events[-1]["disks"],
            [
                {"path": "disk0.img", "size": 1024, "description": "Disk 0"},
                {"path": "disk1.img", "size": 2048, "description": "Disk 1"},
            ],
        )

    def test_file_carve_emits_progress_and_result(self) -> None:
        source = _FakeSource()
        temp_dir = Path(self.id().replace(".", "_"))
        temp_dir.mkdir(exist_ok=True)
        self.addCleanup(lambda: temp_dir.exists() and temp_dir.rmdir())

        def fake_carve(src, state, out_dir, log_cb=None, progress_cb=None):
            self.assertEqual(out_dir, temp_dir)
            assert progress_cb is not None
            progress_cb(4, 10)
            return 3

        with patch.object(bridge, "open_source", return_value=source), patch.object(
            bridge, "carve_signatures", side_effect=fake_carve
        ):
            exit_code = bridge._command_file_carve({"source_path": "disk.img", "out_dir": str(temp_dir)})

        self.assertEqual(exit_code, 0)
        self.assertTrue(source.closed)
        self.assertTrue(any(evt["type"] == "progress" and evt["operation"] == "file_carve" for evt in self.events))
        self.assertEqual(self.events[-1]["type"], "result")
        self.assertEqual(self.events[-1]["command"], "file_carve")
        self.assertEqual(self.events[-1]["found"], 3)

    def test_create_image_emits_progress_and_result(self) -> None:
        source = _FakeSource()
        output_path = Path("temp-image.img")
        captured: dict[str, object] = {}

        def fake_create_image(src, state, out_path, *, start=0, end=None, log_cb=None, progress_cb=None):
            captured["out_path"] = out_path
            captured["start"] = start
            captured["end"] = end
            assert progress_cb is not None
            progress_cb(8, 16)

        with patch.object(bridge, "open_source", return_value=source), patch.object(
            bridge, "create_image", side_effect=fake_create_image
        ):
            exit_code = bridge._command_create_image(
                {"source_path": "disk.img", "out_path": str(output_path), "start": 512, "end": 2048}
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(source.closed)
        self.assertEqual(captured, {"out_path": output_path, "start": 512, "end": 2048})
        self.assertTrue(any(evt["type"] == "progress" and evt["operation"] == "create_image" for evt in self.events))
        self.assertEqual(self.events[-1]["type"], "result")
        self.assertEqual(self.events[-1]["command"], "create_image")
        self.assertEqual(self.events[-1]["out_path"], str(output_path))

    def test_recover_items_writes_resident_data(self) -> None:
        source = _FakeSource()
        tmp_path = Path("resident-output")
        self.addCleanup(lambda: tmp_path.exists() and __import__("shutil").rmtree(tmp_path, ignore_errors=True))
        payload = {
            "source_path": "disk.img",
            "output_root": str(tmp_path),
            "items": [
                {
                    "path": "Users/Alice/notes.txt",
                    "size": 5,
                    "resident_data_b64": base64.b64encode(b"hello").decode("ascii"),
                    "inode": 42,
                    "is_dir": False,
                }
            ],
        }

        with patch.object(bridge, "open_source", return_value=source):
            exit_code = bridge._command_recover_items(payload)

        self.assertEqual(exit_code, 0)
        self.assertTrue(source.closed)
        self.assertEqual((tmp_path / "Users" / "Alice" / "notes.txt").read_bytes(), b"hello")
        self.assertEqual(self.events[-1]["type"], "result")
        self.assertEqual(self.events[-1]["command"], "recover_items")
        self.assertEqual(self.events[-1]["ok"], 1)
        self.assertEqual(self.events[-1]["errors"], 0)

    def test_recover_items_skips_directories(self) -> None:
        source = _FakeSource()
        tmp_path = Path("directory-output")
        self.addCleanup(lambda: tmp_path.exists() and __import__("shutil").rmtree(tmp_path, ignore_errors=True))

        with patch.object(bridge, "open_source", return_value=source):
            exit_code = bridge._command_recover_items(
                {
                    "source_path": "disk.img",
                    "output_root": str(tmp_path),
                    "items": [{"path": "Users/Alice", "is_dir": True, "inode": 7}],
                }
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(source.closed)
        self.assertTrue((tmp_path / "Users" / "Alice").exists())
        self.assertEqual(self.events[-1]["command"], "recover_items")
        self.assertEqual(self.events[-1]["ok"], 0)
        self.assertEqual(self.events[-1]["skipped"], 1)

    def test_deep_scan_falls_back_to_bruteforce_and_returns_files(self) -> None:
        source = _FakeSource(size=32768)
        boot = SimpleNamespace(cluster_size=4096, file_record_size=1024, volume_size_bytes=16384, mft_lcn=0)
        records = [object(), object()]

        with patch.object(bridge, "open_source", return_value=source), patch.object(
            bridge,
            "safe_read_granular",
            side_effect=lambda src, state, offset, length, log_cb=None: (b"BOOT" if length == 512 else b"\x00" * length),
        ), patch.object(bridge, "parse_ntfs_boot_sector", return_value=boot), patch.object(
            bridge, "scan_and_parse_mft", return_value=iter(records)
        ), patch.object(
            bridge,
            "_records_to_files",
            side_effect=lambda record_items, *args, **kwargs: [
                {"path": f"file-{index}.txt"} for index, _ in enumerate(record_items, start=1)
            ],
        ):
            exit_code = bridge._command_deep_scan(
                {"source_path": "disk.img", "partition_start": 4096, "partition_length": 8192}
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(source.closed)
        self.assertTrue(any(evt["type"] == "log" and "brute-force" in str(evt["message"]) for evt in self.events))
        self.assertEqual(self.events[-1]["type"], "result")
        self.assertEqual(self.events[-1]["command"], "deep_scan")
        self.assertEqual(self.events[-1]["count"], 2)
        self.assertEqual(self.events[-1]["raw_record_count"], 2)

    def test_deep_scan_returns_not_ntfs_error_when_boot_invalid(self) -> None:
        source = _FakeSource(size=32768)

        with patch.object(bridge, "open_source", return_value=source), patch.object(
            bridge, "safe_read_granular", return_value=b"BOOT"
        ), patch.object(bridge, "parse_ntfs_boot_sector", return_value=None):
            exit_code = bridge._command_deep_scan({"source_path": "disk.img", "partition_start": 4096})

        self.assertEqual(exit_code, 1)
        self.assertTrue(source.closed)
        self.assertEqual(self.events[-1]["type"], "error")
        self.assertEqual(self.events[-1]["code"], "not_ntfs")

    def test_mft_scan_returns_files(self) -> None:
        source = _FakeSource(size=32768)
        records = [object()]

        with patch.object(bridge, "open_source", return_value=source), patch.object(
            bridge, "scan_and_parse_mft", return_value=iter(records)
        ), patch.object(
            bridge,
            "_records_to_files",
            side_effect=lambda record_items, *args, **kwargs: [{"path": "mft-file.txt"} for _ in record_items],
        ):
            exit_code = bridge._command_mft_scan({"source_path": "disk.img"})

        self.assertEqual(exit_code, 0)
        self.assertTrue(source.closed)
        self.assertEqual(self.events[-1]["type"], "result")
        self.assertEqual(self.events[-1]["command"], "mft_scan")
        self.assertEqual(self.events[-1]["count"], 1)
        self.assertEqual(self.events[-1]["raw_record_count"], 1)


if __name__ == "__main__":
    unittest.main()
