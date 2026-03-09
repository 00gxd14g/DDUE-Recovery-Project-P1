from __future__ import annotations

import unittest

from pyddeu.mft import MftFileName
from pyddeu.winui_bridge import _make_file_item, _records_to_files, _safe_rel_path


class _FakeRecord:
    def __init__(
        self,
        *,
        inode: int,
        is_deleted: bool,
        file_names: list[MftFileName],
        resident_data: bytes | None = None,
        parent_ref: int | None = None,
        data_runs: list[tuple[int | None, int]] | None = None,
        data_size: int | None = None,
    ) -> None:
        self.inode = inode
        self.is_deleted = is_deleted
        self.file_names = file_names
        self.resident_data = resident_data
        self.parent_ref = parent_ref
        self.data_runs = data_runs
        self.data_size = data_size


class TestWinuiBridgeHelpers(unittest.TestCase):
    def test_make_file_item_uses_path_in_dedupe_key(self) -> None:
        first = _make_file_item(
            path="Users/Alice/Report.docx",
            size=12,
            status="ACTIVE",
            inode=42,
            part_offset=4096,
            is_dir=False,
            source="pytsk3",
            name_source="pytsk3",
        )
        second = _make_file_item(
            path="Users/Alice/Report (copy).docx",
            size=12,
            status="ACTIVE",
            inode=42,
            part_offset=4096,
            is_dir=False,
            source="pytsk3",
            name_source="pytsk3",
        )

        self.assertEqual(first["file_name"], "Report.docx")
        self.assertEqual(second["file_name"], "Report (copy).docx")
        self.assertNotEqual(first["dedupe_key"], second["dedupe_key"])

    def test_records_to_files_prefers_long_name_and_emits_metadata(self) -> None:
        root = _FakeRecord(
            inode=5,
            is_deleted=False,
            file_names=[MftFileName(name="Users", parent_ref=5, namespace=1)],
            parent_ref=5,
            data_size=0,
        )
        child = _FakeRecord(
            inode=42,
            is_deleted=True,
            file_names=[
                MftFileName(name="RAPOR~1.DOC", parent_ref=5, namespace=2),
                MftFileName(name="Rapor Final.docx", parent_ref=5, namespace=1),
            ],
            parent_ref=5,
            data_size=1234,
        )

        files = _records_to_files(
            [root, child],
            part_start=1048576,
            cluster_size=4096,
            include_deleted=True,
            include_active=True,
            max_resident=1024,
            source="deep",
        )

        item = next(row for row in files if row["inode"] == 42)
        self.assertEqual(item["path"], "Users/Rapor Final.docx")
        self.assertEqual(item["display_path"], "Users/Rapor Final.docx")
        self.assertEqual(item["file_name"], "Rapor Final.docx")
        self.assertEqual(item["name_source"], "win32")
        self.assertIn("users/rapor final.docx", item["dedupe_key"])

    def test_safe_rel_path_strips_prefixes_and_invalid_chars(self) -> None:
        rel = _safe_rel_path(r'[DEEP] /Users/Alice/Bad:Name?.txt')
        self.assertEqual(rel, "Users/Alice/Bad_Name_.txt")


if __name__ == "__main__":
    unittest.main()
