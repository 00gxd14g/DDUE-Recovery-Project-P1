"""
Tests for partition scanning helpers.

These tests focus on DMDE-style behaviors used on Linux:
- Treating 512-byte LBA addressing as canonical.
- Normalizing NTFS *backup boot* hits (end-of-volume) back to the real start.
"""

from __future__ import annotations

import struct
import unittest

from pyddeu.partitions import DEFAULT_SECTOR_SIZE, scan_partitions


def _make_ntfs_boot_sector(
    *,
    bytes_per_sector: int = 512,
    sectors_per_cluster: int = 8,
    total_sectors: int,
    mft_lcn: int = 4,
    mftmirr_lcn: int = 8,
    file_record_exp: int = -10,  # 2^10 = 1024 bytes
) -> bytes:
    buf = bytearray(b"\x00" * 512)
    buf[3:11] = b"NTFS    "
    struct.pack_into("<H", buf, 11, int(bytes_per_sector))
    buf[13] = int(sectors_per_cluster) & 0xFF
    struct.pack_into("<Q", buf, 40, int(total_sectors))
    struct.pack_into("<Q", buf, 48, int(mft_lcn))
    struct.pack_into("<Q", buf, 56, int(mftmirr_lcn))
    struct.pack_into("<b", buf, 64, int(file_record_exp))
    buf[510:512] = b"\x55\xAA"
    return bytes(buf)


class _FakeDiskSource:
    """Minimal DiskSource-like object for scan_partitions()."""

    def __init__(self, *, size: int, sector_size: int = 512, data: dict[int, bytes] | None = None):
        self._size = int(size)
        self._sector_size = int(sector_size)
        self._data = dict(data or {})

    def size(self) -> int:
        return self._size

    def sector_size(self) -> int:
        return self._sector_size

    def read_at(self, offset: int, size: int) -> bytes:
        off = int(offset)
        sz = int(size)
        buf = self._data.get(off)
        if buf is None:
            return b"\x00" * sz
        if len(buf) >= sz:
            return buf[:sz]
        return buf + (b"\x00" * (sz - len(buf)))

    def close(self) -> None:
        return


class TestPartitionScanNormalization(unittest.TestCase):
    def test_scan_normalizes_backup_ntfs_boot_to_start(self) -> None:
        # Put an NTFS boot sector only at an LBA that would represent the backup boot
        # of a volume starting at LBA 2048. 409640 is one of the DMDE-style probe LBAs.
        start_lba = 2048
        backup_lba = 409640
        total_sectors = backup_lba - start_lba + 1

        boot = _make_ntfs_boot_sector(total_sectors=total_sectors)
        src = _FakeDiskSource(
            size=(backup_lba + 1) * DEFAULT_SECTOR_SIZE + 1024,
            sector_size=512,
            data={
                backup_lba * DEFAULT_SECTOR_SIZE: boot,
            },
        )

        parts = scan_partitions(src)
        starts = {int(p.start_offset) for p in parts}

        self.assertIn(start_lba * DEFAULT_SECTOR_SIZE, starts)
        self.assertNotIn(backup_lba * DEFAULT_SECTOR_SIZE, starts)

        # Ensure cached boot info is preserved for deep scans.
        p = next(pp for pp in parts if int(pp.start_offset) == start_lba * DEFAULT_SECTOR_SIZE)
        self.assertIsNotNone(p.ntfs_boot)

