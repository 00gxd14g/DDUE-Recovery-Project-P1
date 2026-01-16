"""
Tests for the Linux/POSIX I/O layer.

These tests verify:
- Basic file reading operations
- Sector alignment logic
- Timeout handling
- Device size/sector detection
- Error handling
"""
from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Skip these tests on Windows
import sys
if sys.platform == "win32":
    raise unittest.SkipTest("POSIX tests only run on Linux/Unix")

from pyddeu.io.posix import (
    LinuxDiskSource,
    PosixPreadSource,
    PosixSeekSource,
    ReadTimeoutError,
    _align_read,
    _is_block_device,
    _query_device_size,
    _query_sector_size,
    _read_with_timeout_thread,
    open_posix_source,
)
from pyddeu.config import PyddeuConfig


class TestAlignRead(unittest.TestCase):
    """Tests for sector alignment calculations."""

    def test_already_aligned(self):
        """Test when offset and size are already aligned."""
        aligned_start, aligned_size, data_offset, data_size = _align_read(
            offset=0, size=512, sector_size=512, device_size=10000
        )
        self.assertEqual(aligned_start, 0)
        self.assertEqual(aligned_size, 512)
        self.assertEqual(data_offset, 0)
        self.assertEqual(data_size, 512)

    def test_unaligned_offset(self):
        """Test unaligned offset gets aligned down."""
        aligned_start, aligned_size, data_offset, data_size = _align_read(
            offset=100, size=100, sector_size=512, device_size=10000
        )
        self.assertEqual(aligned_start, 0)  # Aligned down
        self.assertEqual(data_offset, 100)   # Offset within aligned buffer
        self.assertEqual(data_size, 100)

    def test_unaligned_size(self):
        """Test unaligned size gets aligned up."""
        aligned_start, aligned_size, data_offset, data_size = _align_read(
            offset=0, size=100, sector_size=512, device_size=10000
        )
        self.assertEqual(aligned_start, 0)
        self.assertEqual(aligned_size, 512)  # Aligned up to sector boundary
        self.assertEqual(data_offset, 0)
        self.assertEqual(data_size, 100)

    def test_crossing_sector_boundary(self):
        """Test read that crosses sector boundary."""
        aligned_start, aligned_size, data_offset, data_size = _align_read(
            offset=500, size=100, sector_size=512, device_size=10000
        )
        self.assertEqual(aligned_start, 0)      # Start of first sector
        self.assertEqual(aligned_size, 1024)    # Two sectors needed
        self.assertEqual(data_offset, 500)      # Offset within buffer
        self.assertEqual(data_size, 100)

    def test_offset_beyond_device(self):
        """Test offset beyond device size."""
        aligned_start, aligned_size, data_offset, data_size = _align_read(
            offset=20000, size=512, sector_size=512, device_size=10000
        )
        self.assertEqual(aligned_size, 0)  # No data to read

    def test_read_exceeds_device(self):
        """Test read that exceeds device size."""
        aligned_start, aligned_size, data_offset, data_size = _align_read(
            offset=9000, size=2000, sector_size=512, device_size=10000
        )
        # Should clamp to device boundary
        self.assertLess(data_size, 2000)

    def test_4k_sector_alignment(self):
        """Test alignment with 4K sectors."""
        aligned_start, aligned_size, data_offset, data_size = _align_read(
            offset=5000, size=1000, sector_size=4096, device_size=100000
        )
        self.assertEqual(aligned_start, 4096)  # First 4K boundary <= 5000
        self.assertEqual(data_offset, 5000 - 4096)


class TestIsBlockDevice(unittest.TestCase):
    """Tests for block device detection."""

    def test_regular_file(self):
        """Regular file should not be detected as block device."""
        with tempfile.NamedTemporaryFile() as f:
            self.assertFalse(_is_block_device(f.name))

    def test_nonexistent_path(self):
        """Nonexistent path should return False."""
        self.assertFalse(_is_block_device("/nonexistent/path/12345"))

    def test_directory(self):
        """Directory should not be detected as block device."""
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(_is_block_device(d))


class TestReadWithTimeoutThread(unittest.TestCase):
    """Tests for timeout-protected reads."""

    def test_successful_read(self):
        """Test successful read within timeout."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_data = b"Hello, World!" * 100
            f.write(test_data)
            f.flush()
            fname = f.name

        try:
            fd = os.open(fname, os.O_RDONLY)
            try:
                data = _read_with_timeout_thread(fd, 0, 100, 5000)
                self.assertEqual(data, test_data[:100])
            finally:
                os.close(fd)
        finally:
            os.unlink(fname)

    def test_partial_read(self):
        """Test reading less than file size."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_data = b"X" * 1000
            f.write(test_data)
            f.flush()
            fname = f.name

        try:
            fd = os.open(fname, os.O_RDONLY)
            try:
                data = _read_with_timeout_thread(fd, 500, 100, 5000)
                self.assertEqual(data, test_data[500:600])
            finally:
                os.close(fd)
        finally:
            os.unlink(fname)


class TestPosixPreadSource(unittest.TestCase):
    """Tests for simple pread-based source."""

    def setUp(self):
        """Create a test file."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_data = b"0123456789ABCDEF" * 1000
        self.temp_file.write(self.test_data)
        self.temp_file.flush()
        self.temp_file.close()

    def tearDown(self):
        """Clean up test file."""
        try:
            os.unlink(self.temp_file.name)
        except Exception:
            pass

    def test_basic_read(self):
        """Test basic read operation."""
        fd = os.open(self.temp_file.name, os.O_RDONLY)
        src = PosixPreadSource(
            path=self.temp_file.name,
            _fd=fd,
            _size=len(self.test_data),
            _sector_size=512,
        )
        try:
            data = src.read_at(0, 16)
            self.assertEqual(data, b"0123456789ABCDEF")
        finally:
            src.close()

    def test_offset_read(self):
        """Test read with offset."""
        fd = os.open(self.temp_file.name, os.O_RDONLY)
        src = PosixPreadSource(
            path=self.temp_file.name,
            _fd=fd,
            _size=len(self.test_data),
            _sector_size=512,
        )
        try:
            data = src.read_at(10, 6)
            self.assertEqual(data, b"ABCDEF")
        finally:
            src.close()

    def test_size_property(self):
        """Test size property."""
        fd = os.open(self.temp_file.name, os.O_RDONLY)
        src = PosixPreadSource(
            path=self.temp_file.name,
            _fd=fd,
            _size=len(self.test_data),
            _sector_size=512,
        )
        try:
            self.assertEqual(src.size(), len(self.test_data))
        finally:
            src.close()


class TestLinuxDiskSource(unittest.TestCase):
    """Tests for full-featured Linux disk source."""

    def setUp(self):
        """Create a test file."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_data = b"0123456789ABCDEF" * 1000
        self.temp_file.write(self.test_data)
        self.temp_file.flush()
        self.temp_file.close()

    def tearDown(self):
        """Clean up test file."""
        try:
            os.unlink(self.temp_file.name)
        except Exception:
            pass

    def test_basic_read(self):
        """Test basic read operation."""
        fd = os.open(self.temp_file.name, os.O_RDONLY)
        src = LinuxDiskSource(
            path=self.temp_file.name,
            _fd=fd,
            _size=len(self.test_data),
            _sector_size=512,
            _timeout_ms=5000,
            _use_direct=False,
            _is_block_device=False,
        )
        try:
            data = src.read_at(0, 16)
            self.assertEqual(data, b"0123456789ABCDEF")
        finally:
            src.close()

    def test_read_with_timeout(self):
        """Test read with timeout enabled."""
        fd = os.open(self.temp_file.name, os.O_RDONLY)
        src = LinuxDiskSource(
            path=self.temp_file.name,
            _fd=fd,
            _size=len(self.test_data),
            _sector_size=512,
            _timeout_ms=5000,
            _use_direct=False,
            _is_block_device=False,
        )
        try:
            data = src.read_at(100, 50)
            self.assertEqual(len(data), 50)
        finally:
            src.close()

    def test_refresh_with_timeout(self):
        """Test device refresh operation."""
        fd = os.open(self.temp_file.name, os.O_RDONLY)
        src = LinuxDiskSource(
            path=self.temp_file.name,
            _fd=fd,
            _size=len(self.test_data),
            _sector_size=512,
            _timeout_ms=5000,
            _use_direct=False,
            _is_block_device=False,
        )
        try:
            # Refresh should succeed
            result = src.refresh_with_timeout(timeout_s=2.0)
            self.assertTrue(result)
            # Source should still be readable
            data = src.read_at(0, 16)
            self.assertEqual(data, b"0123456789ABCDEF")
        finally:
            src.close()


class TestOpenPosixSource(unittest.TestCase):
    """Tests for open_posix_source factory function."""

    def setUp(self):
        """Create a test file."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_data = b"TestData" * 500
        self.temp_file.write(self.test_data)
        self.temp_file.flush()
        self.temp_file.close()

    def tearDown(self):
        """Clean up test file."""
        try:
            os.unlink(self.temp_file.name)
        except Exception:
            pass

    def test_open_regular_file(self):
        """Test opening a regular file."""
        src = open_posix_source(self.temp_file.name)
        try:
            self.assertGreater(src.size(), 0)
            data = src.read_at(0, 8)
            self.assertEqual(data, b"TestData")
        finally:
            src.close()

    def test_open_with_config(self):
        """Test opening with custom config."""
        config = PyddeuConfig(deviowait_ms=10000)
        src = open_posix_source(self.temp_file.name, config=config)
        try:
            data = src.read_at(0, 8)
            self.assertEqual(data, b"TestData")
        finally:
            src.close()

    def test_open_with_zero_timeout(self):
        """Test opening with timeout disabled."""
        config = PyddeuConfig(deviowait_ms=0)
        src = open_posix_source(self.temp_file.name, config=config)
        try:
            # With timeout disabled, should still work
            data = src.read_at(0, 8)
            self.assertEqual(data, b"TestData")
        finally:
            src.close()


class TestQueryDeviceSize(unittest.TestCase):
    """Tests for device size query."""

    def test_regular_file_size(self):
        """Test size query for regular file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_data = b"X" * 12345
            f.write(test_data)
            f.flush()
            fname = f.name

        try:
            fd = os.open(fname, os.O_RDONLY)
            try:
                size = _query_device_size(fd, fname)
                self.assertEqual(size, 12345)
            finally:
                os.close(fd)
        finally:
            os.unlink(fname)


class TestQuerySectorSize(unittest.TestCase):
    """Tests for sector size query."""

    def test_regular_file_sector_size(self):
        """Test sector size query for regular file (should return default)."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"X" * 1000)
            f.flush()
            fname = f.name

        try:
            fd = os.open(fname, os.O_RDONLY)
            try:
                sector_size = _query_sector_size(fd)
                # Regular files don't have sector size, should return default
                self.assertEqual(sector_size, 512)
            finally:
                os.close(fd)
        finally:
            os.unlink(fname)


if __name__ == "__main__":
    unittest.main()
