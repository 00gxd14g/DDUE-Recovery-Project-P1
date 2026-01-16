"""
Tests for the scan module.

These tests verify:
- Safe read operations
- Bad sector handling
- Error code classification
- Granular fallback reads
"""
from __future__ import annotations

import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from pyddeu.scan import (
    LINUX_PANIC_CODES,
    WINDOWS_PANIC_CODES,
    ScanProgress,
    _is_panic_error,
    iter_offsets,
    safe_read,
    safe_read_granular,
)
from pyddeu.state import BadRegionMap, RecoveryState
from pyddeu.config import PyddeuConfig


class TestIterOffsets(unittest.TestCase):
    """Tests for offset iteration."""

    def test_basic_iteration(self):
        """Test basic offset iteration."""
        offsets = list(iter_offsets(1000, 100))
        self.assertEqual(offsets, [0, 100, 200, 300, 400, 500, 600, 700, 800, 900])

    def test_exact_multiple(self):
        """Test when total is exact multiple of step."""
        offsets = list(iter_offsets(300, 100))
        self.assertEqual(offsets, [0, 100, 200])

    def test_partial_final_step(self):
        """Test when final step is partial."""
        offsets = list(iter_offsets(250, 100))
        self.assertEqual(offsets, [0, 100, 200])

    def test_zero_total(self):
        """Test with zero total size."""
        offsets = list(iter_offsets(0, 100))
        self.assertEqual(offsets, [])

    def test_step_larger_than_total(self):
        """Test when step is larger than total."""
        offsets = list(iter_offsets(50, 100))
        self.assertEqual(offsets, [0])


class TestIsPanicError(unittest.TestCase):
    """Tests for error code classification."""

    @patch('pyddeu.scan.IS_WINDOWS', False)
    def test_linux_eio(self):
        """Test Linux EIO detection."""
        err = OSError(errno.EIO, "I/O error")
        self.assertTrue(_is_panic_error(err))

    @patch('pyddeu.scan.IS_WINDOWS', False)
    def test_linux_enxio(self):
        """Test Linux ENXIO detection."""
        err = OSError(errno.ENXIO, "No such device or address")
        self.assertTrue(_is_panic_error(err))

    @patch('pyddeu.scan.IS_WINDOWS', False)
    def test_linux_etimedout(self):
        """Test Linux ETIMEDOUT detection."""
        err = OSError(errno.ETIMEDOUT, "Connection timed out")
        # On weak media, timeouts are treated as recoverable (skip), not a controller panic.
        self.assertFalse(_is_panic_error(err))

    @patch('pyddeu.scan.IS_WINDOWS', False)
    def test_linux_non_panic(self):
        """Test Linux non-panic error."""
        err = OSError(errno.ENOENT, "File not found")
        self.assertFalse(_is_panic_error(err))

    @patch('pyddeu.scan.IS_WINDOWS', True)
    def test_windows_panic_codes(self):
        """Test Windows panic code detection."""
        for code in WINDOWS_PANIC_CODES:
            err = OSError(code, f"Windows error {code}")
            err.winerror = code
            self.assertTrue(_is_panic_error(err), f"Failed for code {code}")

    @patch('pyddeu.scan.IS_WINDOWS', True)
    def test_windows_non_panic(self):
        """Test Windows non-panic error."""
        err = OSError(2, "File not found")
        err.winerror = 2
        self.assertFalse(_is_panic_error(err))


class TestSafeRead(unittest.TestCase):
    """Tests for safe_read function."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.map_path = Path(self.temp_dir) / "test.map.json"
        self.config = PyddeuConfig()
        self.state = RecoveryState(self.map_path, config=self.config)

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_successful_read(self):
        """Test successful read operation."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000
        mock_src.read_at.return_value = b"Hello World"
        mock_src.sector_size.return_value = 512

        data = safe_read(mock_src, self.state, 0, 11)
        self.assertEqual(data, b"Hello World")

    def test_read_pads_short_data(self):
        """Test that short reads are padded with zeros."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000
        mock_src.read_at.return_value = b"Short"
        mock_src.sector_size.return_value = 512

        data = safe_read(mock_src, self.state, 0, 10)
        self.assertEqual(data, b"Short\x00\x00\x00\x00\x00")

    def test_read_beyond_size(self):
        """Test read beyond disk size returns zeros."""
        mock_src = MagicMock()
        mock_src.size.return_value = 1000

        data = safe_read(mock_src, self.state, 2000, 100)
        self.assertEqual(data, b"\x00" * 100)
        mock_src.read_at.assert_not_called()

    def test_read_in_bad_region(self):
        """Test read in bad region returns zeros."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000

        # Mark region as bad
        self.state.bad_map.add(0, 1000)

        data = safe_read(mock_src, self.state, 0, 100)
        self.assertEqual(data, b"\x00" * 100)
        mock_src.read_at.assert_not_called()

    def test_read_error_registers_bad(self):
        """Test that I/O errors register bad sectors."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000
        mock_src.read_at.side_effect = OSError(errno.EIO, "I/O error")

        data = safe_read(mock_src, self.state, 0, 100)
        self.assertEqual(data, b"\x00" * 100)
        self.assertTrue(self.state.bad_map.contains(0, 100))

    def test_stop_requested_returns_zeros(self):
        """Test that stop request returns zeros."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000

        self.state.stop_requested = True

        data = safe_read(mock_src, self.state, 0, 100)
        self.assertEqual(data, b"\x00" * 100)
        mock_src.read_at.assert_not_called()


class TestSafeReadGranular(unittest.TestCase):
    """Tests for safe_read_granular function."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.map_path = Path(self.temp_dir) / "test.map.json"
        self.config = PyddeuConfig()
        self.state = RecoveryState(self.map_path, config=self.config)

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_successful_read(self):
        """Test successful read operation."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000
        mock_src.read_at.return_value = b"Hello World"
        mock_src.sector_size.return_value = 512

        data = safe_read_granular(mock_src, self.state, 0, 11)
        self.assertEqual(data, b"Hello World")

    def test_fallback_to_sector_by_sector(self):
        """Test fallback to sector-by-sector on error."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000
        mock_src.sector_size.return_value = 512

        # First call fails, subsequent calls succeed
        call_count = [0]

        def read_side_effect(offset, size):
            call_count[0] += 1
            if call_count[0] == 1 and size > 512:
                raise OSError(errno.EIO, "I/O error")
            return b"X" * size

        mock_src.read_at.side_effect = read_side_effect

        data = safe_read_granular(mock_src, self.state, 0, 1024, sector_size=512)
        # Should have fallen back to sector-by-sector
        self.assertEqual(len(data), 1024)

    def test_preserves_size(self):
        """Test that output size matches requested size."""
        mock_src = MagicMock()
        mock_src.size.return_value = 10000
        mock_src.read_at.return_value = b"X" * 100
        mock_src.sector_size.return_value = 512

        data = safe_read_granular(mock_src, self.state, 0, 100)
        self.assertEqual(len(data), 100)


class TestScanProgress(unittest.TestCase):
    """Tests for ScanProgress dataclass."""

    def test_creation(self):
        """Test ScanProgress creation."""
        progress = ScanProgress(offset=1000, total=10000)
        self.assertEqual(progress.offset, 1000)
        self.assertEqual(progress.total, 10000)

    def test_immutable(self):
        """Test that ScanProgress is frozen."""
        progress = ScanProgress(offset=1000, total=10000)
        with self.assertRaises(AttributeError):
            progress.offset = 2000


if __name__ == "__main__":
    unittest.main()
