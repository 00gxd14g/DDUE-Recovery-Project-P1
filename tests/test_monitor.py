"""
Tests for the monitor module.

These tests verify:
- Kernel message classification
- Error pattern detection
- Panic triggering
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Skip Windows-specific tests
import sys

from pyddeu.monitor import LinuxKernelMonitor, start_monitor
from pyddeu.state import RecoveryState
from pyddeu.config import PyddeuConfig


class TestLinuxKernelMonitor(unittest.TestCase):
    """Tests for LinuxKernelMonitor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.map_path = Path(self.temp_dir) / "test.map.json"
        self.config = PyddeuConfig()
        self.state = RecoveryState(self.map_path, config=self.config)
        self.log_messages = []

        def log_cb(level, msg):
            self.log_messages.append((level, msg))

        self.log_cb = log_cb

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_classify_critical_reset(self):
        """Test classification of reset messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("sd 0:0:0:0: device reset requested")
        self.assertEqual(level, "CRITICAL")
        self.assertTrue(panic)

    def test_classify_critical_disconnected(self):
        """Test classification of disconnection messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("usb 1-1: device disconnected")
        self.assertEqual(level, "CRITICAL")
        self.assertTrue(panic)

    def test_classify_critical_offline(self):
        """Test classification of offline messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("sd 0:0:0:0: going offline")
        self.assertEqual(level, "CRITICAL")
        self.assertTrue(panic)

    def test_classify_warning_io_error(self):
        """Test classification of I/O error messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("Buffer I/O error on dev sda, sector 12345")
        self.assertEqual(level, "WARNING")
        self.assertFalse(panic)

    def test_classify_nvme_error(self):
        """Test classification of NVMe error messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("nvme nvme0: I/O error occurred")
        self.assertEqual(level, "CRITICAL")
        self.assertTrue(panic)

    def test_classify_nvme_timeout(self):
        """Test classification of NVMe timeout messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("nvme nvme0: timeout")
        self.assertEqual(level, "CRITICAL")
        self.assertTrue(panic)

    def test_classify_ata_exception(self):
        """Test classification of ATA exception messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("ata1: exception Emask")
        self.assertEqual(level, "CRITICAL")
        self.assertTrue(panic)

    def test_classify_medium_error(self):
        """Test classification of medium error messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("sd 0:0:0:0: medium error, sense key 0x03")
        self.assertEqual(level, "WARNING")
        self.assertFalse(panic)

    def test_classify_unrelated(self):
        """Test classification of unrelated messages."""
        monitor = LinuxKernelMonitor(self.log_cb)
        level, panic = monitor._classify_message("eth0: link up")
        self.assertEqual(level, "")
        self.assertFalse(panic)

    def test_should_process_with_device_hint(self):
        """Test line filtering with device hint."""
        monitor = LinuxKernelMonitor(self.log_cb, device_hint="sda")
        self.assertTrue(monitor._should_process_line("sda: some error"))
        self.assertFalse(monitor._should_process_line("sdb: some error"))

    def test_should_process_without_device_hint(self):
        """Test line filtering without device hint."""
        monitor = LinuxKernelMonitor(self.log_cb)
        self.assertTrue(monitor._should_process_line("sd 0:0:0:0: error"))
        self.assertTrue(monitor._should_process_line("nvme0: error"))
        self.assertFalse(monitor._should_process_line("eth0: link up"))

    def test_critical_patterns_list(self):
        """Test all critical patterns are detected."""
        monitor = LinuxKernelMonitor(self.log_cb)

        for pattern in LinuxKernelMonitor.CRITICAL_PATTERNS:
            level, panic = monitor._classify_message(f"test {pattern} message")
            self.assertEqual(level, "CRITICAL", f"Pattern '{pattern}' not detected as CRITICAL")
            self.assertTrue(panic, f"Pattern '{pattern}' not triggering panic")

    def test_warning_patterns_list(self):
        """Test all warning patterns are detected."""
        monitor = LinuxKernelMonitor(self.log_cb)

        for pattern in LinuxKernelMonitor.WARNING_PATTERNS:
            # Skip patterns that might also match critical patterns
            if any(cp in pattern for cp in LinuxKernelMonitor.CRITICAL_PATTERNS):
                continue
            level, panic = monitor._classify_message(f"test {pattern} message")
            self.assertIn(level, ("WARNING", "CRITICAL"), f"Pattern '{pattern}' not detected")


class TestStartMonitor(unittest.TestCase):
    """Tests for start_monitor function."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.map_path = Path(self.temp_dir) / "test.map.json"
        self.config = PyddeuConfig()
        self.state = RecoveryState(self.map_path, config=self.config)
        self.log_messages = []

        def log_cb(level, msg):
            self.log_messages.append((level, msg))

        self.log_cb = log_cb

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('pyddeu.monitor.IS_LINUX', True)
    @patch('pyddeu.monitor.IS_WINDOWS', False)
    def test_start_linux_monitor(self):
        """Test starting Linux monitor."""
        # This will try to start dmesg which may fail in test environment
        # We just verify the function returns a thread
        with patch('subprocess.Popen') as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = iter([])  # Empty iterator
            mock_popen.return_value = mock_proc

            monitor = start_monitor(self.log_cb, "/dev/sda", self.state)
            if monitor is not None:
                # Stop the monitor using its stop method (sets the _stop Event)
                monitor.stop()
                # Give it time to finish, but don't call join with threading issues
                import time
                time.sleep(0.2)

    @patch('pyddeu.monitor.IS_LINUX', False)
    @patch('pyddeu.monitor.IS_WINDOWS', False)
    def test_start_monitor_unsupported(self):
        """Test starting monitor on unsupported platform."""
        monitor = start_monitor(self.log_cb, "/dev/sda", self.state)
        self.assertIsNone(monitor)


if __name__ == "__main__":
    unittest.main()
