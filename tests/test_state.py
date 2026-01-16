"""
Tests for the state module.

These tests verify:
- BadRegionMap operations
- RecoveryState management
- Adaptive skip behavior
- Controller panic handling
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pyddeu.state import (
    BadRegionMap,
    RecoveryState,
    Region,
    map_path_for_source,
)
from pyddeu.config import PyddeuConfig


class TestRegion(unittest.TestCase):
    """Tests for Region dataclass."""

    def test_creation(self):
        """Test Region creation."""
        r = Region(start=0, end=100)
        self.assertEqual(r.start, 0)
        self.assertEqual(r.end, 100)

    def test_overlaps_true(self):
        """Test overlapping regions."""
        r1 = Region(0, 100)
        r2 = Region(50, 150)
        self.assertTrue(r1.overlaps(r2))
        self.assertTrue(r2.overlaps(r1))

    def test_overlaps_false(self):
        """Test non-overlapping regions."""
        r1 = Region(0, 100)
        r2 = Region(100, 200)
        self.assertFalse(r1.overlaps(r2))
        self.assertFalse(r2.overlaps(r1))

    def test_overlaps_contained(self):
        """Test contained regions overlap."""
        r1 = Region(0, 100)
        r2 = Region(25, 75)
        self.assertTrue(r1.overlaps(r2))
        self.assertTrue(r2.overlaps(r1))

    def test_merge(self):
        """Test region merging."""
        r1 = Region(0, 100)
        r2 = Region(50, 150)
        merged = r1.merge(r2)
        self.assertEqual(merged.start, 0)
        self.assertEqual(merged.end, 150)


class TestBadRegionMap(unittest.TestCase):
    """Tests for BadRegionMap class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.map_path = Path(self.temp_dir) / "test.map.json"

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_empty_map(self):
        """Test empty map initialization."""
        brm = BadRegionMap(self.map_path)
        self.assertEqual(brm.region_count(), 0)

    def test_add_region(self):
        """Test adding a region."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        self.assertEqual(brm.region_count(), 1)

    def test_contains_exact(self):
        """Test contains with exact match."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        self.assertTrue(brm.contains(0, 100))

    def test_contains_subset(self):
        """Test contains with subset."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        self.assertTrue(brm.contains(25, 50))

    def test_contains_partial_false(self):
        """Test contains returns False for partial overlap."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        # Partial overlap should return False (only full containment returns True)
        self.assertFalse(brm.contains(50, 100))

    def test_contains_outside(self):
        """Test contains returns False for outside range."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        self.assertFalse(brm.contains(100, 100))

    def test_merge_adjacent(self):
        """Test merging adjacent regions."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        brm.add(100, 100)
        self.assertEqual(brm.region_count(), 1)
        self.assertTrue(brm.contains(0, 200))

    def test_merge_overlapping(self):
        """Test merging overlapping regions."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        brm.add(50, 100)
        self.assertEqual(brm.region_count(), 1)
        self.assertTrue(brm.contains(0, 150))

    def test_save_and_load(self):
        """Test saving and loading map."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        brm.add(200, 50)
        brm.save()

        # Load in new instance
        brm2 = BadRegionMap(self.map_path)
        self.assertEqual(brm2.region_count(), 2)
        self.assertTrue(brm2.contains(0, 100))
        self.assertTrue(brm2.contains(200, 50))

    def test_add_zero_length(self):
        """Test adding zero-length region does nothing."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 0)
        self.assertEqual(brm.region_count(), 0)

    def test_contains_zero_size(self):
        """Test contains with zero size returns False."""
        brm = BadRegionMap(self.map_path)
        brm.add(0, 100)
        self.assertFalse(brm.contains(50, 0))

    def test_thread_safety(self):
        """Test thread-safe access."""
        brm = BadRegionMap(self.map_path)
        errors = []

        def adder(start):
            try:
                for i in range(100):
                    brm.add(start + i * 1000, 100)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=adder, args=(i * 100000,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        # Should have added some regions (may be merged)
        self.assertGreater(brm.region_count(), 0)


class TestMapPathForSource(unittest.TestCase):
    """Tests for map_path_for_source function."""

    def test_basic_path(self):
        """Test basic path generation."""
        path = map_path_for_source("/dev/sda")
        self.assertTrue(str(path).startswith("pyddeu.map."))
        self.assertTrue(str(path).endswith(".json"))

    def test_windows_path(self):
        """Test Windows physical drive path."""
        path = map_path_for_source(r"\\.\PhysicalDrive0")
        self.assertTrue(str(path).startswith("pyddeu.map."))
        self.assertTrue("PhysicalDrive0" in str(path))

    def test_custom_directory(self):
        """Test custom directory."""
        path = map_path_for_source("/dev/sda", directory=Path("/tmp"))
        self.assertTrue(str(path).startswith("/tmp/pyddeu.map."))

    def test_unique_per_source(self):
        """Test that different sources get different paths."""
        path1 = map_path_for_source("/dev/sda")
        path2 = map_path_for_source("/dev/sdb")
        self.assertNotEqual(path1, path2)

    def test_stable_path(self):
        """Test that same source gets same path."""
        path1 = map_path_for_source("/dev/sda")
        path2 = map_path_for_source("/dev/sda")
        self.assertEqual(path1, path2)


class TestRecoveryState(unittest.TestCase):
    """Tests for RecoveryState class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.map_path = Path(self.temp_dir) / "test.map.json"
        self.config = PyddeuConfig()

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test state initialization."""
        state = RecoveryState(self.map_path, config=self.config)
        self.assertTrue(state.is_alive)
        self.assertFalse(state.stop_requested)
        self.assertEqual(state.consecutive_errors, 0)

    def test_register_error(self):
        """Test error registration."""
        state = RecoveryState(self.map_path, config=self.config)
        state.register_error(0, 100)
        self.assertEqual(state.consecutive_errors, 1)
        self.assertTrue(state.bad_map.contains(0, 100))

    def test_register_success_resets_errors(self):
        """Test success resets consecutive errors."""
        state = RecoveryState(self.map_path, config=self.config)
        state.register_error(0, 100)
        state.register_error(100, 100)
        self.assertEqual(state.consecutive_errors, 2)

        state.register_success()
        self.assertEqual(state.consecutive_errors, 0)

    def test_skip_size_doubles(self):
        """Test skip size doubles on consecutive errors."""
        state = RecoveryState(self.map_path, block_size=1000, config=self.config)
        initial_skip = state.skip_size

        state.register_error(0, 100)
        self.assertEqual(state.skip_size, initial_skip * 2)

        state.register_error(100, 100)
        self.assertEqual(state.skip_size, initial_skip * 4)

    def test_skip_size_max(self):
        """Test skip size has maximum."""
        state = RecoveryState(
            self.map_path,
            block_size=1000,
            max_skip_size=10000,
            config=self.config,
        )

        # Register many errors
        for i in range(20):
            state.register_error(i * 100, 100)

        self.assertLessEqual(state.skip_size, 10000)

    def test_skip_size_reset_on_success(self):
        """Test skip size resets on success after errors."""
        state = RecoveryState(self.map_path, block_size=1000, config=self.config)

        state.register_error(0, 100)
        state.register_error(100, 100)
        self.assertGreater(state.skip_size, 1000)

        state.register_success()
        self.assertEqual(state.skip_size, 1000)

    def test_controller_panic(self):
        """Test controller panic registration."""
        state = RecoveryState(self.map_path, config=self.config)
        log_messages = []

        def log_cb(level, msg):
            log_messages.append((level, msg))

        state.register_controller_panic(log_cb=log_cb)

        # Should have logged warning
        self.assertTrue(any("Controller Panic" in msg for _, msg in log_messages))
        # Should have set pause
        self.assertGreater(state.pause_until, 0)

    def test_controller_panic_auto_stop(self):
        """Test auto-stop after too many panics."""
        state = RecoveryState(self.map_path, config=self.config)

        # Register many panics
        for _ in range(15):
            state.register_controller_panic()

        self.assertTrue(state.stop_requested)

    def test_wait_if_paused(self):
        """Test pause waiting."""
        state = RecoveryState(self.map_path, config=self.config)
        state.pause_until = time.time() + 0.5

        start = time.time()
        state.wait_if_paused()
        elapsed = time.time() - start

        # Should have waited some time (at least a bit)
        self.assertGreater(elapsed, 0.01)

    def test_reset(self):
        """Test state reset."""
        state = RecoveryState(self.map_path, config=self.config)
        state.register_error(0, 100)
        state.register_error(100, 100)
        state.register_controller_panic()

        state.reset()

        self.assertEqual(state.consecutive_errors, 0)
        self.assertEqual(state.skip_size, state.block_size)
        self.assertEqual(state.pause_until, 0)


if __name__ == "__main__":
    unittest.main()
