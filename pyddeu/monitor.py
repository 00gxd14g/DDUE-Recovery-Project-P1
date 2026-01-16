from __future__ import annotations

import subprocess
import threading
import time
from datetime import datetime
from typing import Callable, Optional

from .platform import IS_LINUX, IS_WINDOWS
from .state import RecoveryState


LogCb = Callable[[str, str], None]


class LinuxKernelMonitor(threading.Thread):
    """
    Enhanced Linux kernel log monitor for disk error detection.

    Monitors dmesg for:
    - I/O errors (EIO, buffer errors)
    - Device resets and controller panics
    - NVMe errors (command failures, timeouts)
    - SCSI/ATA errors (sense data, aborted commands)
    - Medium errors (bad sectors, CRC errors)
    - Device disconnections and reconnections
    """

    # Patterns that indicate critical device issues requiring panic handling
    CRITICAL_PATTERNS = (
        "reset",
        "disconnected",
        "offline",
        "controller is down",
        "fatal error",
        "device removed",
        "task abort",
        "hard reset",
        "link down",
        "not responding",
        "device not ready",
        "aborted command",
        "host reset",
    )

    # Patterns that indicate I/O errors (warning level)
    WARNING_PATTERNS = (
        "i/o error",
        "buffer i/o",
        "medium error",
        "read error",
        "write error",
        "crc error",
        "unrecovered read",
        "uncorrectable error",
        "sense data",
        "command failed",
        "timeout",
        "retry",
        "bad sector",
    )

    # NVMe-specific patterns
    NVME_WARNING_PATTERNS = (
        "nvme",
        "nvme timeout",
        "nvme abort",
        "completion polled",
    )

    # SCSI/ATA specific patterns
    SCSI_ATA_PATTERNS = (
        "ata",
        "scsi",
        "sata",
        "exception emask",
        "status: {",
        "sense key",
    )

    def __init__(
        self,
        log_cb: LogCb,
        state: Optional[RecoveryState] = None,
        device_hint: Optional[str] = None,
    ):
        super().__init__(daemon=True)
        self._log_cb = log_cb
        self._state = state
        self._device_hint = device_hint
        self._stop = threading.Event()
        self._error_count = 0
        self._last_error_time = 0.0

    def stop(self) -> None:
        self._stop.set()

    def _classify_message(self, line: str) -> tuple[str, bool]:
        """
        Classify a kernel message and determine severity.

        Returns (level, should_trigger_panic) tuple.
        """
        low = line.lower()

        # Check for critical patterns first
        for pattern in self.CRITICAL_PATTERNS:
            if pattern in low:
                return "CRITICAL", True

        # Check for NVMe errors
        if "nvme" in low:
            for pattern in ("error", "failed", "timeout", "abort"):
                if pattern in low:
                    # NVMe errors are often critical
                    return "CRITICAL", True

        # Check for SCSI/ATA errors with exception
        if any(p in low for p in self.SCSI_ATA_PATTERNS):
            if "exception" in low or "failed" in low:
                return "CRITICAL", True
            if any(p in low for p in self.WARNING_PATTERNS):
                return "WARNING", False

        # Check for warning patterns
        for pattern in self.WARNING_PATTERNS:
            if pattern in low:
                return "WARNING", False

        return "", False

    def _should_process_line(self, line: str) -> bool:
        """Check if a line should be processed based on device hint."""
        if not self._device_hint:
            # No filter - process disk-related messages
            low = line.lower()
            return any(k in low for k in (
                "sd", "nvme", "ata", "scsi", "sata",
                "i/o", "block", "disk", "drive"
            ))

        return self._device_hint in line

    def run(self) -> None:
        # Try dmesg -w first (follow mode) - requires root on most systems
        try:
            proc = subprocess.Popen(
                ["dmesg", "-w", "-T"],  # -T for human-readable timestamps
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except Exception:
            # Fallback without -T flag
            try:
                proc = subprocess.Popen(
                    ["dmesg", "-w"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except Exception as e:
                # dmesg may require root privileges
                self._log_cb(
                    "WARNING",
                    f"Kernel monitor not started (may require root): {e}. "
                    "Disk error monitoring disabled."
                )
                return

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if self._stop.is_set():
                    break

                line_s = line.strip()
                if not line_s:
                    continue

                if not self._should_process_line(line_s):
                    continue

                level, trigger_panic = self._classify_message(line_s)

                if not level:
                    continue

                # Log the message
                self._log_cb(level, f"KERNEL: {line_s}")

                # Track error frequency
                current_time = time.time()
                if current_time - self._last_error_time < 5.0:
                    self._error_count += 1
                else:
                    self._error_count = 1
                self._last_error_time = current_time

                # Trigger panic if critical or too many errors in short time
                if trigger_panic and self._state is not None:
                    self._state.register_controller_panic(log_cb=self._log_cb)
                elif self._error_count >= 5 and self._state is not None:
                    # Many errors in quick succession - treat as panic
                    self._log_cb(
                        "WARNING",
                        f"High error frequency detected ({self._error_count} errors in <5s)"
                    )
                    self._state.register_controller_panic(log_cb=self._log_cb)
                    self._error_count = 0

        finally:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


class WindowsDiskEventMonitor(threading.Thread):
    """
    Best-effort Windows System log monitor without external deps.
    Periodically queries recent events and forwards disk/storage related messages.
    """

    def __init__(self, log_cb: LogCb, state: Optional[RecoveryState] = None, poll_s: float = 2.0):
        super().__init__(daemon=True)
        self._log_cb = log_cb
        self._state = state
        self._poll_s = poll_s
        self._stop = threading.Event()
        self._last_record_id: int = 0
        # Avoid replaying old events on startup; only consider events created after monitor start.
        self._start_iso = datetime.now().isoformat()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                # Provider names commonly: disk, storahci, nvme, stornvme, partmgr, volmgr
                ps = (
                    f"$st=[datetime]::Parse('{self._start_iso}'); "
                    "Get-WinEvent -MaxEvents 50 -FilterHashtable @{LogName='System'; StartTime=$st} | "
                    "Where-Object { $_.ProviderName -in @('disk','partmgr','volmgr','stornvme','nvme','storahci') } | "
                    "Select-Object RecordId, ProviderName, Id, LevelDisplayName, TimeCreated, Message"
                )
                out = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps], text=True, stderr=subprocess.DEVNULL)
                # Very simple parsing: split records by blank lines, track highest RecordId seen.
                blocks = [b.strip() for b in out.split("\n\n") if b.strip()]
                max_id = self._last_record_id
                for b in blocks:
                    rid = _parse_record_id(b)
                    if rid is None:
                        continue
                    if rid <= self._last_record_id:
                        continue
                    max_id = max(max_id, rid)
                    msg = _extract_message(b)
                    low = b.lower()
                    level = "WARNING"
                    critical = ("reset to device" in low) or ("failed" in low and "hardware error" in low)
                    if "critical" in low or critical:
                        level = "CRITICAL"
                    self._log_cb(level, f"EVENTLOG: {msg[:500]}")
                    if critical and self._state is not None:
                        # Controller panic: don't auto-stop; pause reads to let the device recover.
                        self._state.register_controller_panic()
                self._last_record_id = max_id
            except Exception:
                pass
            time.sleep(self._poll_s)


def _parse_record_id(block: str) -> Optional[int]:
    for line in block.splitlines():
        if line.strip().lower().startswith("recordid"):
            # "RecordId : 123"
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    return int(parts[1].strip())
                except Exception:
                    return None
    return None


def _extract_message(block: str) -> str:
    # "Message : ...." may span lines; take from first occurrence.
    lines = block.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().lower().startswith("message"):
            start = i
            break
    if start is None:
        return block
    msg_lines = []
    for j in range(start, len(lines)):
        if j == start:
            # drop "Message :"
            parts = lines[j].split(":", 1)
            msg_lines.append(parts[1].strip() if len(parts) == 2 else lines[j].strip())
        else:
            msg_lines.append(lines[j].rstrip())
    return " ".join(msg_lines).strip()


def start_monitor(log_cb: LogCb, source_path: str, state: Optional[RecoveryState] = None) -> Optional[threading.Thread]:
    if IS_LINUX:
        dev = source_path.split("/")[-1] if source_path.startswith("/dev/") else None
        t = LinuxKernelMonitor(log_cb, state=state, device_hint=dev)
        t.start()
        return t
    if IS_WINDOWS:
        t2 = WindowsDiskEventMonitor(log_cb, state=state)
        t2.start()
        return t2
    return None
