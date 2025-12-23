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
    def __init__(self, log_cb: LogCb, state: Optional[RecoveryState] = None, device_hint: Optional[str] = None):
        super().__init__(daemon=True)
        self._log_cb = log_cb
        self._state = state
        self._device_hint = device_hint
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            proc = subprocess.Popen(["dmesg", "-w"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            self._log_cb("WARNING", f"Kernel monitor not started: {e}")
            return

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                line_s = line.strip()
                if not line_s:
                    continue
                if self._device_hint and self._device_hint not in line_s:
                    continue
                low = line_s.lower()
                if "i/o error" in low or "buffer i/o" in low:
                    self._log_cb("WARNING", f"KERNEL: {line_s}")
                elif "reset" in low or "disconnected" in low or "offline" in low:
                    self._log_cb("CRITICAL", f"KERNEL: {line_s}")
                    if self._state is not None:
                        self._state.register_controller_panic()
                elif "nvme" in low and ("error" in low or "failed" in low):
                    self._log_cb("WARNING", f"KERNEL: {line_s}")
        finally:
            try:
                proc.terminate()
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
