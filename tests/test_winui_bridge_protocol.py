from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
PYTHON_EXE = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))


def _run_bridge(*args: str, payload: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON_EXE, "-m", "pyddeu.winui_bridge", *args],
        cwd=REPO_ROOT,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )


def _parse_stdout(stdout: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


class TestWinuiBridgeProtocol(unittest.TestCase):
    def test_health_returns_expected_payload(self) -> None:
        completed = _run_bridge("--health")

        self.assertEqual(completed.returncode, 0)
        events = _parse_stdout(completed.stdout)
        self.assertEqual(len(events), 1)
        health = events[0]
        self.assertEqual(health["type"], "health")
        self.assertTrue(health["ok"])
        self.assertIsInstance(health["details"], dict)
        self.assertTrue(health["details"]["python"])

    def test_missing_command_returns_invalid_cli(self) -> None:
        completed = _run_bridge()

        self.assertEqual(completed.returncode, 1)
        events = _parse_stdout(completed.stdout)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "error")
        self.assertEqual(events[0]["code"], "invalid_cli")

    def test_invalid_json_payload_returns_invalid_payload(self) -> None:
        completed = _run_bridge("--command", "list_disks", payload="{")

        self.assertEqual(completed.returncode, 1)
        events = _parse_stdout(completed.stdout)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "error")
        self.assertEqual(events[0]["code"], "invalid_payload")

    def test_unknown_command_returns_unknown_command(self) -> None:
        completed = _run_bridge("--command", "does_not_exist", payload="{}")

        self.assertEqual(completed.returncode, 1)
        events = _parse_stdout(completed.stdout)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "error")
        self.assertEqual(events[0]["code"], "unknown_command")


if __name__ == "__main__":
    unittest.main()
