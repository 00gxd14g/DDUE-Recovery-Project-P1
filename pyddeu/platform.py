from __future__ import annotations

import os
import sys
from typing import Final


IS_WINDOWS: Final[bool] = sys.platform.startswith("win")
IS_LINUX: Final[bool] = sys.platform.startswith("linux")
IS_MAC: Final[bool] = sys.platform == "darwin"


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    if hasattr(os, "getuid"):
        return os.getuid() == 0
    return False


def format_source_hint() -> str:
    if IS_WINDOWS:
        return r"Use \\.\PhysicalDrive0 or an image file"
    if IS_LINUX:
        return "Use /dev/sdX or an image file"
    return "Use an image file"

