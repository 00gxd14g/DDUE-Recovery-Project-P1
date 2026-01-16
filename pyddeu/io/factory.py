from __future__ import annotations

from ..platform import IS_WINDOWS
from .base import DiskSource, SourceInfo
from ..config import PyddeuConfig


def open_source(path: str, *, config: PyddeuConfig | None = None) -> DiskSource:
    if IS_WINDOWS:
        from .windows import open_windows_source

        return open_windows_source(path, config=config)

    from .posix import open_posix_source

    return open_posix_source(path, config=config)


def list_sources() -> list[SourceInfo]:
    if IS_WINDOWS:
        from .windows import list_physical_drives

        return list_physical_drives()

    from .posix import list_linux_devices

    return list_linux_devices()
