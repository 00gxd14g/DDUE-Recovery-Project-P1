from __future__ import annotations

from pathlib import Path

from ..platform import IS_WINDOWS
from .base import DiskSource, SourceInfo


def open_source(path: str) -> DiskSource:
    if IS_WINDOWS:
        from .windows import open_windows_source

        return open_windows_source(path)

    from .posix import open_posix_source

    return open_posix_source(path)


def list_sources() -> list[SourceInfo]:
    if IS_WINDOWS:
        from .windows import list_physical_drives

        return list_physical_drives()

    sources: list[SourceInfo] = []
    sys_block = Path("/sys/block")
    if sys_block.exists():
        for dev in sys_block.iterdir():
            name = dev.name
            if name.startswith(("loop", "ram")):
                continue
            size_path = dev / "size"
            if not size_path.exists():
                continue
            try:
                sectors = int(size_path.read_text(encoding="utf-8").strip())
            except Exception:
                continue
            sources.append(SourceInfo(path=f"/dev/{name}", size=sectors * 512, description="block"))
    return sources

