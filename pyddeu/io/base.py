from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SourceInfo:
    path: str
    size: int
    description: str = ""


class DiskSource(Protocol):
    path: str

    def size(self) -> int: ...

    def sector_size(self) -> int: ...

    def read_at(self, offset: int, size: int) -> bytes: ...

    def close(self) -> None: ...
