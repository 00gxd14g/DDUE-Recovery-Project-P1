from __future__ import annotations

from typing import Callable, Optional

import pytsk3

from .io.base import DiskSource
from .scan import safe_read_granular
from .state import RecoveryState


class DDEUImg(pytsk3.Img_Info):
    def __init__(
        self,
        source: DiskSource,
        state: RecoveryState,
        log_cb: Optional[Callable[[str, str], None]] = None,
    ):
        self._source = source
        self._state = state
        self._log_cb = log_cb
        super().__init__(url=getattr(source, "path", "pyddeu://source"))

    def get_size(self) -> int:
        return int(self._source.size() or 0)

    def read(self, offset: int, size: int) -> bytes:
        if self._state.stop_requested or not self._state.is_alive:
            return b"\x00" * size
        return safe_read_granular(self._source, self._state, int(offset), int(size), log_cb=self._log_cb)
