from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import configparser
from typing import Optional


@dataclass(frozen=True)
class PyddeuConfig:
    # Mirrors a small, practical subset of dmde.ini (mostly [IO]).
    readonly: bool = True

    retries: int = 1
    seekretries: int = 1
    deviojump_sectors: int = 0

    devioskipfiller: Optional[int] = 0x50494B53  # "SKIP" (little-endian bytes)
    deviobadfiller: Optional[int] = 0x20444142   # "BAD " (little-endian bytes)

    buffer: int = 131072
    dblbuffer: int = 2097152
    diskcache: int = 16777216

    deviowait_ms: int = 0  # overlapped timeout ms (0 disables overlapped timeout reads)
    scsitimeout_s: int = 5

    @staticmethod
    def _parse_int(s: str) -> Optional[int]:
        v = (s or "").strip()
        if not v:
            return None
        try:
            if v.lower().startswith("0x"):
                return int(v, 16)
            return int(v, 10)
        except Exception:
            return None

    @staticmethod
    def _get_bool(cfg: configparser.ConfigParser, section: str, key: str, default: bool) -> bool:
        try:
            return cfg.getboolean(section, key)
        except Exception:
            return bool(default)

    @classmethod
    def load(cls, path: str | Path) -> "PyddeuConfig":
        p = Path(path)
        if not p.exists():
            return cls()

        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str  # keep case (DMDE uses lowercase anyway)
        try:
            parser.read(p, encoding="utf-8")
        except Exception:
            parser.read(p)

        readonly = cls._get_bool(parser, "Setup", "readonly", True)
        retries = int(parser.get("IO", "retries", fallback=str(cls.retries)) or cls.retries)
        seekretries = int(parser.get("IO", "seekretries", fallback=str(cls.seekretries)) or cls.seekretries)
        deviojump = int(parser.get("IO", "deviojump", fallback=str(cls.deviojump_sectors)) or cls.deviojump_sectors)

        badf = cls._parse_int(parser.get("IO", "deviobadfiller", fallback=""))
        skipf = cls._parse_int(parser.get("IO", "devioskipfiller", fallback=""))

        buffer = int(parser.get("IO", "buffer", fallback=str(cls.buffer)) or cls.buffer)
        dblbuffer = int(parser.get("IO", "dblbuffer", fallback=str(cls.dblbuffer)) or cls.dblbuffer)
        diskcache = int(parser.get("IO", "diskcache", fallback=str(cls.diskcache)) or cls.diskcache)

        deviowait = int(parser.get("IO", "deviowait", fallback=str(cls.deviowait_ms)) or cls.deviowait_ms)
        scsitimeout = int(parser.get("IO", "scsitimeout", fallback=str(cls.scsitimeout_s)) or cls.scsitimeout_s)

        # Clamp to sane ranges
        retries = max(0, min(999, retries))
        seekretries = max(0, min(999, seekretries))
        deviojump = max(0, min(1024 * 1024, deviojump))
        buffer = max(4096, min(1048576, buffer))
        dblbuffer = max(4096, min(16777216, dblbuffer))
        diskcache = max(4096, min(33554432, diskcache))
        deviowait = max(0, min(600000, deviowait))
        scsitimeout = max(1, min(3600, scsitimeout))

        return cls(
            readonly=bool(readonly),
            retries=retries,
            seekretries=seekretries,
            deviojump_sectors=deviojump,
            deviobadfiller=badf,
            devioskipfiller=skipf,
            buffer=buffer,
            dblbuffer=dblbuffer,
            diskcache=diskcache,
            deviowait_ms=deviowait,
            scsitimeout_s=scsitimeout,
        )


def default_config_path() -> Path:
    # Workspace-local config file (user can edit).
    return Path("pyddeu.ini")

