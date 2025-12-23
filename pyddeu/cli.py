from __future__ import annotations

import argparse
from pathlib import Path

from .io import list_sources, open_source
from .partitions import scan_partitions
from .state import RecoveryState


def _cmd_list_disks(_args: argparse.Namespace) -> int:
    sources = list_sources()
    for s in sources:
        gb = (s.size or 0) / (1024**3)
        print(f"{s.path}\t{gb:.2f} GB\t{s.description}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    src = open_source(args.source)
    try:
        state = RecoveryState(map_path=Path("pyddeu.map.json"))

        def log_cb(level: str, msg: str) -> None:
            print(f"[{level}] {msg}")

        parts = scan_partitions(src, state=state, log_cb=log_cb)
        for p in parts:
            gb = p.length / (1024**3)
            name = f" name={p.name}" if p.name else ""
            print(f"[{p.index}] {p.scheme} {p.type_str} start={p.start_offset} size={gb:.2f}GB{name}")
        return 0
    finally:
        src.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pyddeu", add_help=True)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-disks", help="List available raw disks").set_defaults(func=_cmd_list_disks)

    scan = sub.add_parser("scan", help="Scan MBR/GPT partitions")
    scan.add_argument("--source", required=True, help=r"Image path or raw device (e.g. \\.\PhysicalDrive0)")
    scan.set_defaults(func=_cmd_scan)

    sub.add_parser("gui", help="Launch the Tkinter GUI")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "gui":
        from .gui import main as gui_main

        gui_main()
        return 0
    return int(args.func(args))
