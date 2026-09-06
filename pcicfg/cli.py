"""Command line: decode, all, list, dump.

Module 1 implements `decode --hex`. The other paths say plainly that they are
not built yet instead of printing something that looks decoded.
"""

from __future__ import annotations

import argparse
import sys

from .parse import ParseError, load_config_space
from .render import render_hex

NOT_YET = 2  # exit code for "this part is not built yet"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcicfg",
        description="Read and decode PCI Express configuration space.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode", help="decode one dump (lspci -xxxx text or raw binary)")
    d.add_argument("file")
    d.add_argument("--json", action="store_true", help="JSON instead of text")
    d.add_argument(
        "--hex",
        action="store_true",
        help="print the raw bytes, 16 per row, absolute offsets (same look as lspci -xxxx)",
    )
    d.add_argument(
        "--annotate",
        action="store_true",
        help="hex rows with each capability's start marked, then each capability rebased to 00",
    )

    a = sub.add_parser("all", help="decode every device in a full `lspci -vvv -xxxx` listing")
    a.add_argument("file")

    sub.add_parser("list", help="Windows only: one row per PCI function with link speed/width")

    du = sub.add_parser("dump", help="Windows only: raw config space of one function (Layer 3)")
    du.add_argument("bdf", help="bus:device.function, e.g. 01:00.0")
    du.add_argument("-o", "--output", help="write the raw bytes to this file")
    return p


def cmd_decode(args: argparse.Namespace) -> int:
    cs = load_config_space(args.file)
    where = f"{cs.bdf} " if cs.bdf else ""
    print(f"# {where}{cs.description}".rstrip())
    print(f"# {cs.source}: {cs.size} bytes = {cs.frame}")
    if args.hex:
        print(render_hex(cs.data))
    if args.json or args.annotate:
        print("decode --json / --annotate: not built yet (module: render)", file=sys.stderr)
        return NOT_YET
    if not args.hex:
        print(
            "decoded view: not built yet (modules: header, caps, pcie_cap, extcaps, aer)",
            file=sys.stderr,
        )
        return NOT_YET
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "decode":
            return cmd_decode(args)
        print(f"pcicfg {args.cmd}: not built yet", file=sys.stderr)
        return NOT_YET
    except (ParseError, FileNotFoundError, IndexError) as e:
        print(f"pcicfg: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
