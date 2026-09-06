"""Command line: decode, all, list, dump.

Module 1 implements `decode --hex`. The other paths say plainly that they are
not built yet instead of printing something that looks decoded.

Exit codes (a choice, not spec):
  0  done
  1  bad input: the file is missing, unreadable, or not a dump
  2  usage error (argparse's own convention: unknown command or flag)
  3  the requested part of the tool is not built yet
"""

import argparse
import sys

from .parse import ParseError, load_config_space
from .render import render_hex

OK, BAD_INPUT, NOT_YET = 0, 1, 3  # 2 is taken by argparse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcicfg",
        description="Read and decode PCI Express configuration space.",
    )
    # One sub-command per verb: `pcicfg decode ...`, `pcicfg all ...`, and so on.
    # dest="cmd" stores which one was typed in args.cmd; required=True refuses none.
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode", help="decode one dump (lspci -xxxx text or raw binary)")
    d.add_argument("file")
    # store_true: the flag is False unless typed, then True. No value follows it.
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
    # Two "# ..." lines first: what device (when the file said), then what we read.
    bdf_prefix = f"{cs.bdf} " if cs.bdf else ""
    if bdf_prefix or cs.description:
        print(f"# {bdf_prefix}{cs.description}".rstrip())
    print(f"# {cs.source}: {cs.size} bytes ({cs.origin}) = {cs.frame}")
    if "<access denied>" in cs.lspci_text:
        print("# note: lspci was run without sudo, so only the first 64 bytes are present")
    if args.hex:
        print(render_hex(cs.data))
    # Messages about what is missing go to stderr, so stdout stays clean data.
    if args.json or args.annotate:
        print("decode --json / --annotate: not built yet (module: render)", file=sys.stderr)
        return NOT_YET
    if not args.hex:
        print(
            "decoded view: not built yet (modules: header, caps, pcie_cap, extcaps, aer)",
            file=sys.stderr,
        )
        return NOT_YET
    return OK


def main(argv: list[str] | None = None) -> int:
    # argv=None means "use the real command line"; tests pass a list instead.
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "decode":
            return cmd_decode(args)
        print(f"pcicfg {args.cmd}: not built yet", file=sys.stderr)
        return NOT_YET
    except (ParseError, OSError, IndexError) as e:
        # OSError covers a missing file, a directory, or no permission to read.
        print(f"pcicfg: {e}", file=sys.stderr)
        return BAD_INPUT
