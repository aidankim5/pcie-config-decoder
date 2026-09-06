"""Command line: decode, all, list, dump.

Built so far: `decode` prints the header (module 2), the standard capability
chain and the --annotate view (module 3), and with --hex the raw bytes
(module 1). Everything else says plainly that it is not built yet instead of
printing something that looks decoded.

Exit codes (a choice, not spec):
  0  done
  1  bad input: the file is missing, unreadable, or not a dump
  2  usage error (argparse's own convention: unknown command or flag)
  3  the requested part of the tool is not built yet
"""

import argparse
import json
import sys
from dataclasses import asdict

from .caps import CapabilityChain, walk_standard_caps
from .header import decode_header
from .msi import decode_msi, decode_msix
from .parse import ConfigSpace, ParseError, load_config_space
from .pm import decode_power_management
from .render import render_annotated, render_capabilities, render_chain, render_header, render_hex

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


def describe_source(cs: ConfigSpace) -> list[str]:
    """The '# ...' lines that say what device and what file we are looking at."""
    lines = []
    bdf_prefix = f"{cs.bdf} " if cs.bdf else ""
    if bdf_prefix or cs.description:
        lines.append(f"# {bdf_prefix}{cs.description}".rstrip())
    lines.append(f"# {cs.source}: {cs.size} bytes ({cs.origin}) = {cs.frame}")
    if "<access denied>" in cs.lspci_text:
        lines.append("# note: lspci was run without sudo, so only the first 64 bytes are present")
    return lines


def decoded_capability(cs: ConfigSpace, c) -> dict | None:
    """The registers of one chain entry as a dict, when a decoder exists and the bytes fit."""
    decoders = {0x01: (8, decode_power_management), 0x11: (12, decode_msix)}
    if c.cap_id == 0x05:
        decoders[0x05] = (c.structure_length or 4, decode_msi)
    if c.cap_id not in decoders:
        return None
    needed, decode = decoders[c.cap_id]
    if c.span < needed:
        return {"problem": f"only {c.span} bytes before the next start; the structure needs {needed}"}
    return asdict(decode(cs, c.offset))


def chain_as_json(cs: ConfigSpace, chain: CapabilityChain | None) -> dict:
    """The chain as plain dicts; bytes become hex strings (.hex()), which JSON can carry."""
    if chain is None:
        return {"entries": [], "notes": ["Vendor ID FFFFh: no Function is present (7.5.1.1.1); the chain was not walked"]}
    return {
        "pointer_raw": chain.pointer_raw,
        "pointer": chain.pointer,
        "has_list": chain.has_list,
        "notes": chain.notes,
        "entries": [
            {
                "offset": c.offset,
                "id": c.cap_id,
                "name": c.name,
                "next_pointer": c.next_pointer,
                "span": c.span,  # a choice: the address gap to the next start
                "structure_length": c.structure_length,  # the spec's size when known, else null
                "taught": c.taught,
                "problem": c.problem,
                "span_data": c.data.hex(),
                "structure_data": c.structure_data.hex(),
                "decoded": decoded_capability(cs, c),  # null until that capability has a decoder
            }
            for c in chain.entries
        ],
    }


def cmd_decode(args: argparse.Namespace) -> int:
    cs = load_config_space(args.file)
    header = decode_header(cs)
    # Vendor ID FFFFh means no Function (7.5.1.1.1): the bytes are all ones, so 34h is not a
    # pointer and the walk is skipped.
    chain = walk_standard_caps(cs) if header.function_present else None

    if args.json:
        # asdict turns the dataclass (and its nested Bit/Bar lists) into plain dicts and lists,
        # the only things json.dumps can write. JSON has no hex literal, so 4318 here is 0x10DE
        # (a choice; hex strings would be the alternative). Properties are not fields, so the
        # derived names are added by the render module later.
        doc = {"source": cs.source, "bdf": cs.bdf, "size": cs.size, "header": asdict(header)}
        doc["standard_capabilities"] = chain_as_json(cs, chain)
        print(json.dumps(doc, indent=2))
        print("json: PCI Express capability and the extended chain not built yet (modules pcie_cap, extcaps, aer)", file=sys.stderr)
        return NOT_YET

    print("\n".join(describe_source(cs)))
    print(render_header(header))
    if chain is not None:
        print()
        print(render_chain(chain))
        if chain.entries:
            print()
            print(render_capabilities(cs, chain))
        if args.annotate:
            print()
            print(render_annotated(cs, chain))
    if args.hex:  # like lspci -xxxx: the decoded view first, then the raw bytes
        print()
        print(render_hex(cs.data))
    # Messages about what is missing go to stderr, so stdout stays clean data.
    print("PCI Express capability and the extended chain: not built yet (modules pcie_cap, extcaps, aer)", file=sys.stderr)
    return NOT_YET


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
        # IndexError: a register read past the end of a short dump (ConfigSpace._check in parse.py).
        print(f"pcicfg: {e}", file=sys.stderr)
        return BAD_INPUT
