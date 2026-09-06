"""Command line: decode, all, list, dump.

Built so far: `decode` prints the header (module 2), the standard capability
chain and the --annotate view (module 3), the Power Management, MSI and MSI-X
registers (module 4; --json carries them under 'decoded'), and with --hex the
raw bytes (module 1). Everything else says plainly that it is not built yet
instead of printing something that looks decoded.

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

from .aer import ROOT_PORT_TYPES, decode_aer
from .caps import Capability, CapabilityChain, walk_standard_caps
from .extcaps import ExtendedChain, decode_extended_registers, l1ss_summary, ltr_summary, walk_extended_caps
from .header import decode_header
from .msi import decode_msi, decode_msix
from .parse import ConfigSpace, ParseError, load_config_space
from .pcie_cap import decode_pcie_capability
from .pm import decode_power_management
from .render import (
    render_annotated,
    render_annotated_extended,
    render_capabilities,
    render_chain,
    render_extended_capabilities,
    render_extended_chain,
    render_header,
    render_hex,
)

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


def decoded_capability(cs: ConfigSpace, c: Capability) -> dict | None:
    """The registers of one chain entry as a dict, or None when no decoder exists yet.

    asdict gives the stored fields only, so the derived values an lspci line is
    built from (table size, vector counts, the 64-bit address, PME states) are
    added by name afterwards.
    """
    if c.cap_id not in (0x01, 0x05, 0x10, 0x11):
        return None
    if c.structure_length is None:  # fewer than 4 bytes: the register at +02h is unreadable
        return {"problem": f"only {c.span} bytes; the register at +02h cannot be read"}
    if c.span < c.structure_length:
        return {"problem": c.problem}
    if c.cap_id == 0x10:
        p = decode_pcie_capability(cs, c.offset)
        return {
            "offset": p.offset,
            "version": p.version,
            "device_port_type": p.device_port_type,
            "device_port_type_name": p.device_port_type_name,
            "structure_length": p.structure_length,
            "link_summary": p.link_summary if p.has_link_registers else None,
            "speed_downgraded": p.speed_downgraded,
            "width_downgraded": p.width_downgraded,
            "current_link_speed_code": p.current_link_speed_code,
            "max_link_speed_code": p.max_link_speed_code,
            "negotiated_link_width": p.negotiated_link_width,
            "max_link_width": p.max_link_width,
            "max_payload_supported_bytes": p.max_payload_supported_bytes,
            "max_payload_bytes": p.max_payload_bytes,
            "max_read_request_bytes": p.max_read_request_bytes,
            "supported_speeds_gts": p.supported_speeds_gts,
            "registers": [asdict(r) for r in p.registers],
        }
    if c.cap_id == 0x01:
        pm = decode_power_management(cs, c.offset)
        doc = asdict(pm)
        doc.update(power_state_name=pm.power_state_name, pme_states=pm.pme_states, aux_current_ma=pm.aux_current_ma)
    elif c.cap_id == 0x05:
        m = decode_msi(cs, c.offset)
        doc = asdict(m)
        doc.update(vectors_capable=m.vectors_capable, vectors_enabled=m.vectors_enabled,
                   full_address=m.full_address, structure_length=m.structure_length, problem=m.problem)
    else:
        x = decode_msix(cs, c.offset)
        doc = asdict(x)
        doc.update(table_size=x.table_size, table_bar_offset=x.table_bar_offset, pba_bar_offset=x.pba_bar_offset)
    return doc


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


def pcie_facts(cs: ConfigSpace, chain: CapabilityChain | None) -> tuple[int | None, bool]:
    """(Maximum Link Width, is this a Root Port or Event Collector) from the PCI Express capability.

    The width sizes the per-lane extended structures; the port type says whether
    AER's Root Error registers apply.
    """
    if chain is None:
        return None, False
    pcie = chain.find(0x10)
    if pcie is None or pcie.structure_length is None or pcie.span < pcie.structure_length:
        return None, False
    p = decode_pcie_capability(cs, pcie.offset)
    width = p.max_link_width if p.has_link_registers else None
    return width, p.device_port_type in ROOT_PORT_TYPES


def aer_as_json(cs: ConfigSpace, c, is_root: bool) -> dict | None:
    if c.span < 0x2C:
        return None
    aer = decode_aer(cs, c.offset, is_root)
    return {
        "summary": aer.summary,
        "uncorrectable_errors": aer.uncorrectable_errors,
        "correctable_errors": aer.correctable_errors,
        "uncorrectable_masked": aer.uncorrectable_masked,
        "correctable_masked": aer.correctable_masked,
        "fatal_errors": aer.fatal_errors,
        "first_error_pointer": aer.first_error_pointer,
        "severity_is_spec_default": aer.severity_is_spec_default,
        "header_log": aer.header_log,
        "header_log_wire_bytes": aer.header_log_wire_bytes.hex(),
        "tlp_prefix_log": aer.tlp_prefix_log,
        "registers": [asdict(r) for r in aer.registers],
    }


def extended_chain_as_json(cs: ConfigSpace, ext: ExtendedChain | None, is_root: bool = False) -> dict:
    if ext is None:
        return {"present": False, "entries": [], "notes": ["Vendor ID FFFFh: no Function is present; the chain was not walked"]}
    return {
        "present": ext.present,
        "notes": ext.notes,
        "entries": [
            {
                "offset": c.offset,
                "header": c.header,
                "id": c.cap_id,
                "version": c.version,
                "name": c.name,
                "next_offset": c.next_offset,
                "span": c.span,
                "structure_length": c.structure_length,
                "taught": c.taught,
                "problem": c.problem,
                "summary": ltr_summary(cs, c) or l1ss_summary(cs, c),
                "registers": [asdict(r) for r in decode_extended_registers(cs, c)],
                "aer": aer_as_json(cs, c, is_root) if c.cap_id == 0x0001 else None,
                "structure_data": c.structure_data.hex(),
            }
            for c in ext.entries
        ],
    }


def cmd_decode(args: argparse.Namespace) -> int:
    cs = load_config_space(args.file)
    header = decode_header(cs)
    # Vendor ID FFFFh means no Function (7.5.1.1.1): the bytes are all ones, so 34h is not a
    # pointer and the walk is skipped.
    chain = walk_standard_caps(cs) if header.function_present else None
    max_width, is_root = pcie_facts(cs, chain)
    ext = walk_extended_caps(cs, max_width) if header.function_present else None

    if args.json:
        # asdict turns the dataclass (and its nested Bit/Bar lists) into plain dicts and lists,
        # the only things json.dumps can write. JSON has no hex literal, so 4318 here is 0x10DE
        # (a choice; hex strings would be the alternative). Properties are not fields, so the
        # derived values are added by name in the *_as_json helpers.
        doc = {"source": cs.source, "bdf": cs.bdf, "size": cs.size, "header": asdict(header)}
        doc["standard_capabilities"] = chain_as_json(cs, chain)
        doc["extended_capabilities"] = extended_chain_as_json(cs, ext, is_root)
        print(json.dumps(doc, indent=2))
        return OK

    print("\n".join(describe_source(cs)))
    print(render_header(header))
    if chain is not None:
        print()
        print(render_chain(chain))
        if chain.entries:
            print()
            print(render_capabilities(cs, chain))
    if ext is not None:
        print()
        print(render_extended_chain(ext))
        if ext.entries:
            print()
            print(render_extended_capabilities(cs, ext, is_root))
    if args.annotate and chain is not None:
        print()
        print(render_annotated(cs, chain))
        if ext is not None and ext.present:
            print()
            print(render_annotated_extended(cs, ext))
    if args.hex:  # like lspci -xxxx: the decoded view first, then the raw bytes
        print()
        print(render_hex(cs.data))
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
        # IndexError: a register read past the end of a short dump (ConfigSpace._check in parse.py).
        print(f"pcicfg: {e}", file=sys.stderr)
        return BAD_INPUT
