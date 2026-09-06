"""Command line: decode, all, list, dump.

Layer 1 is complete: `decode` prints the header (module 2), the standard
capability chain and --annotate view (module 3), the Power Management, MSI and
MSI-X registers (module 4), the PCI Express capability (module 5), the
extended chain (module 6), AER (module 7), and with --hex the raw bytes
(module 1); `all` runs the same over every device of a full lspci listing
(module 8). --json gives the same as plain dicts. `list` and `dump` are the
Windows layers and say plainly that they are not built yet.

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
from pathlib import Path

from .aer import ROOT_PORT_TYPES, decode_aer
from .caps import Capability, CapabilityChain, walk_standard_caps
from .extcaps import ExtendedCapability, ExtendedChain, decode_extended_registers, l1ss_summary, ltr_summary, walk_extended_caps
from .header import decode_header
from .msi import decode_msi, decode_msix
from .parse import (
    ConfigSpace,
    ParseError,
    decode_text,
    load_config_space,
    looks_like_lspci_text,
    parse_lspci_all,
    skipped_lspci_blocks,
)
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
    a.add_argument("--json", action="store_true", help="a JSON list, one document per device")

    lst = sub.add_parser("list", help="Windows only: one row per PCI function with link speed/width, no driver")
    lst.add_argument("--json", action="store_true", help="JSON instead of the table")

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
    if c.span < c.structure_length and c.cap_id != 0x10:
        return {"problem": c.problem}
    if c.cap_id == 0x10:
        # PcieCapability stores only offset and registers, so its dict is written by hand: the
        # lspci-line values first (None where a version-1 structure has no such register), then
        # every Register (and its Field list) through asdict. A structure the next capability
        # cuts into is decoded up to the cut, with the problem kept (see render_capabilities).
        p = decode_pcie_capability(cs, c.offset, limit=c.span if c.span < c.structure_length else None)
        return {
            "offset": p.offset,
            "version": p.version,
            "device_port_type": p.device_port_type,
            "device_port_type_name": p.device_port_type_name,
            "structure_length": p.structure_length,
            "problem": c.problem if c.span < c.structure_length else None,
            "link_summary": p.link_summary,
            "speed_downgraded": p.speed_downgraded,
            "width_downgraded": p.width_downgraded,
            "speed_tag": p.speed_tag,
            "width_tag": p.width_tag,
            "current_link_speed_code": p.current_link_speed_code,
            "max_link_speed_code": p.max_link_speed_code,
            "negotiated_link_width": p.negotiated_link_width,
            "max_link_width": p.max_link_width,
            "max_payload_supported_bytes": p.max_payload_supported_bytes,
            "max_payload_bytes": p.max_payload_bytes,
            "max_read_request_bytes": p.max_read_request_bytes,
            "slot_power_limit_watts": p.slot_power_limit_watts,
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


def pcie_facts(cs: ConfigSpace, chain: CapabilityChain | None) -> tuple[int | None, bool, bool]:
    """Three facts the extended capabilities need, all read from the PCI Express capability.

    (Maximum Link Width, is this a Root Port or Event Collector, End-End TLP
    Prefix Supported). The width sizes the per-lane extended structures
    (7.7.3.4, 7.7.5.9, 7.7.7.4); the port type says whether AER's Root Error
    registers at 2Ch-37h apply (7.8.4); Device Capabilities 2 bit 21 (7.5.3.15)
    says whether AER's TLP Prefix Log at 38h-47h exists.
    """
    if chain is None:
        return None, False, False
    pcie = chain.find(0x10)
    if pcie is None or pcie.structure_length is None:
        return None, False, False
    p = decode_pcie_capability(cs, pcie.offset, limit=pcie.span if pcie.span < pcie.structure_length else None)
    width = p.max_link_width if p.has_link_registers else None
    prefix = bool(p.value_or_none("device_capabilities_2", "End-End TLP Prefix Supported"))
    return width, p.device_port_type in ROOT_PORT_TYPES, prefix


def aer_as_json(cs: ConfigSpace, c: ExtendedCapability, is_root: bool, e2e_prefix: bool = False) -> dict | None:
    """The AER structure (spec 7.8.4, extended capability ID 0001h) as a dict, or None when the
    dump holds fewer than the 44 bytes AER needs; the text view prints a [problem] line instead."""
    if c.span < 0x2C:
        return None
    aer = decode_aer(cs, c.offset, is_root, e2e_prefix)
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


def extended_chain_as_json(cs: ConfigSpace, ext: ExtendedChain | None, is_root: bool = False,
                           e2e_prefix: bool = False) -> dict:
    """The extended capability chain (spec 7.6, from 100h) as a dict: the walker's notes, then
    one entry per header with its decoded registers and, for ID 0001h, the AER document."""
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
                "aer": aer_as_json(cs, c, is_root, e2e_prefix) if c.cap_id == 0x0001 else None,
                "structure_data": c.structure_data.hex(),
            }
            for c in ext.entries
        ],
    }


def decode_document(cs: ConfigSpace) -> dict:
    """One function's whole decode as plain dicts, for --json.

    asdict turns each dataclass (and its nested Bit/Bar lists) into dicts and
    lists, the only things json.dumps can write. JSON has no hex literal, so
    4318 here is 0x10DE (a choice; hex strings would be the alternative).
    Properties are not fields, so the derived values are added by name in the
    *_as_json helpers.
    """
    header = decode_header(cs)
    chain = walk_standard_caps(cs) if header.function_present else None
    max_width, is_root, e2e_prefix = pcie_facts(cs, chain)
    ext = walk_extended_caps(cs, max_width, is_root, e2e_prefix) if header.function_present else None
    return {
        "source": cs.source,
        "bdf": cs.bdf,
        "description": cs.description,
        "size": cs.size,
        "frame": cs.frame,
        "header": asdict(header),
        "standard_capabilities": chain_as_json(cs, chain),
        "extended_capabilities": extended_chain_as_json(cs, ext, is_root, e2e_prefix),
    }


def render_device(cs: ConfigSpace, annotate: bool = False, hex_dump: bool = False) -> str:
    """The full text decode of one function: source, header, both chains, then the
    teaching view and the raw bytes when asked (bytes last, like lspci -xxxx)."""
    header = decode_header(cs)
    # Vendor ID FFFFh means no Function (7.5.1.1.1): the bytes are all ones, so 34h is not a
    # pointer and the walk is skipped.
    chain = walk_standard_caps(cs) if header.function_present else None
    max_width, is_root, e2e_prefix = pcie_facts(cs, chain)
    ext = walk_extended_caps(cs, max_width, is_root, e2e_prefix) if header.function_present else None

    parts = ["\n".join(describe_source(cs)), render_header(header)]
    if chain is not None:
        parts.append(render_chain(chain))
        if chain.entries:
            parts.append(render_capabilities(cs, chain))
    if ext is not None:
        parts.append(render_extended_chain(ext))
        if ext.entries:
            parts.append(render_extended_capabilities(cs, ext, is_root, e2e_prefix))
    if annotate and chain is not None:
        parts.append(render_annotated(cs, chain))
        if ext is not None and ext.present:
            parts.append(render_annotated_extended(cs, ext))
    if hex_dump:
        parts.append(render_hex(cs.data))
    parts[0] = parts[0] + "\n" + parts[1]  # the source lines and the header share one block
    del parts[1]
    return "\n\n".join(parts)


def cmd_decode(args: argparse.Namespace) -> int:
    cs = load_config_space(args.file)
    if args.json:
        print(json.dumps(decode_document(cs), indent=2))
    else:
        print(render_device(cs, annotate=args.annotate, hex_dump=args.hex))
    return OK


def cmd_all(args: argparse.Namespace) -> int:
    """Every device in a full `lspci -vvv -xxxx` listing, one after another (or a JSON list)."""
    text = Path(args.file).read_bytes()
    decoded = decode_text(text)
    if decoded is None:
        raise ParseError(f"{args.file}: not text this tool can read (not UTF-8, and no UTF-16 byte order mark)")
    if not looks_like_lspci_text(decoded):
        raise ParseError(f"{args.file}: not an lspci text listing (no hex rows like '00: de 10 89 24'; `lspci -vvv -xxxx` writes them, and -xxxx needs root)")
    devices = parse_lspci_all(decoded, source=str(args.file))
    # A block lspci wrote without hex rows is skipped, and named on stderr: a silent skip
    # would read as "that device is not in the file".
    skipped = skipped_lspci_blocks(decoded)
    if not devices:
        raise ParseError(f"{args.file}: no device with hex rows found")
    if args.json:
        print(json.dumps([decode_document(cs) for cs in devices], indent=2))
        for line in skipped:
            print(f"# skipped, no hex rows: {line}", file=sys.stderr)
        return OK
    for n, cs in enumerate(devices):
        if n:
            print()
            print("=" * 100)
            print()
        print(render_device(cs))
    print(f"\n# {len(devices)} device(s) decoded from {args.file}", file=sys.stderr)
    for line in skipped:
        print(f"# skipped, no hex rows: {line}", file=sys.stderr)
    return OK


def cmd_list(args: argparse.Namespace) -> int:
    """Layer 2: the Windows PnP view of every PCI function (pcicfg/win/enum.py)."""
    from .win.enum import functions_as_json, list_pci_functions, render_list  # imported here: Windows only

    if sys.platform != "win32":
        print("pcicfg list: reads Windows PnP device properties; on Linux use `lspci -vv` (LnkCap / LnkSta lines)", file=sys.stderr)
        return BAD_INPUT
    try:
        functions = list_pci_functions()
    except (RuntimeError, ValueError, OSError) as e:
        print(f"pcicfg list: {e}", file=sys.stderr)
        return BAD_INPUT
    if args.json:
        print(json.dumps(functions_as_json(functions), indent=2))
    else:
        print(render_list(functions))
    return OK


def cmd_dump(args: argparse.Namespace) -> int:
    """Layer 3: raw configuration-space bytes of one Function, then decode them.

    The read needs a kernel driver, because both hardware paths to configuration
    space are ring 0 (see pcicfg/win/raw.py). The security-on path is tried
    first: Microsoft's own signed kldbgdrv.sys, which loads with Memory
    Integrity on and the vulnerable-driver blocklist enforced
    (pcicfg/win/kldbg.py). When it reads, this prints how far each of its two
    reads reached, writes the bytes if -o was given, and decodes them in place.
    When it cannot, it prints what was tried, what stopped it and how else to
    get the bytes, and exits 3 rather than pretending.
    """
    from .win.raw import dump_config_space, parse_bdf, probe_pawnio, report  # imported here: Windows only

    try:
        parse_bdf(args.bdf)
    except ValueError as e:
        print(f"pcicfg dump: {e}", file=sys.stderr)
        return BAD_INPUT

    outcome = dump_config_space(args.bdf)
    if outcome.data is None:
        print(report(probe_pawnio(), args.bdf))
        if args.output:
            print(f"Nothing was written to {args.output}.", file=sys.stderr)
        return NOT_YET

    if args.output:
        Path(args.output).write_bytes(outcome.data)
        print(f"# wrote {len(outcome.data)} bytes to {args.output} via {outcome.method}", file=sys.stderr)
    for line in describe_read(outcome):
        print(line)
    cs = ConfigSpace(data=outcome.data, source=outcome.method, origin="raw image", bdf=args.bdf)
    print(render_device(cs))
    return OK


def describe_read(outcome) -> list[str]:
    """The '# ...' lines saying which access method read the bytes, and how far each reached.

    The question this answers is the one the extended capabilities depend on:
    whether the read got the 256-byte PCI-compatible frame (spec 7.2.1) or the
    full 4096-byte extended frame (spec 7.2.2). Both numbers are measured, not
    assumed: see kldbg.read_config_space.
    """
    lines = [f"# read by {outcome.method}"]
    detail = outcome.detail
    if detail is None:
        return lines
    lines.append(f"# got {detail.size} bytes: {detail.frame}")
    if detail.bus_data_bytes:
        lines.append(f"#   SysDbgReadBusData reached {detail.bus_data_bytes} bytes (HalGetBusDataByOffset)")
    if detail.ecam_address is not None:
        reached = f"reached {detail.physical_bytes} bytes" if detail.physical_bytes else "was refused"
        lines.append(f"#   SysDbgReadPhysical at ECAM 0x{detail.ecam_address:X} {reached}")
    for note in detail.notes:
        lines.append(f"#   note: {note}")
    return lines


def main(argv: list[str] | None = None) -> int:
    # argv=None means "use the real command line"; tests pass a list instead.
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "decode":
            return cmd_decode(args)
        if args.cmd == "all":
            return cmd_all(args)
        if args.cmd == "list":
            return cmd_list(args)
        if args.cmd == "dump":
            return cmd_dump(args)
        print(f"pcicfg {args.cmd}: not built yet", file=sys.stderr)
        return NOT_YET
    except (ParseError, OSError, IndexError) as e:
        # OSError covers a missing file, a directory, or no permission to read.
        # IndexError: a register read past the end of a short dump (ConfigSpace._check in parse.py).
        print(f"pcicfg: {e}", file=sys.stderr)
        return BAD_INPUT
