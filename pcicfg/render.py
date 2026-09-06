"""Text output: the hex view (module 1), the header view (module 2), the
standard capability chain and the --annotate teaching view (module 3), the
register blocks for Power Management, MSI and MSI-X (module 4), one line per
register with the relative offset first and the absolute offset after it,
every register of the PCI Express capability with lspci's LnkSta summary
first (module 5), the extended chain and the decoded extended capabilities
(module 6), and AER (module 7).

The header view lists one line per register: absolute offset, name, raw value
as it sits in the dump (little-endian already flipped), then the decoded
meaning. The layout is a choice made to match how the header was taught:
offset first, so each line can be found in the hex rows. Two more choices:
the revision is always printed, even when it is 00, so the byte at 08h is
always visible (lspci omits a zero revision); and the second DWORD of a
64-bit BAR is printed on the BAR's own line with its absolute offset.
Offsets and pointers print the way the spec writes them, "B4h", uppercase.
"""

from .aer import Aer, decode_aer
from .caps import PCI_COMPATIBLE_END, Capability, CapabilityChain
from .extcaps import (
    EXTENDED_END,
    ExtendedCapability,
    ExtendedChain,
    decode_extended_registers,
    l1ss_summary,
    ltr_summary,
)
from .header import ROM_VALIDATION_STATUS, Bar, Bit, CommonHeader, Type0Header, Type1Header
from .msi import Msi, MsiX, decode_msi, decode_msix
from .parse import ConfigSpace
from .pcie_cap import PcieCapability, Register, decode_pcie_capability
from .pm import PowerManagement, decode_power_management


def render_hex(data: bytes, base: int = 0) -> str:
    """Bytes, 16 per row, labeled the way `lspci -xxxx` labels them.

    `base` is the absolute offset of data[0]. With base=0 on a whole dump this
    reproduces lspci's hex block byte for byte ("00:" ... "ff0:").
    """
    rows = []
    for i in range(0, len(data), 16):  # i = index of each row's first byte: 0, 16, 32, ...
        chunk = data[i : i + 16]
        # :02x = lowercase hex, at least 2 digits, zero-padded ("0a" not "a").
        # Labels 0x100 and up grow to 3 digits by themselves, matching lspci's "100:" ... "ff0:".
        label = f"{base + i:02x}:"
        rows.append(label + " " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(rows)


def render_hex_rebased(data: bytes, start: int) -> str:
    """A capability's bytes with labels restarting at 00 (relative offsets, the way it was
    taught), and the absolute offset of each row at the end so nobody has to add by hand.
    """
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        body = " ".join(f"{b:02x}" for b in chunk)
        # :<47 pads a full 16-byte row (47 characters) so the absolute note lines up.
        rows.append(f"{i:02x}: {body:<47} | absolute {start + i:02X}h")
    return "\n".join(rows)


def set_bits(bits: list[Bit]) -> str:
    """The names of the bits that are 1, comma-separated, or 'none'."""
    names = [b.name for b in bits if b.set]
    return ", ".join(names) if names else "none"


def _line(offset: int, name: str, raw: str, meaning: str = "") -> str:
    # Offsets print as the spec writes them: two uppercase hex digits and an h, "0Ch".
    # :<18 pads the name to 18 characters so the columns line up.
    return f"  {offset:02X}h {name:<18} {raw:<20} {meaning}".rstrip()


def render_bar(bar: Bar) -> str:
    raw = f"{bar.raw:08x}"
    if bar.upper_raw is not None:
        # The upper DWORD of a 64-bit BAR, shown with its own absolute offset (base + 4).
        raw += f" {bar.offset + 4:02X}h:{bar.upper_raw:08x}"
    if bar.kind == "empty":
        meaning = "reads as zero: unimplemented, or not assigned"
    elif bar.kind == "io":
        meaning = f"I/O ports at {bar.address:x}; {bar.size_note}"
    else:
        pf = "prefetchable" if bar.prefetchable else "non-prefetchable"
        meaning = f"Memory at {bar.address:x} ({bar.width}-bit, {pf}); {bar.size_note}"
    if bar.problem:
        meaning += f" [problem: {bar.problem}]"
    return _line(bar.offset, f"BAR{bar.index}", raw, meaning)


def render_headline(h: CommonHeader) -> str:
    """The lspci-style first line: class: vendor device (rev), plus the prog-if name if known."""
    line = f"{h.class_name}: {h.vendor_name} {h.device_name} (rev {h.revision_id:02x})"
    if h.prog_if_name:
        line += f" (prog-if {h.prog_if:02x} [{h.prog_if_name}])"
    return line


def render_common(h: CommonHeader) -> list[str]:
    cache_bytes = h.cache_line_size * 4  # DWORDs -> bytes
    layout = h.layout_name + (", multi-function" if h.multi_function else "")
    return [
        _line(0x00, "Vendor ID", f"{h.vendor_id:04x}", h.vendor_name),
        _line(0x02, "Device ID", f"{h.device_id:04x}", h.device_name),
        _line(0x04, "Command", f"{h.command:04x}", "set: " + set_bits(h.command_bits)),
        _line(0x06, "Status", f"{h.status:04x}", "set: " + set_bits(h.status_bits)),
        _line(0x08, "Revision ID", f"{h.revision_id:02x}"),
        _line(
            0x09,
            "Class Code",
            f"{h.class_code:06x}",
            f"{h.class_name} (base {h.base_class:02x}, sub {h.sub_class:02x}, prog-if {h.prog_if:02x})",
        ),
        _line(0x0C, "Cache Line Size", f"{h.cache_line_size:02x}", f"{h.cache_line_size} DWORDs = {cache_bytes} bytes"),
        _line(0x0D, "Latency Timer", f"{h.latency_timer:02x}"),
        _line(0x0E, "Header Type", f"{h.header_type:02x}", layout),
        _line(0x0F, "BIST", f"{h.bist:02x}"),
    ]


def render_tail(h: CommonHeader) -> list[str]:
    cap_note = ""
    if h.capabilities_pointer_raw != h.capabilities_pointer:
        cap_note = f"-> {h.capabilities_pointer:02X}h (bits 1:0 are reserved, masked off per 7.5.1.1.11)"
    if not h.has_capabilities_list:
        cap_note = (cap_note + " (Status bit 4 clear: no capability list)").strip()
    line_note = ""
    if h.interrupt_line == 0xFF:
        # A PCI convention kept by Linux, not PCIe 5.0 spec text; lspci's "routed to IRQ N"
        # comes from the kernel's own assignment, not from this byte.
        line_note = "ff = unknown / no connection (PCI convention)"
    return [
        _line(0x34, "Capabilities Ptr", f"{h.capabilities_pointer_raw:02x}", cap_note),
        _line(0x3C, "Interrupt Line", f"{h.interrupt_line:02x}", line_note),
        _line(0x3D, "Interrupt Pin", f"{h.interrupt_pin:02x}", h.interrupt_pin_name),
    ]


def render_expansion_rom(h: Type0Header) -> str:
    if h.expansion_rom == 0:
        meaning = "reads as zero: no Expansion ROM, or not assigned"
    else:
        state = "enabled" if h.expansion_rom_enabled else "disabled"
        meaning = f"at {h.expansion_rom_address:x}, {state}"
        if h.expansion_rom_validation_status:
            status = ROM_VALIDATION_STATUS[h.expansion_rom_validation_status]
            meaning += f"; {status} (details {h.expansion_rom_validation_details:x})"
    return _line(0x30, "Expansion ROM", f"{h.expansion_rom:08x}", meaning)


def render_header(h: Type0Header | Type1Header) -> str:
    lines = [render_headline(h)]
    if not h.function_present:
        lines.append(
            "Vendor ID FFFFh: no Function is present (spec 7.5.1.1.1). These bytes are the "
            "all-ones response of an empty slot or an unpowered device, not device state."
        )
        lines += render_common(h)
        return "\n".join(lines)
    # isinstance: which of the two header classes decode_header built.
    if isinstance(h, Type0Header):
        if h.layout_is_defined:
            lines.append("Type 0 header (spec 7.5.1.1, 7.5.1.2)  [taught]")
        else:
            lines.append(
                f"Header Layout {h.header_layout:02x}h is reserved (spec 7.5.1.1.9 defines only 0 and 1); "
                "00h-0Fh, 34h, 3Ch, 3Dh are common fields, 10h-3Fh are shown with Type 0 names as a guess"
            )
        lines += render_common(h)
        lines += [render_bar(b) for b in h.bars]
        lines += [
            _line(0x28, "Cardbus CIS", f"{h.cardbus_cis:08x}"),
            _line(
                0x2C,
                "Subsystem",
                f"{h.subsystem_vendor_id:04x}:{h.subsystem_id:04x}",
                f"{h.subsystem_vendor_name} {h.subsystem_name}",
            ),
            render_expansion_rom(h),
        ]
        lines += render_tail(h)
        lines.append(_line(0x3E, "Min_Gnt/Max_Lat", f"{h.min_gnt:02x} {h.max_lat:02x}", "legacy PCI, hardwired 0"))
    else:
        lines.append(
            "Type 1 header (spec 7.5.1.3)  [ahead: common fields, two BARs and the bus numbers only; "
            "the I/O, memory and prefetchable windows, Secondary Status, Bridge Control and the ROM at 38h "
            "are not decoded]"
        )
        lines += render_common(h)
        lines += [render_bar(b) for b in h.bars]
        lines += [
            _line(0x18, "Primary Bus", f"{h.primary_bus:02x}", "legacy: upstream bus; PCIe functions do not use it (7.5.1.3.2)"),
            _line(0x19, "Secondary Bus", f"{h.secondary_bus:02x}", "the bus directly behind the bridge"),
            _line(0x1A, "Subordinate Bus", f"{h.subordinate_bus:02x}", "the highest bus number behind it"),
        ]
        lines += render_tail(h)
    return "\n".join(lines)


# --- module 3: the standard capability chain -------------------------------------

def ahead_tag(c: Capability) -> str:
    """'' for a capability Aidan has worked through by hand, else the [ahead] marker (CLAUDE.md rule 5).

    'Ahead' means ahead of what he can explain, not ahead of what the tool decodes.
    """
    return "" if c.taught else "[ahead: decoded by the tool, not yet worked through by hand]"


def describe_capability(c: Capability) -> str:
    """'Vendor Specific (length 14h)': the name plus what the header bytes add."""
    text = c.name
    if c.vendor_specific_length is not None:
        text += f" (length {c.vendor_specific_length:02X}h)"
    return text


def span_text(c: Capability) -> str:
    """'60 bytes to the next start at B4h' or '76 bytes to 100h, the end of the PCI-compatible space'."""
    if c.end >= PCI_COMPATIBLE_END:
        return f"{c.span} bytes to 100h, the end of the PCI-compatible space"
    return f"{c.span} bytes to the next start at {c.end:02X}h"


def structure_text(c: Capability) -> str:
    """'structure 8 bytes (spec)' when the spec fixes, or the capability tells, its size."""
    length = c.structure_length
    if length is None:
        return "structure size: set by its own registers"
    if c.cap_id == 0x09:
        return f"structure {length} bytes (declared, Table 7-160)"
    if c.cap_id == 0x05:
        return f"structure {length} bytes (DWORDs of Figures 7-44 to 7-47 per Message Control; a count, the spec gives no byte size)"
    if c.cap_id == 0x10:
        return f"structure {length} bytes (by Capability Version and port type; a choice of this tool, see pcie_cap.py)"
    return f"structure {length} bytes (spec)"


def render_chain(chain: CapabilityChain) -> str:
    """One line per entry, in link order: offset, ID byte, name, next pointer, span, structure, tag."""
    lines = [
        f"Standard capability chain (spec 7.5.1.1.11; Capabilities Pointer 34h = {chain.pointer:02X}h)  [taught]"
    ]
    for c in chain.entries:
        end = "end of list" if c.next_pointer == 0 else f"next {c.next_pointer:02X}h"
        # :<32 and :<12 pad the name and the next-pointer column so the lines line up
        # (same idea as :<18 in _line).
        lines.append(
            f"  {c.offset:02X}h  ID {c.cap_id:02x}  {describe_capability(c):<32} {end:<12} "
            f"{span_text(c)}; {structure_text(c)}  {ahead_tag(c)}".rstrip()
        )
        if c.problem:
            lines.append(f"        [problem: {c.problem}]")
    if chain.has_list and chain.pointer == 0 and not chain.entries:
        lines.append("  (empty: the Capabilities Pointer is 00h)")
    for note in chain.notes:
        lines.append(f"  note: {note}")
    return "\n".join(lines)


def render_annotated(cs: ConfigSpace, chain: CapabilityChain) -> str:
    """The teaching view: hex rows 00h-FFh with each capability's start marked,
    then every capability printed again from 00 (relative offsets).

    A marker line sits under the row: ^^ under the ID byte, then the absolute
    offset, the name, and the next pointer. In the rebased blocks the labels
    restart at 00 and every row ends with its absolute offset, so a register at
    "PCIe capability offset 12h" is on row 10:, third byte, absolute 8Ah.
    """
    end = min(cs.size, PCI_COMPATIBLE_END)
    title = f"Annotated PCI-compatible space 00h-{end - 1:02X}h (256-byte frame, spec 7.2.1)"
    if end < PCI_COMPATIBLE_END:
        title += "; the dump stops here"
    elif cs.size > PCI_COMPATIBLE_END:
        title += "; the extended chain (100h-FFFh, spec 7.6) follows below"
    else:
        title += "; this dump has no extended space"
    lines = [title]
    # A lookup table offset -> Capability, so the loop can ask "does a capability start here?"
    starts = {c.offset: c for c in chain.entries}
    for row_start in range(0, end, 16):
        lines.append(render_hex(cs.data[row_start : row_start + 16], base=row_start))
        for off in range(row_start, row_start + 16):
            if off in starts:
                c = starts[off]
                # column of byte k in a row: the "xx: " label is 4 characters, then 3 per byte
                col = 4 + 3 * (off - row_start)
                nxt = "end" if c.next_pointer == 0 else f"next {c.next_pointer:02X}h"
                lines.append(" " * col + f"^^ {off:02X}h: {c.name} (ID {c.cap_id:02x}, {nxt}) {ahead_tag(c)}".rstrip())
    # Blocks in address order (lowest offset first) so they read top to bottom like the hex
    # rows; render_chain keeps link order. key=lambda tells sorted which number to compare.
    for c in sorted(chain.entries, key=lambda cap: cap.offset):
        lines.append("")
        lines.append(
            f"== {c.offset:02X}h {c.name}: {structure_text(c)}; {span_text(c)}; "
            f"printed from 00 (relative offsets; add {c.offset:02X}h for the absolute offset) == {ahead_tag(c)}".rstrip()
        )
        lines.append(render_hex_rebased(c.structure_data, c.offset))
        extra = c.span - len(c.structure_data)
        if extra > 0:
            lines.append(
                f"   + {extra} more bytes up to {c.end:02X}h are not part of this structure "
                "(see the hex rows above)"
            )
    return "\n".join(lines)


# --- module 5: the PCI Express capability ----------------------------------------------

def is_reserved_field(name: str) -> bool:
    """Fields the spec marks reserved or undefined; render_register_lines hides them when 0.

    The double parentheses hand startswith a tuple: true if the name starts with any one of them.
    """
    return name.startswith(("RsvdP", "RsvdZ", "Reserved", "Undefined"))


def name_pad(registers, floor: int = 18) -> int:
    """Width of the register-name column: the longest name in this block, never below `floor`.

    Per block, not one number for the whole tool: the AER names run to 28 characters and the
    Power Management ones to 18, so a single width would leave one block far too wide.
    """
    return max([floor] + [len(r.name) for r in registers])


def render_register_lines(base: int, r: Register, collapse_note: str = "", pad: int = 22) -> list[str]:
    """The register's own line (relative and absolute offset, raw), then one line per field.

    Reserved and undefined fields print only when they are not zero. With a
    collapse_note and a raw value of zero the register is one line only.
    """
    digits = r.width // 4  # 4 bits per hex digit; the inner {digits} in the f-string is filled first, giving :04x or :08x
    head = _rline(base, r.offset, r.name, f"{r.raw:0{digits}x}", f"spec {r.section}", pad)
    if collapse_note and r.raw == 0:
        return [head + f"; {collapse_note}"]
    lines = [head]
    for f in r.fields:
        if is_reserved_field(f.name) and f.value == 0:
            continue
        note = f"  ({f.note})" if f.note else ""
        # :<6 pads the bit range, :<50 the name, so the value and meaning columns line up.
        lines.append(f"        {f.bits_label:<6} {f.name:<50} {f.value:<5} {f.text}{note}".rstrip())
    return lines


def render_register(p: PcieCapability, r: Register, pad: int = 22) -> list[str]:
    """A PCIe capability register, one line per field.

    Registers the spec says this Function type does not implement (page 718:
    hardwired 0b) collapse to one line when they read zero: the Slot registers
    unless this is a Downstream Port with Slot Implemented set, the Root
    registers unless this is a Root Port or Event Collector. The placeholder
    Device Status 2 collapses the same way. Any non-zero register prints in
    full whatever the type. Omitting the bit names there is a choice; --json
    lists them.
    """
    port_type = p.device_port_type
    has_slot = port_type in (4, 6) and p.register("pcie_capabilities").is_set("Slot Implemented")
    is_root = port_type in (4, 10)
    if r.key.startswith("slot_") and not has_slot:
        return render_register_lines(p.offset, r, "Downstream Ports with a slot only (Slot Implemented = 0 here); bit names omitted, a choice", pad)
    if r.key.startswith("root_") and not is_root:
        return render_register_lines(p.offset, r, "Root Ports and Root Complex Event Collectors only; bit names omitted, a choice", pad)
    if r.key in ("device_status_2", "slot_control_2", "slot_status_2"):
        return render_register_lines(p.offset, r, "placeholder register", pad)
    return render_register_lines(p.offset, r, pad=pad)


def render_pcie_capability(p: PcieCapability) -> list[str]:
    lines = []
    if p.has_link_registers:
        lines.append(f"  Link: {p.link_summary}   (lspci's LnkSta line; 'downgraded' = below Link Capabilities, not said for Downstream Ports)")
    pad = name_pad(p.registers)
    for r in p.registers:
        lines += render_register(p, r, pad)
    return lines


# --- module 6: the extended chain ------------------------------------------------------

def ext_ahead_tag(c: ExtendedCapability) -> str:
    return "" if c.taught else "[ahead: decoded by the tool, not yet worked through by hand]"


def ext_span_text(c: ExtendedCapability) -> str:
    if c.end >= EXTENDED_END:
        return f"{c.span} bytes to 1000h, the end of the ECAM frame"
    return f"{c.span} bytes to the next start at {c.end:03X}h"


def ext_structure_text(c: ExtendedCapability) -> str:
    if c.structure_length is None:
        return "structure size: not known to this tool"
    if c.cap_id == 0x000B:
        return f"structure {c.structure_length} bytes (VSEC Length, declared)"
    if c.cap_id in (0x0019, 0x0026, 0x0027):
        return f"structure {c.structure_length} bytes (from the lane count)"
    return f"structure {c.structure_length} bytes (spec layout)"


def render_extended_chain(chain: ExtendedChain) -> str:
    """One line per header, in link order: offset, ID, version, name, next, span, structure, tag."""
    lines = ["Extended capability chain (spec 7.6.1, 7.6.3; starts at 100h, one DWORD header each)  [taught]"]
    for c in chain.entries:
        end = "end of list" if c.next_offset == 0 else f"next {c.next_masked:03X}h"
        lines.append(
            f"  {c.offset:03X}h  ID {c.cap_id:04x} v{c.version}  {c.name:<44} {end:<12} "
            f"{ext_span_text(c)}; {ext_structure_text(c)}  {ext_ahead_tag(c)}".rstrip()
        )
        if c.problem:
            lines.append(f"        [problem: {c.problem}]")
    for note in chain.notes:
        lines.append(f"  note: {note}")
    return "\n".join(lines)


def render_aer(aer: Aer) -> list[str]:
    """AER (module 7): a one-line health summary, every register, and the Header Log as
    lspci prints it (four DWORDs, header byte 0 in the top byte of the first, 7.8.4.8)."""
    lines = [f"  summary: {aer.summary}"]
    pad = name_pad(aer.registers)
    if not aer.severity_is_spec_default:
        lines.append("  note: Uncorrectable Error Severity differs from the spec 5.0 default 00462030h (Table 7-102)")
    for r in aer.registers:
        lines += render_register_lines(aer.offset, r, pad=pad)
        if r.key == "caps_control":
            log = " ".join(f"{dw:08x}" for dw in aer.header_log)
            lines.append(_rline(aer.offset, 0x1C, "Header Log", "", f"{log}  (four DWORDs; header byte 0 is the top byte of the first, 7.8.4.8; spec 7.8.4.8)", pad))
    if not aer.is_root:
        lines.append(_rline(aer.offset, 0x2C, "Root Error regs", "", "2Ch-37h: Root Ports and Root Complex Event Collectors only; read zero on this Function", pad))
    if aer.tlp_prefix_log is not None:
        log = " ".join(f"{dw:08x}" for dw in aer.tlp_prefix_log)
        lines.append(_rline(aer.offset, 0x38, "TLP Prefix Log", "", f"{log}  (spec 7.8.4.12)", pad))
    return lines


def render_extended_capabilities(cs: ConfigSpace, chain: ExtendedChain, is_root: bool = False) -> str:
    """Every extended capability: header line, decoded registers where this tool has them,
    otherwise the header and up to 64 bytes of the structure, printed from 00."""
    lines = []
    for c in chain.entries:
        lines.append("")
        detail = f"ID {c.cap_id:04x} v{c.version}, header {c.header:08x}"
        if c.structure_length is not None:
            detail += f", {c.structure_length} bytes"
        lines.append(f"-- {c.offset:03X}h {c.name} ({detail})  {ext_ahead_tag(c)}".rstrip())
        if c.problem:
            lines.append(f"  [problem: {c.problem}]")
        if c.cap_id == 0x0001:
            if c.span < 0x2C:
                lines.append(f"  [problem: only {c.span} bytes before the next start; AER needs 44]")
                continue
            lines += render_aer(decode_aer(cs, c.offset, is_root))
            continue
        summary = ltr_summary(cs, c) or l1ss_summary(cs, c)
        if summary:
            lines.append(f"  summary: {summary}")
        regs = decode_extended_registers(cs, c)
        if regs:
            registers = regs
            for r in regs:
                lines += render_register_lines(c.offset, r, pad=name_pad(registers))
        else:
            shown = c.structure_data[:64]
            lines.append(f"  header only; first {len(shown)} bytes of the structure, printed from 00 (add {c.offset:03X}h for the absolute offset):")
            lines.append(render_hex_rebased(shown, c.offset))
            if len(shown) < len(c.structure_data):
                lines.append(f"   + {len(c.structure_data) - len(shown)} more bytes not shown (see --hex)")
    return "\n".join(lines).lstrip("\n")


def render_annotated_extended(cs: ConfigSpace, chain: ExtendedChain) -> str:
    """The teaching view for the extended space: where each header sits, then each capability
    printed from 00 with the absolute offset on every row."""
    lines = ["Annotated extended space (100h-FFFh, ECAM frame, spec 7.2.2; headers per spec 7.6.3)"]
    for c in sorted(chain.entries, key=lambda cap: cap.offset):
        nxt = "end" if c.next_offset == 0 else f"next {c.next_masked:03X}h"
        lines.append(f"  {c.offset:03X}h: {c.name} (ID {c.cap_id:04x} v{c.version}, {nxt}) {ext_ahead_tag(c)}".rstrip())
    for c in sorted(chain.entries, key=lambda cap: cap.offset):
        block = c.structure_data if c.structure_length is not None else c.data[:64]
        lines.append("")
        lines.append(
            f"== {c.offset:03X}h {c.name}: {ext_structure_text(c)}; {ext_span_text(c)}; "
            f"printed from 00 (relative offsets; add {c.offset:03X}h for the absolute offset) == {ext_ahead_tag(c)}".rstrip()
        )
        lines.append(render_hex_rebased(block, c.offset))
        if len(block) < c.span:
            lines.append(f"   + {c.span - len(block)} more bytes up to {c.end:03X}h not shown (see --hex)")
    for note in chain.notes:
        lines.append(f"  note: {note}")
    return "\n".join(lines)


# --- module 4: Power Management, MSI, MSI-X ----------------------------------------

def plus_minus(flag: bool) -> str:
    """lspci's convention: '+' when a bit is set, '-' when clear."""
    return "+" if flag else "-"


def _rline(cap_offset: int, rel: int, name: str, raw: str, meaning: str = "", pad: int = 22) -> str:
    """One capability register: relative offset first, absolute in parentheses, then raw and meaning."""
    # The nested {pad} is filled first, so :<22 pads the name to that many characters (the widest
    # name in this block, see name_pad); :<10 pads the raw value.
    return f"  +{rel:02X}h ({cap_offset + rel:02X}h) {name:<{pad}} {raw:<10} {meaning}".rstrip()


def cap_heading(c: Capability, detail: str) -> str:
    """The block title: '-- 40h Power Management (ID 01, spec 7.5.2, 8 bytes)  [ahead: ...]'."""
    return f"-- {c.offset:02X}h {c.name} (ID {c.cap_id:02x}, {detail})  {ahead_tag(c)}".rstrip()


def vector_text(count: int | None, code: int) -> str:
    """'32' for a valid code, or 'reserved code 6' (Table 7-39 defines 000b-101b only)."""
    return str(count) if count is not None else f"reserved code {code}"


def bir_text(bir: int, bar_offset: int | None) -> str:
    """'BIR 0 = BAR at 10h', or 'BIR 6 (reserved code)' for the two codes Table 7-48 reserves."""
    return f"BIR {bir} = BAR at {bar_offset:02X}h" if bar_offset is not None else f"BIR {bir} (reserved code)"


def render_power_management(pm: PowerManagement) -> list[str]:
    pme = ", ".join(pm.pme_states) or "none"  # an empty list joins to "", which counts as false, so `or` gives "none"
    version = f"version {pm.version}" + ("" if pm.version == 3 else " (spec requires 011b = 3)")
    pmc_meaning = (
        f"{version}; PME Clock{plus_minus(pm.pme_clock)}; "
        f"Immediate Readiness on Return to D0{plus_minus(pm.immediate_readiness)}; "
        f"DSI{plus_minus(pm.dsi)}; Aux current {pm.aux_current_ma} mA; D1{plus_minus(pm.d1_support)}; "
        f"D2{plus_minus(pm.d2_support)}; PME from: {pme}"
    )
    if pm.data_register_present:
        data_text = (
            f"Data_Select {pm.data_select} ({pm.data_select_name}); "
            f"Data_Scale {pm.data_scale} ({pm.data_scale_name})"
        )
    else:
        data_text = "Data_Select 0, Data_Scale 0: Data register reads 00 (not implemented, or nothing selected; 7.5.2.3)"
    pmcsr_meaning = (
        f"{pm.power_state_name}; No Soft Reset{plus_minus(pm.no_soft_reset)}; PME_En{plus_minus(pm.pme_enable)}; "
        f"{data_text}; PME_Status{plus_minus(pm.pme_status)}"
    )
    return [
        _rline(pm.offset, 0x02, "PMC", f"{pm.pmc:04x}", pmc_meaning),
        _rline(pm.offset, 0x04, "PMCSR", f"{pm.pmcsr:04x}", pmcsr_meaning),
        _rline(
            pm.offset, 0x06, "Reserved", f"{pm.reserved_byte:02x}",
            "bits 5:0 RsvdP, 7:6 undefined (Table 7-14 DWORD bits 21:16 / 23:22; pci_regs.h names 7:6 PPB_B2_B3 / BPCC_ENABLE)",
        ),
        _rline(pm.offset, 0x07, "Data", f"{pm.data:02x}", "optional; 00 when not implemented"),
    ]


def render_msi(m: Msi) -> list[str]:
    control = (
        f"Enable{plus_minus(m.enable)}; "
        f"{vector_text(m.vectors_enabled, m.multiple_message_enable)} of "
        f"{vector_text(m.vectors_capable, m.multiple_message_capable)} vectors "
        f"(codes {m.multiple_message_enable}/{m.multiple_message_capable}, 2^code); "
        f"64-bit Address{plus_minus(m.address_64bit)}; Per-Vector Masking{plus_minus(m.per_vector_masking)}; "
        f"Extended Message Data capable{plus_minus(m.extended_data_capable)} enable{plus_minus(m.extended_data_enable)}"
    )
    if m.problem:
        control += f" [problem: {m.problem}]"
    lines = [
        _rline(m.offset, 0x02, "Message Control", f"{m.message_control:04x}", control),
        _rline(m.offset, 0x04, "Message Address", f"{m.message_address:08x}", "bits 31:2; DWORD aligned"),
    ]
    if m.message_upper_address is not None:
        lines.append(
            _rline(m.offset, 0x08, "Message Upper Addr", f"{m.message_upper_address:08x}",
                   f"bits 63:32 -> full address {m.full_address:016x}")
        )
    if m.extended_data_capable:
        high = f"Extended Message Data (high 16 bits) {m.extended_message_data:04x}"
    else:
        # 7.7.1.6: without the capability those bits are not a register: undefined (no
        # masking) or RsvdP (with masking).
        high = f"high 16 bits {m.extended_message_data:04x}: not Extended Message Data Capable, so undefined here (7.7.1.6)"
    lines.append(_rline(m.offset, m.data_offset, "Message Data", f"{m.message_data:04x}", f"low 16 bits of the DWORD; {high}"))
    if m.per_vector_masking:
        lines.append(_rline(m.offset, m.mask_offset, "Mask Bits", f"{m.mask_bits:08x}", "bit n = vector n masked"))
        lines.append(_rline(m.offset, m.pending_offset, "Pending Bits", f"{m.pending_bits:08x}", "bit n = vector n pending"))
    return lines


def render_msix(x: MsiX) -> list[str]:
    return [
        _rline(x.offset, 0x02, "Message Control", f"{x.message_control:04x}",
               f"Enable{plus_minus(x.enable)}; Function Mask{plus_minus(x.function_mask)}; "
               f"Table Size code {x.table_size_code} = {x.table_size} entries"),
        _rline(x.offset, 0x04, "Table Offset/BIR", f"{x.table_register:08x}",
               f"{bir_text(x.table_bir, x.table_bar_offset)}, offset {x.table_offset:x}h (the table is in memory space)"),
        _rline(x.offset, 0x08, "PBA Offset/BIR", f"{x.pba_register:08x}",
               f"{bir_text(x.pba_bir, x.pba_bar_offset)}, offset {x.pba_offset:x}h"),
    ]


def render_capabilities(cs: ConfigSpace, chain: CapabilityChain) -> str:
    """Every chain entry's registers, in link order; entries without a decoder yet say so."""
    lines = []
    for c in chain.entries:
        lines.append("")
        length = c.structure_length
        does_not_fit = length is not None and c.span < length
        if c.cap_id == 0x01:
            if does_not_fit:
                lines.append(cap_heading(c, "spec 7.5.2") + f"\n  [problem: {c.problem}]")
                continue
            lines.append(cap_heading(c, "spec 7.5.2, 8 bytes"))
            lines += render_power_management(decode_power_management(cs, c.offset))
        elif c.cap_id == 0x05:
            if length is None:
                # Only for a hand-built dump: fewer than 4 bytes, so Message Control (bytes 2-3)
                # could not be read. The three real frames always have at least 4.
                lines.append(cap_heading(c, "spec 7.7.1") + f"\n  [problem: only {c.span} bytes; Message Control at +02h cannot be read]")
                continue
            if does_not_fit:
                lines.append(cap_heading(c, "spec 7.7.1") + f"\n  [problem: {c.problem}]")
                continue
            m = decode_msi(cs, c.offset)
            width = "64" if m.address_64bit else "32"
            masking = "with" if m.per_vector_masking else "no"
            lines.append(cap_heading(c, f"spec 7.7.1, {m.structure_length} bytes by DWORD count: {width}-bit address, {masking} per-vector masking"))
            lines += render_msi(m)
        elif c.cap_id == 0x11:
            if does_not_fit:
                lines.append(cap_heading(c, "spec 7.7.2") + f"\n  [problem: {c.problem}]")
                continue
            lines.append(cap_heading(c, "spec 7.7.2, 12 bytes"))
            lines += render_msix(decode_msix(cs, c.offset))
        elif c.cap_id == 0x10:
            if length is None:
                lines.append(cap_heading(c, "spec 7.5.3") + "\n  [problem: PCI Express Capabilities register at +02h cannot be read]")
                continue
            # A structure the next capability cuts into still has readable registers up to
            # the cut (Linux ends a version-2 Endpoint at +34h, so a dump laid out that way is
            # not wrong): decode what fits and say what was left out.
            p = decode_pcie_capability(cs, c.offset, limit=c.span if does_not_fit else None)
            lines.append(cap_heading(c, f"spec 7.5.3, {p.structure_length} bytes: version {p.version}, {p.device_port_type_name}"))
            if does_not_fit:
                lines.append(f"  [problem: {c.problem}; only the {len(p.registers)} registers inside the {c.span}-byte span are decoded]")
            lines += render_pcie_capability(p)
        elif c.cap_id == 0x09:
            lines.append(cap_heading(c, "spec 7.9.4, vendor-defined bytes after the 3-byte header"))
            lines.append(render_hex_rebased(c.structure_data, c.offset))
        else:
            lines.append(cap_heading(c, "no decoder in this tool") + "\n  bytes only:")
            lines.append(render_hex_rebased(c.structure_data, c.offset))
    # The loop puts a blank line before every block; drop the one before the first.
    return "\n".join(lines).lstrip("\n")
