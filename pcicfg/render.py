"""Text output: the hex view (module 1), the header view (module 2), the
standard capability chain and the --annotate teaching view (module 3).

The header view lists one line per register: absolute offset, name, raw value
as it sits in the dump (little-endian already flipped), then the decoded
meaning. The layout is a choice made to match how the header was taught:
offset first, so each line can be found in the hex rows. Two more choices:
the revision is always printed, even when it is 00, so the byte at 08h is
always visible (lspci omits a zero revision); and the second DWORD of a
64-bit BAR is printed on the BAR's own line with its absolute offset.
"""

from .caps import Capability, CapabilityChain
from .header import ROM_VALIDATION_STATUS, Bar, Bit, CommonHeader, Type0Header, Type1Header
from .parse import ConfigSpace


def render_hex(data: bytes, base: int = 0) -> str:
    """Bytes, 16 per row, labeled the way `lspci -xxxx` labels them.

    `base` is the absolute offset of data[0]. With base=0 on a whole dump this
    reproduces lspci's hex block byte for byte ("00:" ... "ff0:"). --annotate
    reuses it with base=0 on a capability's own bytes so that capability
    reads from 00 again (relative offsets), the way it was taught.
    """
    rows = []
    for i in range(0, len(data), 16):  # i = index of each row's first byte: 0, 16, 32, ...
        chunk = data[i : i + 16]
        # :02x = lowercase hex, at least 2 digits, zero-padded ("0a" not "a").
        # Labels 0x100 and up grow to 3 digits by themselves, matching lspci's "100:" ... "ff0:".
        label = f"{base + i:02x}:"
        rows.append(label + " " + " ".join(f"{b:02x}" for b in chunk))
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
        cap_note = f"-> {h.capabilities_pointer:02x}h (bits 1:0 are reserved, masked off per 7.5.1.1.11)"
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

def describe_capability(c: Capability) -> str:
    """'Power Management' plus what the header bytes add: a Vendor-Specific length, or a problem."""
    text = c.name
    if c.vendor_specific_length is not None:
        text += f" (length {c.vendor_specific_length:02x}h)"
    if c.problem:
        text += f" [problem: {c.problem}]"
    return text


def render_chain(chain: CapabilityChain) -> str:
    """One line per entry, in link order: offset, ID byte, name, next pointer, span, tag."""
    lines = [
        f"Standard capability chain (spec 7.5.1.1.11; Capabilities Pointer 34h = {chain.pointer:02x}h)  [taught]"
    ]
    for c in chain.entries:
        end = "end of list" if c.next_pointer == 0 else f"next {c.next_pointer:02x}h"
        tag = "" if c.taught else "[ahead: registers not yet decoded by hand]"
        lines.append(
            f"  {c.offset:02X}h  ID {c.cap_id:02x}  {describe_capability(c):<40} {end:<12} {c.span:3d} bytes to the next start  {tag}".rstrip()
        )
    if not chain.entries and not chain.notes:
        lines.append("  (empty: the Capabilities Pointer is 00h)")
    for note in chain.notes:
        lines.append(f"  note: {note}")
    return "\n".join(lines)


def render_annotated(cs: ConfigSpace, chain: CapabilityChain) -> str:
    """The teaching view: hex rows 00h-FFh with each capability's start marked,
    then every capability printed again from 00 (relative offsets).

    A marker line sits under the row: ^^ under the ID byte, then the absolute
    offset, the name, and the next pointer. In the rebased block the labels
    restart at 00, so a register at "PCIe capability offset 12h" is on row 10:,
    third byte; add the capability's start for the absolute offset.
    """
    lines = ["Annotated PCI-compatible space (00h-FFh); the extended space at 100h is the extended chain (extcaps)"]
    starts = {c.offset: c for c in chain.entries}
    end = min(cs.size, 0x100)
    for row_start in range(0, end, 16):
        row = render_hex(cs.data[row_start : row_start + 16], base=row_start)
        lines.append(row)
        for off in range(row_start, row_start + 16):
            if off in starts:
                c = starts[off]
                # column of byte k in a row: the "xx: " label is 4 characters, then 3 per byte
                col = 4 + 3 * (off - row_start)
                nxt = "end" if c.next_pointer == 0 else f"next {c.next_pointer:02x}h"
                lines.append(" " * col + f"^^ {off:02X}h: {c.name} (ID {c.cap_id:02x}, {nxt})")
    for c in sorted(chain.entries, key=lambda c: c.offset):
        lines.append("")
        lines.append(
            f"== {c.offset:02X}h {c.name}: {c.span} bytes, printed from 00 "
            f"(relative offsets; add {c.offset:02X}h for the absolute offset) =="
        )
        lines.append(render_hex(c.data, base=0))
    return "\n".join(lines)
