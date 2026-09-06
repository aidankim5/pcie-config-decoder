"""Text output: the hex view (module 1) and the header view (module 2).

The header view lists one line per register: absolute offset, name, raw value
as it sits in the dump (little-endian already flipped), then the decoded
meaning. The layout is a choice made to match how the header was taught:
offset first, so each line can be found in the hex rows.
"""

from .header import Bar, Bit, CommonHeader, Type0Header, Type1Header


def render_hex(data: bytes, base: int = 0) -> str:
    """Bytes, 16 per row, labeled the way `lspci -xxxx` labels them.

    `base` is the absolute offset of data[0]. With base=0 on a whole dump this
    reproduces lspci's hex block byte for byte ("00:" ... "ff0:"). `--annotate`
    will reuse it with base=0 on a capability's own bytes so that capability
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
        raw += f" +{bar.offset + 4:02X}h {bar.upper_raw:08x}"  # the second slot of a 64-bit BAR
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
    return [
        _line(0x34, "Capabilities Ptr", f"{h.capabilities_pointer:02x}",
              "" if h.has_capabilities_list else "(Status bit 4 clear: no capability list)"),
        _line(0x3C, "Interrupt Line", f"{h.interrupt_line:02x}"),
        _line(0x3D, "Interrupt Pin", f"{h.interrupt_pin:02x}", h.interrupt_pin_name),
    ]


def render_header(h: Type0Header | Type1Header) -> str:
    lines = [f"{h.class_name}: {h.vendor_name} {h.device_name} (rev {h.revision_id:02x})"]
    if isinstance(h, Type0Header):
        lines.append("Type 0 header (spec 7.5.1.1, 7.5.1.2)  [taught]")
        lines += render_common(h)
        lines += [render_bar(b) for b in h.bars]
        rom_state = "enabled" if h.expansion_rom_enabled else "disabled"
        lines += [
            _line(0x28, "Cardbus CIS", f"{h.cardbus_cis:08x}"),
            _line(0x2C, "Subsystem", f"{h.subsystem_vendor_id:04x}:{h.subsystem_id:04x}", h.subsystem_vendor_name),
            _line(0x30, "Expansion ROM", f"{h.expansion_rom:08x}", f"at {h.expansion_rom_address:x}, {rom_state}"),
        ]
        lines += render_tail(h)
        lines.append(_line(0x3E, "Min_Gnt/Max_Lat", f"{h.min_gnt:02x} {h.max_lat:02x}", "legacy PCI, hardwired 0"))
    else:
        lines.append("Type 1 header (spec 7.5.1.3)  [ahead: only the bus numbers are decoded]")
        lines += render_common(h)
        lines += [render_bar(b) for b in h.bars]
        lines += [
            _line(0x18, "Primary Bus", f"{h.primary_bus:02x}", "the bus this bridge sits on"),
            _line(0x19, "Secondary Bus", f"{h.secondary_bus:02x}", "the bus directly behind it"),
            _line(0x1A, "Subordinate Bus", f"{h.subordinate_bus:02x}", "the highest bus number behind it"),
        ]
        lines += render_tail(h)
    return "\n".join(lines)
