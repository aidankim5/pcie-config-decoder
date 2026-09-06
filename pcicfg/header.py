"""The configuration header: the first 64 bytes of every function.

[Taught] Aidan decoded the Type 0 header of his GPU by hand: Vendor and
Device ID, Command, Status, Class Code, Header Type, the six BARs, the
Subsystem IDs, the Expansion ROM, the Capabilities Pointer, the interrupt pin.
[Ahead] Type 1 (bridge) headers: only the three bus numbers at 18h-1Ah are
decoded here; the rest of a bridge header is not.

Spec sections (PCI Express Base 5.0):
- 7.5.1.1 Type 0/1 Common Configuration Space: offsets 00h-0Fh, and 34h,
  3Ch, 3Dh, which both header types share.
- 7.5.1.2 Type 0 Configuration Space Header: 10h-33h and 3Eh-3Fh.
- 7.5.1.3 Type 1 Configuration Space Header: bridges. Two BARs instead of
  six, bus numbers at 18h-1Ah, Expansion ROM moved to 38h.

Every offset in this file is absolute (from the start of the function's
configuration space). Every multi-byte field is read little-endian through
ConfigSpace.u16/u32 (see parse.py).
"""

from dataclasses import dataclass

from . import ids
from .parse import ConfigSpace


def bit(value: int, n: int) -> bool:
    """True when bit n of value is 1. (value >> n) moves bit n to position 0; & 1 keeps only it."""
    return (value >> n) & 1 == 1


def bits(value: int, hi: int, lo: int) -> int:
    """The field value in bits hi:lo of value, as a number.

    (value >> lo) drops the bits below the field; the mask (1 << width) - 1 is
    `width` ones in a row and keeps only the field. bits(0x80, 6, 0) is 0.
    """
    width = hi - lo + 1
    return (value >> lo) & ((1 << width) - 1)


@dataclass
class Bit:
    """One named bit of a register: where it sits, what it is called, whether it is set."""

    bit: int
    name: str
    set: bool
    note: str = ""  # e.g. "legacy PCI; hardwired 0 on PCI Express"


# Spec 7.5.1.1.3, Command Register, offset 04h, Table 7-3. Bits 15:11 are RsvdP.
COMMAND_BITS = [
    (0, "I/O Space Enable", ""),
    (1, "Memory Space Enable", ""),
    (2, "Bus Master Enable", ""),
    (3, "Special Cycle Enable", "legacy PCI; hardwired 0 on PCI Express"),
    (4, "Memory Write and Invalidate", "legacy PCI; hardwired 0 on PCI Express"),
    (5, "VGA Palette Snoop", "legacy PCI; hardwired 0 on PCI Express"),
    (6, "Parity Error Response", ""),
    (7, "IDSEL Stepping/Wait Cycle Control", "legacy PCI; hardwired 0 on PCI Express"),
    (8, "SERR# Enable", ""),
    (9, "Fast Back-to-Back Transactions Enable", "legacy PCI; hardwired 0 on PCI Express"),
    (10, "Interrupt Disable", ""),
]

# Spec 7.5.1.1.4, Status Register, offset 06h, Table 7-4. Bits 2:1 and 6 are RsvdZ;
# bits 10:9 are the DEVSEL Timing field (decoded separately, hardwired 00b on PCIe).
STATUS_BITS = [
    (0, "Immediate Readiness", ""),
    (3, "Interrupt Status", ""),
    (4, "Capabilities List", "must be 1 on PCI Express"),
    (5, "66 MHz Capable", "legacy PCI; hardwired 0 on PCI Express"),
    (7, "Fast Back-to-Back Transactions Capable", "legacy PCI; hardwired 0 on PCI Express"),
    (8, "Master Data Parity Error", "RW1C: written 1 to clear"),
    (11, "Signaled Target Abort", "RW1C"),
    (12, "Received Target Abort", "RW1C"),
    (13, "Received Master Abort", "RW1C"),
    (14, "Signaled System Error", "RW1C"),
    (15, "Detected Parity Error", "RW1C"),
]

# Spec 7.5.1.1.9, Header Type Register, offset 0Eh, bits 6:0.
HEADER_LAYOUTS = {0: "Type 0", 1: "Type 1 (bridge)", 2: "Type 2 (CardBus, reserved)"}

# Spec 7.5.1.1.13, Interrupt Pin Register, offset 3Dh.
INTERRUPT_PINS = {0: "none", 1: "INTA", 2: "INTB", 3: "INTC", 4: "INTD"}


def decode_command(value: int) -> list[Bit]:
    """Spec 7.5.1.1.3, Command Register, offset 04h (16 bits). Named bits with their state."""
    return [Bit(n, name, bit(value, n), note) for n, name, note in COMMAND_BITS]


def decode_status(value: int) -> list[Bit]:
    """Spec 7.5.1.1.4, Status Register, offset 06h (16 bits). Named bits with their state."""
    return [Bit(n, name, bit(value, n), note) for n, name, note in STATUS_BITS]


def decode_header_type(value: int) -> tuple[int, bool]:
    """Spec 7.5.1.1.9, Header Type Register, offset 0Eh.

    Returns (layout, multi_function): bits 6:0 are the layout (0 = Type 0,
    1 = Type 1 bridge, 2 reserved), bit 7 is the Multi-Function Device bit.
    """
    return bits(value, 6, 0), bit(value, 7)


@dataclass
class Bar:
    """One Base Address Register, spec 7.5.1.2.1 (offsets 10h-24h, one DWORD each).

    Bit 0 says which space: 0 = memory, 1 = I/O. For memory, bits 2:1 give the
    width (00b = 32-bit, 10b = 64-bit) and bit 3 says prefetchable; the address
    is bits 31:4. For I/O, bit 1 is reserved and the address is bits 31:2. A
    64-bit BAR spans two DWORDs: the next slot holds address bits 63:32.
    """

    index: int  # 0-5 in a Type 0 header
    offset: int  # absolute offset of the low DWORD: 10h + 4 * index
    raw: int  # the DWORD as read
    kind: str  # "memory", "io", or "empty" (reads as zero)
    address: int = 0
    width: int = 32  # 32 or 64 (memory only)
    prefetchable: bool = False
    upper_raw: int | None = None  # the second DWORD of a 64-bit BAR, at offset + 4
    # Sizing needs a write of all ones and a read-back (spec 7.5.1.2.1); a dump cannot do that.
    size_note: str = "size: not determinable from a dump"
    problem: str = ""  # set when the BAR breaks a spec rule, e.g. a reserved type encoding

    @property
    def slots(self) -> int:
        """How many DWORD slots this BAR occupies: 2 for a 64-bit memory BAR, else 1."""
        return 2 if self.width == 64 else 1


def decode_bar(cs: ConfigSpace, index: int, count: int = 6) -> Bar:
    """Spec 7.5.1.2.1, Base Address Register `index` at absolute offset 10h + 4*index.

    count is how many BAR slots this header type has (6 for Type 0, 2 for
    Type 1); a 64-bit BAR in the last slot has no room for its upper half and
    is reported as a problem instead of reading the register after the BARs.
    """
    offset = 0x10 + 4 * index
    raw = cs.u32(offset)
    if raw == 0:
        # "Unimplemented Base Address registers are hardwired to zero" (7.5.1.2.1);
        # an implemented but unassigned BAR also reads as zero, and a dump cannot tell.
        return Bar(index, offset, raw, "empty")
    if bit(raw, 0):
        return Bar(index, offset, raw, "io", address=raw & ~0x3)  # bits 31:2
    memory_type = bits(raw, 2, 1)  # Table 7-8: 00b = 32-bit, 10b = 64-bit, 01b and 11b reserved
    width = 64 if memory_type == 0b10 else 32
    problem = "" if memory_type in (0b00, 0b10) else f"reserved memory type {memory_type:02b}"
    address = raw & ~0xF  # bits 31:4
    upper = None
    if width == 64:
        if index + 1 >= count:
            problem = "64-bit BAR in the last slot: no room for its upper half"
            width = 32
        else:
            upper = cs.u32(offset + 4)
            address |= upper << 32  # the next DWORD is address bits 63:32
    return Bar(index, offset, raw, "memory", address, width, bit(raw, 3), upper, problem=problem)


def decode_bars(cs: ConfigSpace, count: int) -> list[Bar]:
    """Walk the BAR slots in order; a 64-bit BAR consumes the slot after it.

    count is 6 for a Type 0 header (10h-24h) and 2 for a Type 1 header (10h-14h).
    """
    out = []
    index = 0
    while index < count:
        bar = decode_bar(cs, index, count)
        out.append(bar)
        index += bar.slots
    return out


@dataclass
class CommonHeader:
    """Spec 7.5.1.1: the fields both header types share (00h-0Fh, 34h, 3Ch, 3Dh)."""

    vendor_id: int  # 00h, 16 bits
    device_id: int  # 02h, 16 bits
    command: int  # 04h, 16 bits, raw
    command_bits: list[Bit]
    status: int  # 06h, 16 bits, raw
    status_bits: list[Bit]
    devsel_timing: int  # Status bits 10:9, legacy field, hardwired 00b
    revision_id: int  # 08h, 8 bits
    prog_if: int  # 09h: Class Code bits 7:0, Programming Interface
    sub_class: int  # 0Ah: Class Code bits 15:8
    base_class: int  # 0Bh: Class Code bits 23:16
    cache_line_size: int  # 0Ch, in units of DWORDs (PCI convention; 0x10 = 64 bytes)
    latency_timer: int  # 0Dh, hardwired 00h on PCI Express
    header_type: int  # 0Eh, raw
    header_layout: int  # Header Type bits 6:0
    multi_function: bool  # Header Type bit 7
    bist: int  # 0Fh, raw (bit 7 BIST Capable, bit 6 Start BIST, bits 3:0 Completion Code)
    capabilities_pointer: int  # 34h, bits 1:0 masked off (spec 7.5.1.1.11)
    interrupt_line: int  # 3Ch, programmed by system software
    interrupt_pin: int  # 3Dh, 0 = none, 1-4 = INTA-INTD

    @property
    def class_code(self) -> int:
        """The 24-bit Class Code as one number, base class in the top byte: 0x030000 = VGA."""
        return (self.base_class << 16) | (self.sub_class << 8) | self.prog_if

    @property
    def class_name(self) -> str:
        return ids.class_name(self.base_class, self.sub_class, self.prog_if)

    @property
    def vendor_name(self) -> str:
        return ids.vendor_name(self.vendor_id)

    @property
    def device_name(self) -> str:
        return ids.device_name(self.vendor_id, self.device_id)

    @property
    def has_capabilities_list(self) -> bool:
        """Status bit 4. Only when set may the chain at the Capabilities Pointer be walked."""
        return bit(self.status, 4)

    @property
    def layout_name(self) -> str:
        return HEADER_LAYOUTS.get(self.header_layout, f"reserved layout {self.header_layout}")

    @property
    def interrupt_pin_name(self) -> str:
        return INTERRUPT_PINS.get(self.interrupt_pin, f"reserved value {self.interrupt_pin:#04x}")


@dataclass
class Type0Header(CommonHeader):
    """Spec 7.5.1.2: everything an endpoint's header adds to the common part."""

    bars: list[Bar]  # 10h-24h, six slots
    cardbus_cis: int  # 28h, hardwired 0 on PCI Express (7.5.1.2.2)
    subsystem_vendor_id: int  # 2Ch (7.5.1.2.3): who built the board
    subsystem_id: int  # 2Eh
    expansion_rom: int  # 30h, raw (7.5.1.2.4)
    min_gnt: int  # 3Eh, hardwired 0 on PCI Express (7.5.1.2.5)
    max_lat: int  # 3Fh, hardwired 0

    @property
    def expansion_rom_enabled(self) -> bool:
        """Expansion ROM bit 0 (7.5.1.2.4, Table 7-9)."""
        return bit(self.expansion_rom, 0)

    @property
    def expansion_rom_address(self) -> int:
        """Expansion ROM bits 31:11; the ROM is at least 2 KB aligned (7.5.1.2.4)."""
        return self.expansion_rom & ~0x7FF

    @property
    def subsystem_vendor_name(self) -> str:
        return ids.vendor_name(self.subsystem_vendor_id)


@dataclass
class Type1Header(CommonHeader):
    """[Ahead] Spec 7.5.1.3: a bridge's header. Only the bus numbers are decoded."""

    bars: list[Bar]  # 10h-14h, two slots (7.5.1.3.1)
    primary_bus: int  # 18h (7.5.1.3.2): the bus the bridge sits on
    secondary_bus: int  # 19h (7.5.1.3.3): the bus directly behind it
    subordinate_bus: int  # 1Ah (7.5.1.3.4): the highest bus number behind it


def decode_common_header(cs: ConfigSpace) -> CommonHeader:
    """Spec 7.5.1.1, Type 0/1 Common Configuration Space, offsets 00h-0Fh, 34h, 3Ch, 3Dh."""
    command = cs.u16(0x04)
    status = cs.u16(0x06)
    header_type = cs.u8(0x0E)
    layout, multi = decode_header_type(header_type)
    return CommonHeader(
        vendor_id=cs.u16(0x00),
        device_id=cs.u16(0x02),
        command=command,
        command_bits=decode_command(command),
        status=status,
        status_bits=decode_status(status),
        devsel_timing=bits(status, 10, 9),
        revision_id=cs.u8(0x08),
        prog_if=cs.u8(0x09),  # Class Code is three separate bytes, low to high:
        sub_class=cs.u8(0x0A),  # 09h prog-if, 0Ah sub-class, 0Bh base class
        base_class=cs.u8(0x0B),
        cache_line_size=cs.u8(0x0C),
        latency_timer=cs.u8(0x0D),
        header_type=header_type,
        header_layout=layout,
        multi_function=multi,
        bist=cs.u8(0x0F),
        capabilities_pointer=cs.u8(0x34) & ~0x3,  # bottom two bits reserved (7.5.1.1.11)
        interrupt_line=cs.u8(0x3C),
        interrupt_pin=cs.u8(0x3D),
    )


def decode_type0_header(cs: ConfigSpace) -> Type0Header:
    """Spec 7.5.1.2, Type 0 Configuration Space Header (an endpoint)."""
    common = decode_common_header(cs)
    return Type0Header(
        **vars(common),  # copy the common fields, then add the Type 0 ones
        bars=decode_bars(cs, 6),
        cardbus_cis=cs.u32(0x28),
        subsystem_vendor_id=cs.u16(0x2C),
        subsystem_id=cs.u16(0x2E),
        expansion_rom=cs.u32(0x30),
        min_gnt=cs.u8(0x3E),
        max_lat=cs.u8(0x3F),
    )


def decode_type1_header(cs: ConfigSpace) -> Type1Header:
    """[Ahead] Spec 7.5.1.3, Type 1 header: common fields, two BARs, and the bus numbers."""
    common = decode_common_header(cs)
    return Type1Header(
        **vars(common),
        bars=decode_bars(cs, 2),
        primary_bus=cs.u8(0x18),
        secondary_bus=cs.u8(0x19),
        subordinate_bus=cs.u8(0x1A),
    )


def decode_header(cs: ConfigSpace) -> Type0Header | Type1Header:
    """Pick the decoder from Header Type bits 6:0 (spec 7.5.1.1.9)."""
    layout, _ = decode_header_type(cs.u8(0x0E))
    if layout == 1:
        return decode_type1_header(cs)
    return decode_type0_header(cs)  # layout 0; reserved layouts are decoded as Type 0 with a warning upstream
