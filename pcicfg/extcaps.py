"""The extended capability chain: the linked list at 100h and above (spec 7.6).

[Taught] Aidan walked the GPU's extended chain by hand: ten headers, one
DWORD each, from 100h, following each header's next offset, including the
hop backwards in memory from 258h to 128h (pointers, not positions).
[Ahead] The registers inside most of these capabilities (Virtual Channel,
Resizable BAR, and so on). Fully decoded here, from verified spec tables:
Power Budgeting (7.8.1), LTR (7.8.2), L1 PM Substates (7.8.3), Secondary
PCI Express (7.7.3), Data Link Feature (7.7.4), Physical Layer 16.0 GT/s
(7.7.5), Lane Margining port registers (7.7.7), the Vendor-Specific header
(7.9.5). AER (7.8.4) is aer.py. Everything else is header plus raw bytes.

Spec:
- 7.6.1: the list always begins at 100h. Absence of any extended capability
  is a header with ID 0000h, version 0h, next 000h, so the DWORD at 100h
  reads 00000000h.
- 7.6.3 Table 7-37, the Extended Capability Header, one little-endian DWORD:
  bits 15:0 Capability ID, 19:16 Capability Version, 31:20 Next Capability
  Offset. The offset is absolute (from the start of configuration space),
  000h ends the list, any other value must be greater than 0FFh, and its two
  low bits are reserved 00b (software masks them: Linux uses & 0xFFC).
- 7.6: every structure is DWORD aligned.

Frame: this chain exists only in the 4096-byte ECAM frame (7.2.2). A
256-byte dump cannot contain it; the walker says so instead of guessing.
A DWORD of FFFFFFFFh at 100h is what a Function without extended
configuration space returns for every read there (and FFFFh is the RCRB
absence marker in 7.6.2); the tool treats it as "no extended capabilities"
too, as the brief asks. That second rule is a choice.

Guards are choices, not spec, and say what they protect against.
"""

from dataclasses import dataclass

from . import ids
from .header import bit, bits
from .parse import ConfigSpace
from .pcie_cap import Register, hex_text, make_register, reserved_text, speeds_vector_text

EXTENDED_START = 0x100  # 7.6.1: the list begins here
EXTENDED_END = 0x1000  # one past FFFh: the ECAM frame (7.2.2)
MAX_HOPS = 64  # the brief's cap; the visited set already stops any loop


@dataclass
class ExtendedCapability:
    offset: int  # absolute offset of the header DWORD
    header: int  # the DWORD as read (little-endian)
    cap_id: int  # bits 15:0
    version: int  # bits 19:16
    next_offset: int  # bits 31:20 as read; 000h ends the list
    name: str
    taught: bool  # CLAUDE.md rule 5
    span: int  # a choice: bytes to the next start in address order, or to 1000h
    data: bytes  # the span bytes
    structure_length: int | None = None  # the structure's own size when the spec fixes or declares it
    problem: str = ""

    @property
    def end(self) -> int:
        return self.offset + self.span

    @property
    def next_masked(self) -> int:
        """Next Capability Offset with its two reserved low bits cleared (Table 7-37)."""
        return self.next_offset & ~0x3

    @property
    def structure_data(self) -> bytes:
        length = self.structure_length
        return self.data[:length] if length else self.data


@dataclass
class ExtendedChain:
    present: bool  # the dump reaches 100h at all
    entries: list[ExtendedCapability]  # in link order
    notes: list[str]

    def find(self, cap_id: int) -> ExtendedCapability | None:
        for c in self.entries:
            if c.cap_id == cap_id:
                return c
        return None


def read_extended_header(cs: ConfigSpace, offset: int) -> tuple[int, int, int, int]:
    """Spec 7.6.3 Table 7-37: the header DWORD at `offset` -> (raw, ID, version, next offset)."""
    raw = cs.u32(offset)
    return raw, bits(raw, 15, 0), bits(raw, 19, 16), bits(raw, 31, 20)


def walk_extended_caps(cs: ConfigSpace, max_link_width: int | None = None) -> ExtendedChain:
    """Spec 7.6.1 and 7.6.3: follow the headers from 100h until a next offset of 000h.

    max_link_width (from the PCI Express capability) sizes the per-lane
    structures (Secondary PCIe, Physical Layer 16 GT/s, Lane Margining).
    Stops, with a note, on an offset below 100h, an unaligned offset, an
    offset past the dump, a revisit (loop), or more than 64 hops.
    """
    chain = ExtendedChain(present=cs.size > EXTENDED_START, entries=[], notes=[])
    if not chain.present:
        chain.notes.append(
            f"extended space not present in dump ({cs.size} bytes; the extended chain needs the 4096-byte ECAM frame, spec 7.2.2)"
        )
        return chain
    first = cs.u32(EXTENDED_START)
    if first == 0:
        chain.notes.append("no extended capabilities: the header at 100h is 00000000h (spec 7.6.1)")
        return chain
    if first == 0xFFFFFFFF:
        chain.notes.append("no extended capabilities: 100h reads FFFFFFFFh (no extended configuration space; a choice, see the module docstring)")
        return chain

    visited: set[int] = set()
    found: list[tuple[int, int, int, int, int]] = []  # (offset, raw, id, version, next)
    ptr = EXTENDED_START
    while True:
        if ptr in visited:
            chain.notes.append(f"offset {ptr:03X}h was already visited: the list loops, stopped")
            break
        if len(visited) >= MAX_HOPS:
            chain.notes.append(f"more than {MAX_HOPS} hops: stopped")
            break
        visited.add(ptr)
        raw, cap_id, version, nxt = read_extended_header(cs, ptr)
        found.append((ptr, raw, cap_id, version, nxt))
        if nxt == 0:  # 000h ends the list (Table 7-37)
            break
        nxt_masked = nxt & ~0x3
        if nxt & 0x3:
            chain.notes.append(f"next offset {nxt:03X}h from {ptr:03X}h has reserved bits 1:0 set; masked to {nxt_masked:03X}h (Table 7-37)")
        if nxt_masked < EXTENDED_START:
            chain.notes.append(f"next offset {nxt_masked:03X}h from {ptr:03X}h points below 100h: stopped")
            break
        if nxt_masked + 4 > cs.size:
            chain.notes.append(f"next offset {nxt_masked:03X}h from {ptr:03X}h is past the end of this {cs.size}-byte dump: stopped")
            break
        ptr = nxt_masked

    chain.entries = _build_entries(cs, found, max_link_width)
    return chain


def _build_entries(cs, found, max_link_width) -> list[ExtendedCapability]:
    starts = sorted(off for off, *_ in found)  # address order; *_ swallows the other tuple items
    entries = []
    for off, raw, cap_id, version, nxt in found:
        later = [s for s in starts if s > off]
        end = min(later[0] if later else EXTENDED_END, cs.size)
        span = end - off
        cap = ExtendedCapability(
            offset=off,
            header=raw,
            cap_id=cap_id,
            version=version,
            next_offset=nxt,
            name=ids.extended_cap_name(cap_id),
            taught=cap_id in ids.TAUGHT_EXTENDED_CAPS,
            span=span,
            data=cs.bytes_at(off, span),
        )
        if cap_id == 0:
            cap.problem = "ID 0000h is only valid as the empty-list header at 100h (7.6.1)"
        elif cap_id == 0xFFFF:
            cap.problem = "ID FFFFh: reads like an absent device"
        cap.structure_length = structure_length(cs, cap, max_link_width)
        if cap.structure_length is not None and cap.structure_length > span:
            where = f"the next capability at {end:03X}h" if later else "the end of the dump"
            cap.problem = f"structure {cap.structure_length} bytes runs past {where}; only {span} bytes are there"
        entries.append(cap)
    return entries


def structure_length(cs: ConfigSpace, cap: ExtendedCapability, max_link_width: int | None) -> int | None:
    """The structure's size when the spec fixes it, a field declares it, or the lane count sets it.

    Fixed (from each capability's layout figure): Power Budgeting 10h (7.8.1
    Figure 7-108), LTR 08h (7.8.2 Figure 7-112), Data Link Feature 0Ch (7.7.4),
    L1 PM Substates 10h for version 1 and 14h for version 2 (7.8.3.1), Device
    Serial Number 0Ch, ARI 08h, ATS 08h. Declared: Vendor-Specific from its
    VSEC Length (7.9.5.2). AER: 2Ch, plus 0Ch of Root Error registers on Root
    Ports / Event Collectors, plus 10h of TLP Prefix Log when present (7.8.4).
    Per lane: Secondary PCIe 0Ch + 2 bytes per lane (7.7.3.4), Physical Layer
    16 GT/s 20h + 1 byte per lane in whole DWORDs (7.7.5.9), Lane Margining
    08h + 4 bytes per lane (7.7.7.4). Unknown: None, and the span is shown.
    """
    off = cap.offset
    fixed = {0x0004: 0x10, 0x0018: 0x08, 0x0025: 0x0C, 0x0003: 0x0C, 0x000E: 0x08, 0x000F: 0x08}
    if cap.cap_id in fixed:
        return fixed[cap.cap_id]
    if cap.cap_id == 0x001E:
        return 0x10 if cap.version < 2 else 0x14
    if cap.cap_id == 0x000B and cap.span >= 8:
        return bits(cs.u32(off + 0x04), 31, 20)  # VSEC Length
    if cap.cap_id == 0x0001 and cap.span >= 0x1C:
        caps_control = cs.u32(off + 0x18)
        length = 0x2C
        if bit(caps_control, 11):  # TLP Prefix Log Present (7.8.4.7)
            length = 0x48  # Root Error registers 2Ch-37h are then also inside the structure
        return length
    if max_link_width:
        if cap.cap_id == 0x0019:
            return 0x0C + 2 * max_link_width
        if cap.cap_id == 0x0026:
            return 0x20 + ((max_link_width + 3) // 4) * 4  # one byte per lane, whole DWORDs
        if cap.cap_id == 0x0027:
            return 0x08 + 4 * max_link_width
    return None


# --- the fully decoded capabilities, as layout tables (see pcie_cap.py) ------------------

# 7.8.1.3 Table 7-89, Power Budgeting Data register, offset 08h.
POWER_BUDGET_TYPE = {0: "PME Aux", 1: "Auxiliary", 2: "Idle", 3: "Sustained",
                     4: "Sustained, Emergency Power Reduction State", 5: "Maximum, Emergency Power Reduction State", 7: "Maximum"}
POWER_BUDGET_RAIL = {0: "12 V", 1: "3.3 V", 2: "1.5 V or 1.8 V", 7: "thermal"}
POWER_SCALE = {0: "1.0x", 1: "0.1x", 2: "0.01x", 3: "0.001x"}
PM_STATE = {0: "D0", 1: "D1", 2: "D2", 3: "D3 (D3cold if Type is Auxiliary or PME Aux, else D3hot)"}
POWER_BUDGET_DATA = [
    (7, 0, "Base Power", lambda v: f"{v}" + (" (F0h-F2h = 250/275/300 W at scale 1.0x)" if v >= 0xF0 else ""), "Watts = Base Power x Data Scale"),
    (9, 8, "Data Scale", POWER_SCALE),
    (12, 10, "PM Sub State", lambda v: "default" if v == 0 else f"device specific {v}"),
    (14, 13, "PM State", PM_STATE),
    (17, 15, "Type", POWER_BUDGET_TYPE),
    (20, 18, "Power Rail", POWER_BUDGET_RAIL),
    (31, 21, "RsvdP", reserved_text),
]
POWER_BUDGET_CAPABILITY = [(0, 0, "System Allocated", None, "1 = already in the system budget; ignore the data"), (7, 1, "RsvdP", reserved_text)]

# 7.8.2.2 / 7.8.2.3, LTR: LatencyScale multipliers from the LTR Message (Section 6.18).
LTR_SCALE_NS = {0: 1, 1: 32, 2: 1024, 3: 32768, 4: 1048576, 5: 33554432}


def ltr_scale_text(v: int) -> str:
    return f"x {LTR_SCALE_NS[v]:,} ns" if v in LTR_SCALE_NS else f"{v} (not permitted)"


LTR_REGISTER = [
    (9, 0, "LatencyValue", lambda v: f"{v}"),
    (12, 10, "LatencyScale", ltr_scale_text),
    (15, 13, "RsvdP", reserved_text),
]


def ltr_latency_ns(value: int) -> int | None:
    """Value x scale multiplier, in nanoseconds; None for the two not-permitted scales."""
    scale = bits(value, 12, 10)
    return bits(value, 9, 0) * LTR_SCALE_NS[scale] if scale in LTR_SCALE_NS else None


# 7.8.3.2 Table 7-95, L1 PM Substates Capabilities, offset 04h.
T_POWER_ON_SCALE_US = {0: 2, 1: 10, 2: 100}


def t_power_on_scale_text(v: int) -> str:
    return f"{T_POWER_ON_SCALE_US[v]} us" if v in T_POWER_ON_SCALE_US else "reserved"


L1SS_CAPABILITIES = [
    (0, 0, "PCI-PM L1.2 Supported", None),
    (1, 1, "PCI-PM L1.1 Supported", None),
    (2, 2, "ASPM L1.2 Supported", None),
    (3, 3, "ASPM L1.1 Supported", None),
    (4, 4, "L1 PM Substates Supported", None),
    (5, 5, "Link Activation Supported", None, "Downstream Ports only"),
    (7, 6, "RsvdP", reserved_text),
    (15, 8, "Port Common_Mode_Restore_Time", lambda v: f"{v} us"),
    (17, 16, "Port T_POWER_ON Scale", t_power_on_scale_text),
    (18, 18, "RsvdP", reserved_text),
    (23, 19, "Port T_POWER_ON Value", lambda v: f"{v}", "T_POWER_ON = Value x Scale"),
    (31, 24, "RsvdP", reserved_text),
]
# 7.8.3.3 Table 7-96, L1 PM Substates Control 1, offset 08h.
L1SS_CONTROL_1 = [
    (0, 0, "PCI-PM L1.2 Enable", None),
    (1, 1, "PCI-PM L1.1 Enable", None),
    (2, 2, "ASPM L1.2 Enable", None),
    (3, 3, "ASPM L1.1 Enable", None),
    (4, 4, "Link Activation Interrupt Enable", None),
    (5, 5, "Link Activation Control", None),
    (7, 6, "RsvdP", reserved_text),
    (15, 8, "Common_Mode_Restore_Time", lambda v: f"{v} us"),
    (25, 16, "LTR_L1.2_THRESHOLD_Value", lambda v: f"{v}"),
    (28, 26, "RsvdP", reserved_text),
    (31, 29, "LTR_L1.2_THRESHOLD_Scale", ltr_scale_text),
]
# 7.8.3.4 Table 7-97, L1 PM Substates Control 2, offset 0Ch.
L1SS_CONTROL_2 = [
    (1, 0, "T_POWER_ON Scale", t_power_on_scale_text),
    (2, 2, "RsvdP", reserved_text),
    (7, 3, "T_POWER_ON Value", lambda v: f"{v}", "T_POWER_ON = Value x Scale"),
    (31, 8, "RsvdP", reserved_text),
]
# 7.8.3.5 Table 7-98, L1 PM Substates Status, offset 10h (version 2 only).
L1SS_STATUS = [(0, 0, "Link Activation Status", None, "RW1C; Downstream Ports only"), (31, 1, "RsvdZ", reserved_text)]

# 7.7.3.2 Table 7-56, Link Control 3, offset 04h; 7.7.3.3 Table 7-57, Lane Error Status, 08h.
LINK_CONTROL_3 = [
    (0, 0, "Perform Equalization", None),
    (1, 1, "Link Equalization Request Interrupt Enable", None),
    (8, 2, "RsvdP", reserved_text),
    (15, 9, "Enable Lower SKP OS Generation Vector", speeds_vector_text),
    (31, 16, "RsvdP", reserved_text),
]
LANE_ERROR_STATUS = [(31, 0, "Lane Error Status Bits", lambda v: "none" if v == 0 else f"lanes {[n for n in range(32) if bit(v, n)]}", "RW1CS; bit N = Lane N")]

# 7.7.4.2 Table 7-60 and 7.7.4.3 Table 7-61, Data Link Feature.
DLF_CAPABILITIES = [
    (0, 0, "Local Scaled Flow Control Supported", None),
    (22, 1, "RsvdP", reserved_text),
    (30, 23, "RsvdP", reserved_text),
    (31, 31, "Data Link Feature Exchange Enable", None),
]
DLF_STATUS = [
    (0, 0, "Remote Scaled Flow Control Supported", None),
    (22, 1, "Undefined", reserved_text),
    (30, 23, "RsvdZ", reserved_text),
    (31, 31, "Remote Data Link Feature Supported Valid", None),
]

# 7.7.5.4 Table 7-65, 16.0 GT/s Status, offset 0Ch.
PHY16_STATUS = [
    (0, 0, "Equalization 16.0 GT/s Complete", None),
    (1, 1, "Equalization 16.0 GT/s Phase 1 Successful", None),
    (2, 2, "Equalization 16.0 GT/s Phase 2 Successful", None),
    (3, 3, "Equalization 16.0 GT/s Phase 3 Successful", None),
    (4, 4, "Link Equalization Request 16.0 GT/s", None, "RW1CS"),
    (31, 5, "RsvdZ", reserved_text),
]
LANE_BITMAP = [(31, 0, "per-lane bits", lambda v: "none" if v == 0 else f"lanes {[n for n in range(32) if bit(v, n)]}", "RW1CS; bit N = Lane N")]

# 7.7.7.2 Table 7-80 and 7.7.7.3 Table 7-81, Lane Margining port registers.
MARGINING_PORT_CAPABILITIES = [(0, 0, "Margining uses Driver Software", None), (15, 1, "RsvdP", reserved_text)]
MARGINING_PORT_STATUS = [(0, 0, "Margining Ready", None), (1, 1, "Margining Software Ready", None), (15, 2, "RsvdZ", reserved_text)]

# 7.9.5.2 Table 7-162, Vendor-Specific Header, offset 04h.
VSEC_HEADER = [
    (15, 0, "VSEC ID", hex_text(16), "vendor-defined; qualify by Vendor ID first"),
    (19, 16, "VSEC Rev", lambda v: f"{v}"),
    (31, 20, "VSEC Length", lambda v: f"{v:03x}h = {v} bytes", "whole structure incl. both headers"),
]


def decode_extended_registers(cs: ConfigSpace, cap: ExtendedCapability) -> list[Register]:
    """The registers of one extended capability, for the IDs decoded here; [] for the rest.

    Each register is read at cap.offset plus its relative offset; every
    layout cites its spec table above.
    """
    off = cap.offset
    have = cap.span  # bytes available before the next start

    def u32(rel):
        return cs.u32(off + rel)

    def u16(rel):
        return cs.u16(off + rel)

    def u8(rel):
        return cs.u8(off + rel)

    regs = []
    if cap.cap_id == 0x0004 and have >= 0x10:  # Power Budgeting (7.8.1)
        regs.append(make_register("data_select", "Power Budgeting Data Select", "7.8.1.2", 0x04, 8, u8(0x04),
                                  [(7, 0, "Data Select", lambda v: f"{v}", "which operating condition the Data register shows")]))
        regs.append(make_register("data", "Power Budgeting Data", "7.8.1.3", 0x08, 32, u32(0x08), POWER_BUDGET_DATA))
        regs.append(make_register("capability", "Power Budgeting Capability", "7.8.1.4", 0x0C, 8, u8(0x0C), POWER_BUDGET_CAPABILITY))
    elif cap.cap_id == 0x0018 and have >= 0x08:  # LTR (7.8.2)
        regs.append(make_register("max_snoop", "Max Snoop Latency", "7.8.2.2", 0x04, 16, u16(0x04), LTR_REGISTER))
        regs.append(make_register("max_no_snoop", "Max No-Snoop Latency", "7.8.2.3", 0x06, 16, u16(0x06), LTR_REGISTER))
    elif cap.cap_id == 0x001E and have >= 0x10:  # L1 PM Substates (7.8.3)
        regs.append(make_register("capabilities", "L1 PM Substates Capabilities", "7.8.3.2", 0x04, 32, u32(0x04), L1SS_CAPABILITIES))
        regs.append(make_register("control_1", "L1 PM Substates Control 1", "7.8.3.3", 0x08, 32, u32(0x08), L1SS_CONTROL_1))
        regs.append(make_register("control_2", "L1 PM Substates Control 2", "7.8.3.4", 0x0C, 32, u32(0x0C), L1SS_CONTROL_2))
        if cap.version >= 2 and have >= 0x14:
            regs.append(make_register("status", "L1 PM Substates Status", "7.8.3.5", 0x10, 32, u32(0x10), L1SS_STATUS))
    elif cap.cap_id == 0x0019 and have >= 0x0C:  # Secondary PCI Express (7.7.3)
        regs.append(make_register("link_control_3", "Link Control 3", "7.7.3.2", 0x04, 32, u32(0x04), LINK_CONTROL_3))
        regs.append(make_register("lane_error_status", "Lane Error Status", "7.7.3.3", 0x08, 32, u32(0x08), LANE_ERROR_STATUS))
    elif cap.cap_id == 0x0025 and have >= 0x0C:  # Data Link Feature (7.7.4)
        regs.append(make_register("capabilities", "Data Link Feature Capabilities", "7.7.4.2", 0x04, 32, u32(0x04), DLF_CAPABILITIES))
        regs.append(make_register("status", "Data Link Feature Status", "7.7.4.3", 0x08, 32, u32(0x08), DLF_STATUS))
    elif cap.cap_id == 0x0026 and have >= 0x10:  # Physical Layer 16.0 GT/s (7.7.5)
        regs.append(make_register("capabilities", "16.0 GT/s Capabilities", "7.7.5.2", 0x04, 32, u32(0x04), [(31, 0, "RsvdP", reserved_text)]))
        regs.append(make_register("control", "16.0 GT/s Control", "7.7.5.3", 0x08, 32, u32(0x08), [(31, 0, "RsvdP", reserved_text)]))
        regs.append(make_register("status", "16.0 GT/s Status", "7.7.5.4", 0x0C, 32, u32(0x0C), PHY16_STATUS))
        if have >= 0x1C:
            regs.append(make_register("local_parity_mismatch", "16.0 GT/s Local Data Parity Mismatch Status", "7.7.5.5", 0x10, 32, u32(0x10), LANE_BITMAP))
            regs.append(make_register("first_retimer_parity_mismatch", "16.0 GT/s First Retimer Data Parity Mismatch Status", "7.7.5.6", 0x14, 32, u32(0x14), LANE_BITMAP))
            regs.append(make_register("second_retimer_parity_mismatch", "16.0 GT/s Second Retimer Data Parity Mismatch Status", "7.7.5.7", 0x18, 32, u32(0x18), LANE_BITMAP))
    elif cap.cap_id == 0x0027 and have >= 0x08:  # Lane Margining at the Receiver (7.7.7)
        regs.append(make_register("port_capabilities", "Margining Port Capabilities", "7.7.7.2", 0x04, 16, u16(0x04), MARGINING_PORT_CAPABILITIES))
        regs.append(make_register("port_status", "Margining Port Status", "7.7.7.3", 0x06, 16, u16(0x06), MARGINING_PORT_STATUS))
    elif cap.cap_id == 0x000B and have >= 0x08:  # Vendor-Specific Extended (7.9.5)
        regs.append(make_register("vsec_header", "Vendor-Specific Header", "7.9.5.2", 0x04, 32, u32(0x04), VSEC_HEADER))
    return regs


def ltr_summary(cs: ConfigSpace, cap: ExtendedCapability) -> str | None:
    """lspci's two LTR lines: 'Max snoop latency: 15728640ns'."""
    if cap.cap_id != 0x0018 or cap.span < 8:
        return None
    snoop = ltr_latency_ns(cs.u16(cap.offset + 0x04))
    no_snoop = ltr_latency_ns(cs.u16(cap.offset + 0x06))
    fmt = lambda n: "not permitted scale" if n is None else f"{n} ns"
    return f"max snoop latency {fmt(snoop)}, max no-snoop latency {fmt(no_snoop)}"


def l1ss_summary(cs: ConfigSpace, cap: ExtendedCapability) -> str | None:
    """lspci's L1SubCap/L1SubCtl lines in one string, from the three registers."""
    if cap.cap_id != 0x001E or cap.span < 0x10:
        return None
    caps = cs.u32(cap.offset + 0x04)
    ctl1 = cs.u32(cap.offset + 0x08)
    ctl2 = cs.u32(cap.offset + 0x0C)
    scale = T_POWER_ON_SCALE_US.get(bits(caps, 17, 16))
    port_t_power_on = f"{bits(caps, 23, 19) * scale} us" if scale else "reserved scale"
    scale2 = T_POWER_ON_SCALE_US.get(bits(ctl2, 1, 0))
    t_power_on = f"{bits(ctl2, 7, 3) * scale2} us" if scale2 else "reserved scale"
    threshold_scale = bits(ctl1, 31, 29)
    threshold = (f"{bits(ctl1, 25, 16) * LTR_SCALE_NS[threshold_scale]} ns"
                 if threshold_scale in LTR_SCALE_NS else "not permitted scale")
    return (f"supported: PCI-PM L1.2{'+' if bit(caps, 0) else '-'} L1.1{'+' if bit(caps, 1) else '-'} "
            f"ASPM L1.2{'+' if bit(caps, 2) else '-'} L1.1{'+' if bit(caps, 3) else '-'}; "
            f"Port Common_Mode_Restore_Time {bits(caps, 15, 8)} us; Port T_POWER_ON {port_t_power_on}; "
            f"enabled: PCI-PM L1.2{'+' if bit(ctl1, 0) else '-'} L1.1{'+' if bit(ctl1, 1) else '-'} "
            f"ASPM L1.2{'+' if bit(ctl1, 2) else '-'} L1.1{'+' if bit(ctl1, 3) else '-'}; "
            f"Common_Mode_Restore_Time {bits(ctl1, 15, 8)} us; LTR_L1.2_THRESHOLD {threshold}; T_POWER_ON {t_power_on}")
