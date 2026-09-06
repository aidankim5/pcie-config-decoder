"""The standard capability chain: a linked list inside the PCI-compatible 256 bytes.

[Taught] Aidan walked both fixtures' chains by hand: read the byte at 34h,
go there, read two one-byte fields (ID, then the next pointer), go to the
next pointer, stop at 00h. This module is that walk.

Spec (PCI Express Base 5.0):
- 7.5.1.1.11 Capabilities Pointer, offset 34h: the first entry's offset; its
  bottom two bits are reserved and software must mask them off.
- Every capability structure starts with the same two bytes, defined in that
  capability's own section: 7.5.2.1 (Power Management), 7.5.3.1 Table 7-17
  (PCI Express: bits 7:0 Capability ID, bits 15:8 Next Capability Pointer,
  which is 00h if no other items exist in the linked list), 7.7.1.1 (MSI),
  7.7.2.1 (MSI-X). Vendor-Specific (7.9.4) adds a third byte, Capability Length.
- The ID and the next pointer are two separate one-byte fields. Reading them
  as one little-endian 16-bit number would put the pointer in the high byte;
  this module never does that.

Frame: this chain lives at 40h-FFh, inside what the PCI-compatible
configuration mechanism can reach (spec 7.2.1; on x86 that is the CF8h/CFCh
port pair from the PCI Local Bus spec). It never enters the extended space
at 100h; that chain is a different list with a different header format
(extcaps.py).

Two numbers per entry, and only one of them is spec:
- `structure_length` is the size of the capability when the spec fixes it or
  the capability declares it (Power Management 8 bytes, MSI-X 12 bytes,
  Vendor-Specific from its own Capability Length byte). MSI's comes from its
  Message Control bits through msi.msi_structure_length (a DWORD count off
  the spec's figures); the PCI Express capability's from its version and
  port type through pcie_cap.pcie_structure_length.
- `span` is a choice: the gap from this entry's start to the next capability
  start in address order (or to 100h). It is how the chain reads by eye,
  "this section starts from 00 and runs until the next one begins", and it
  can be larger than the structure.

The guards below are choices, not spec. Each one says what it protects
against at the point it is applied.
"""

from dataclasses import dataclass

from . import ids
from .header import bit
from .msi import msi_structure_length
from .parse import ConfigSpace
from .pcie_cap import pcie_structure_length

FIRST_CAP_OFFSET = 0x40  # the header occupies 00h-3Fh (spec 7.5.1.2), so a capability cannot start below 40h
PCI_COMPATIBLE_END = 0x100  # one past FFh: where the PCI-compatible 256 bytes stop (spec 7.2.1)
MAX_HOPS = 48  # (100h - 40h) / 4: only 48 DWORD-aligned starts exist in 40h-FFh, so more hops means a loop

# Spec-fixed structure sizes, in bytes: PM is 00h-07h (7.5.2 Figure 7-17; the Data byte at 07h
# is optional but the slot is there), MSI-X is 00h-0Bh (7.7.2 Figure 7-56). Linux pci_regs.h
# agrees: PCI_PM_SIZEOF 8, PCI_CAP_MSIX_SIZEOF 12. MSI's size depends on two Message Control
# bits (msi.py); the PCI Express capability's on its version and port type (pcie_cap.py).
FIXED_STRUCTURE_SIZE = {0x01: 8, 0x11: 12}


@dataclass
class Capability:
    """One entry of the chain: where it is, what it is, and its bytes."""

    offset: int  # absolute offset of byte 0 (the ID)
    cap_id: int  # byte 0
    next_pointer: int  # byte 1, as read (00h = end of list)
    name: str
    taught: bool  # CLAUDE.md rule 5: has Aidan decoded this capability's registers by hand?
    span: int  # a choice: bytes to the next capability start in address order, or to 100h
    data: bytes  # the `span` bytes, so each capability can be read from 00 (relative offsets)
    # "" = nothing wrong. The default lets the constructor leave it out; a dataclass field
    # with a default must come after the fields without one.
    problem: str = ""

    @property
    def end(self) -> int:
        """Absolute offset just past this capability's span."""
        return self.offset + self.span

    @property
    def vendor_specific_length(self) -> int | None:
        """Spec 7.9.4 Table 7-160: byte 2, Capability Length, counts the whole structure including these three bytes."""
        if self.cap_id == 0x09 and len(self.data) >= 3:
            return self.data[2]
        return None

    @property
    def structure_length(self) -> int | None:
        """The spec's size of this structure in bytes, when known here; None means its own decoder decides."""
        if self.cap_id == 0x09:
            return self.vendor_specific_length
        if self.cap_id == 0x05 and len(self.data) >= 4:
            # Bytes 2-3 are Message Control (7.7.1.2): the same little-endian flip as
            # ConfigSpace.u16, done on the raw slice because this object holds bytes.
            return msi_structure_length(int.from_bytes(self.data[2:4], "little"))
        if self.cap_id == 0x10 and len(self.data) >= 4:
            # Bytes 2-3 are the PCI Express Capabilities register (7.5.3.2): version and type
            return pcie_structure_length(int.from_bytes(self.data[2:4], "little"))
        return FIXED_STRUCTURE_SIZE.get(self.cap_id)  # dict.get: None when the ID is not listed

    @property
    def boundary_text(self) -> str:
        """What the span runs up to: the next capability's start, or the end of the space."""
        if self.end >= PCI_COMPATIBLE_END:
            return "the end of the PCI-compatible space (100h)"
        return f"the next capability at {self.end:02X}h"

    @property
    def structure_data(self) -> bytes:
        """The bytes that belong to the structure: the declared length if known, else the whole span."""
        length = self.structure_length
        return self.data[:length] if length else self.data


@dataclass
class CapabilityChain:
    pointer_raw: int  # the byte at 34h as it sits in the dump
    pointer: int  # with bits 1:0 masked off (spec 7.5.1.1.11)
    has_list: bool  # Status bit 4, Capabilities List (spec 7.5.1.1.4)
    entries: list[Capability]  # in link order, which is not always address order
    notes: list[str]  # why the walk did not run, or stopped early

    def find(self, cap_id: int) -> Capability | None:
        """The first entry with this ID, or None."""
        for c in self.entries:
            if c.cap_id == cap_id:
                return c
        return None


def walk_standard_caps(cs: ConfigSpace) -> CapabilityChain:
    """Spec 7.5.1.1.11: follow the list from the Capabilities Pointer at 34h until a 00h pointer.

    Each hop reads two one-byte fields at the pointer: byte 0 = Capability ID,
    byte 1 = Next Capability Pointer (7.5.3.1 Table 7-17 and the matching table
    of every other capability). Stops, with a note saying why, on a pointer
    into the header, an unaligned pointer, a pointer past the end of a short
    hand-built dump, a revisit, or more hops than there are aligned slots.
    """
    status = cs.u16(0x06)
    has_list = bit(status, 4)
    pointer_raw = cs.u8(0x34)
    pointer = pointer_raw & ~0x3  # bits 1:0 reserved (7.5.1.1.11); ~ flips all bits, & clears those two
    chain = CapabilityChain(pointer_raw=pointer_raw, pointer=pointer, has_list=has_list, entries=[], notes=[])

    if cs.size <= FIRST_CAP_OFFSET:
        chain.notes.append(f"dump is {cs.size} bytes, the header only; capabilities live at 40h-FFh")
        return chain
    if not has_list:
        # Spec 7.5.1.1.4: every PCI Express Function must set this bit. When it is clear
        # the pointer at 34h has no meaning, so nothing is walked.
        chain.notes.append("Status bit 4 (Capabilities List) is clear: no chain to walk")
        return chain
    if pointer_raw != pointer:
        chain.notes.append(
            f"Capabilities Pointer bits 1:0 were set ({pointer_raw:02X}h); masked to {pointer:02X}h per 7.5.1.1.11"
        )

    # A set, because the only question asked of it is "have I seen this offset?"; link
    # order is kept in `found`. Catches a loop.
    visited: set[int] = set()
    found: list[tuple[int, int, int]] = []  # (offset, id, next) in link order
    ptr = pointer
    while ptr != 0:  # 00h ends the list (7.5.3.1 Table 7-17)
        if ptr < FIRST_CAP_OFFSET:
            chain.notes.append(f"pointer {ptr:02X}h points into the header (00h-3Fh): stopped")
            break
        if ptr & 0x3:
            chain.notes.append(f"pointer {ptr:02X}h is not DWORD aligned: stopped")
            break
        if ptr + 1 >= cs.size:
            # A one-byte pointer cannot pass FFh, and the three real frames are 64, 256 or
            # 4096 bytes, so this only fires for a hand-built dump shorter than 256 bytes.
            chain.notes.append(f"pointer {ptr:02X}h is past the end of this {cs.size}-byte dump: stopped")
            break
        if ptr in visited:
            chain.notes.append(f"pointer {ptr:02X}h was already visited: the list loops, stopped")
            break
        if len(visited) >= MAX_HOPS:
            # Cannot trigger while `visited` works (48 aligned slots), kept as a second fence.
            chain.notes.append(f"more than {MAX_HOPS} hops: stopped")
            break
        visited.add(ptr)
        cap_id = cs.u8(ptr)  # byte 0: the ID
        # byte 1: the next pointer, a separate field, not the high byte of a word.
        # Named `nxt` because `next` is a Python built-in function.
        nxt = cs.u8(ptr + 1)
        found.append((ptr, cap_id, nxt))
        ptr = nxt

    chain.entries = _build_entries(cs, found)
    return chain


def _build_entries(cs: ConfigSpace, found: list[tuple[int, int, int]]) -> list[Capability]:
    """Give each entry its name, tag, and byte span.

    The span is a choice, not the spec's size: it runs to the next capability
    start in ADDRESS order (or to 100h), which is how the chain reads by eye.
    Link order can differ from address order.
    """
    # Each `found` item is (offset, id, next); `_` is the usual name for a value we do not
    # use. sorted() puts the offsets in address order, lowest first, because the span is
    # measured in address order, not link order.
    starts = sorted(off for off, _, _ in found)
    entries = []
    for off, cap_id, nxt in found:
        # Every start above this one, still ascending, so later[0] is the nearest; an empty
        # list means this is the highest capability and the span runs to 100h.
        later = [s for s in starts if s > off]
        end = later[0] if later else PCI_COMPATIBLE_END
        end = min(end, cs.size)  # only a hand-built dump shorter than 256 bytes ever clamps
        span = end - off
        data = cs.bytes_at(off, span)
        problem = ""
        if cap_id == 0x00:
            problem = "ID 00h is not a capability ID"
        elif cap_id == 0xFF:
            problem = "ID FFh: reads like an unpowered or absent device"
        cap = Capability(
            offset=off,
            cap_id=cap_id,
            next_pointer=nxt,
            name=ids.standard_cap_name(cap_id),
            taught=cap_id in ids.TAUGHT_STANDARD_CAPS,
            span=span,
            data=data,
            problem=problem,
        )
        vs_length = cap.vendor_specific_length
        length = cap.structure_length  # spec-fixed, declared, or from Message Control; None if unknown
        if vs_length is not None and vs_length < 3:
            cap.problem = f"declared length {vs_length:02X}h is below the 3 header bytes it must include (7.9.4 Table 7-160)"
        elif length is not None and length > span:
            what = "declared length" if cap.cap_id == 0x09 else "structure"
            cap.problem = f"{what} {length} bytes runs past {cap.boundary_text}; only {span} bytes are there"
        entries.append(cap)
    return entries
