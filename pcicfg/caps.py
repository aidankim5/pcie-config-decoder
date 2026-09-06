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
  "00h if no more"), 7.7.1.1 (MSI), 7.7.2.1 (MSI-X). Vendor-Specific
  (7.9.4) adds a third byte, Capability Length.
- The ID and the next pointer are two separate one-byte fields. Reading them
  as one little-endian 16-bit number would put the pointer in the high byte;
  this module never does that.

Frame: this chain lives at 40h-FFh, inside what the CF8/CFC mechanism can
reach (spec 7.2.1). It never enters the extended space at 100h; that chain
is a different list with a different header format (extcaps.py).

The guards below are choices, not spec. Each one says what it protects
against at the point it is applied.
"""

from dataclasses import dataclass

from . import ids
from .header import bit
from .parse import ConfigSpace

FIRST_CAP_OFFSET = 0x40  # the header occupies 00h-3Fh (spec 7.5.1.2), so a capability cannot start below 40h
LAST_OFFSET = 0xFF  # the PCI-compatible space ends here (spec 7.2.1); a pointer past it is corrupt
MAX_HOPS = 48  # (100h - 40h) / 4: only 48 DWORD-aligned starts exist in 40h-FFh, so more hops means a loop


@dataclass
class Capability:
    """One entry of the chain: where it is, what it is, and its bytes."""

    offset: int  # absolute offset of byte 0 (the ID)
    cap_id: int  # byte 0
    next_pointer: int  # byte 1, as read (00h = end of list)
    name: str
    taught: bool  # CLAUDE.md rule 5: has Aidan decoded this capability's registers by hand?
    span: int  # bytes from this start to the next capability start in address order, or to 100h
    data: bytes  # the `span` bytes, so each capability can be read from 00 (relative offsets)
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

    @property
    def offsets(self) -> list[int]:
        return [c.offset for c in self.entries]


def walk_standard_caps(cs: ConfigSpace) -> CapabilityChain:
    """Spec 7.5.1.1.11: follow the list from the Capabilities Pointer at 34h until a 00h pointer.

    Each hop reads two one-byte fields at the pointer: byte 0 = Capability ID,
    byte 1 = Next Capability Pointer (7.5.3.1 Table 7-17 and the matching table
    of every other capability). Stops, with a note saying why, on a pointer
    into the header, an unaligned pointer, a pointer past FFh, a revisit, or
    more hops than there are aligned slots.
    """
    status = cs.u16(0x06)
    has_list = bit(status, 4)
    pointer_raw = cs.u8(0x34)
    pointer = pointer_raw & ~0x3  # bits 1:0 reserved (7.5.1.1.11); ~ flips all bits, & clears those two
    chain = CapabilityChain(pointer_raw, pointer, has_list, [], [])

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
            f"Capabilities Pointer bits 1:0 were set ({pointer_raw:02x}h); masked to {pointer:02x}h per 7.5.1.1.11"
        )

    visited: set[int] = set()  # every offset already read, to catch a loop
    found: list[tuple[int, int, int]] = []  # (offset, id, next) in link order
    ptr = pointer
    while ptr != 0:  # 00h ends the list (7.5.3.1 Table 7-17)
        if ptr < FIRST_CAP_OFFSET:
            chain.notes.append(f"pointer {ptr:02x}h points into the header (00h-3Fh): stopped")
            break
        if ptr & 0x3:
            chain.notes.append(f"pointer {ptr:02x}h is not DWORD aligned: stopped")
            break
        if ptr + 1 > LAST_OFFSET or ptr + 1 >= cs.size:
            chain.notes.append(f"pointer {ptr:02x}h is past the end of the PCI-compatible space: stopped")
            break
        if ptr in visited:
            chain.notes.append(f"pointer {ptr:02x}h was already visited: the list loops, stopped")
            break
        if len(visited) >= MAX_HOPS:
            # Cannot trigger while `visited` works (48 aligned slots), kept as a second fence.
            chain.notes.append(f"more than {MAX_HOPS} hops: stopped")
            break
        visited.add(ptr)
        cap_id = cs.u8(ptr)  # byte 0: the ID
        nxt = cs.u8(ptr + 1)  # byte 1: the next pointer; a separate field, not the high byte of a word
        found.append((ptr, cap_id, nxt))
        ptr = nxt

    chain.entries = _build_entries(cs, found)
    return chain


def _build_entries(cs: ConfigSpace, found: list[tuple[int, int, int]]) -> list[Capability]:
    """Give each entry its name, tag, and byte span.

    The span runs to the next capability start in ADDRESS order (or to 100h),
    which is how the chain reads by eye: "this section starts from 00 and
    runs until the next one begins". Link order can differ from address order.
    """
    starts = sorted(off for off, _, _ in found)
    entries = []
    for off, cap_id, nxt in found:
        later = [s for s in starts if s > off]
        end = later[0] if later else FIRST_CAP_OFFSET + 0xC0  # 100h: the end of PCI-compatible space
        end = min(end, cs.size)
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
        length = cap.vendor_specific_length
        if length is not None and length > span:
            cap.problem = f"declared length {length:02x}h runs past the next capability at {end:02x}h"
        entries.append(cap)
    return entries
