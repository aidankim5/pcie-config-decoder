"""MSI (ID 05h, spec 7.7.1) and MSI-X (ID 11h, spec 7.7.2).

[Taught] MSI basics: Aidan decoded the GPU's MSI capability by hand (Enable,
1 of 1 vectors, 64-bit address FEE00D58h, data 0000h).
[Ahead] MSI-X: the table and PBA live in memory space behind a BAR; only the
three configuration-space registers are decoded here.

MSI layout (7.7.1, Figures 7-44 to 7-47): which registers exist, and where,
depends on two Message Control bits, so the structure has four shapes:
  +00h ID / +01h next, +02h Message Control (always)
  +04h Message Address (always)
  +08h Message Upper Address   only when 64-bit Address Capable (bit 7)
  Message Data (16 bits) + Extended Message Data (upper 16 bits of the same
  DWORD): at +08h for 32-bit, +0Ch for 64-bit
  Mask Bits and Pending Bits (one DWORD each), only when Per-Vector Masking
  Capable (bit 8): at +0Ch/+10h for 32-bit, +10h/+14h for 64-bit
So the structure is 12, 16, 20 or 24 bytes (Linux pci_regs.h agrees:
PCI_MSI_MASK_64 0x10, PCI_MSI_PENDING_64 0x14).

MSI-X layout (7.7.2, Figure 7-56): 12 bytes, always the same:
  +02h Message Control, +04h Table Offset / Table BIR, +08h PBA Offset / PBA BIR.
"""

from dataclasses import dataclass

from .header import bit, bits
from .parse import ConfigSpace

MSIX_STRUCTURE_LENGTH = 12  # 7.7.2 Figure 7-56: +00h through +0Bh

# Message Control bits 3:1 / 6:4 (7.7.1.2 Table 7-39): the vector count is 2^code, codes 6 and 7 reserved.
VECTOR_COUNTS = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16, 5: 32}

# Table BIR / PBA BIR bits 2:0 (7.7.2.3 Table 7-48): which BAR slot holds the table.
BIR_TO_BAR_OFFSET = {0: 0x10, 1: 0x14, 2: 0x18, 3: 0x1C, 4: 0x20, 5: 0x24}


def msi_structure_length(message_control: int) -> int:
    """Bytes in the MSI structure, from Message Control bits 7 (64-bit) and 8 (per-vector masking)."""
    length = 12  # header, Message Control, Message Address, Message Data DWORD (Figure 7-44)
    if bit(message_control, 7):
        length += 4  # Message Upper Address at +08h (Figures 7-45, 7-47)
    if bit(message_control, 8):
        length += 8  # Mask Bits and Pending Bits (Figures 7-46, 7-47)
    return length


@dataclass
class Msi:
    offset: int  # absolute offset of the capability's first byte
    message_control: int  # +02h, raw 16 bits (7.7.1.2 Table 7-39)
    enable: bool  # bit 0
    multiple_message_capable: int  # bits 3:1, code: 2^code vectors requested
    multiple_message_enable: int  # bits 6:4, code: 2^code vectors allocated
    address_64bit: bool  # bit 7
    per_vector_masking: bool  # bit 8
    extended_data_capable: bool  # bit 9
    extended_data_enable: bool  # bit 10
    message_address: int  # +04h (7.7.1.3), bits 31:2 meaningful; 1:0 read as 0
    message_upper_address: int | None  # +08h (7.7.1.4), only when address_64bit
    data_offset: int  # relative offset of the Message Data DWORD: 08h or 0Ch
    message_data: int  # low 16 bits of that DWORD (7.7.1.5)
    extended_message_data: int  # high 16 bits of that DWORD (7.7.1.6); meaningful only if capable
    mask_bits: int | None  # +0Ch or +10h (7.7.1.7), only when per_vector_masking
    pending_bits: int | None  # +10h or +14h (7.7.1.8), only when per_vector_masking

    @property
    def vectors_capable(self) -> int:
        return VECTOR_COUNTS.get(self.multiple_message_capable, 0)  # 0 = reserved code

    @property
    def vectors_enabled(self) -> int:
        return VECTOR_COUNTS.get(self.multiple_message_enable, 0)

    @property
    def full_address(self) -> int:
        """The 64-bit message address: upper DWORD shifted up 32, or just the low DWORD."""
        upper = self.message_upper_address or 0
        return (upper << 32) | self.message_address

    @property
    def structure_length(self) -> int:
        return msi_structure_length(self.message_control)

    @property
    def mask_offset(self) -> int | None:
        return self.data_offset + 4 if self.per_vector_masking else None

    @property
    def pending_offset(self) -> int | None:
        return self.data_offset + 8 if self.per_vector_masking else None


def decode_msi_message_control(value: int) -> dict:
    """Spec 7.7.1.2, Message Control Register for MSI, capability offset 02h, Table 7-39."""
    return {
        "enable": bit(value, 0),
        "multiple_message_capable": bits(value, 3, 1),
        "multiple_message_enable": bits(value, 6, 4),
        "address_64bit": bit(value, 7),
        "per_vector_masking": bit(value, 8),
        "extended_data_capable": bit(value, 9),
        "extended_data_enable": bit(value, 10),
    }


def decode_msi(cs: ConfigSpace, offset: int) -> Msi:
    """Spec 7.7.1, the MSI structure at absolute `offset`; its shape follows Message Control."""
    control = cs.u16(offset + 0x02)
    fields = decode_msi_message_control(control)
    upper = None
    data_offset = 0x08  # Figure 7-44: Message Data right after Message Address
    if fields["address_64bit"]:
        upper = cs.u32(offset + 0x08)  # Figure 7-45: Upper Address takes +08h
        data_offset = 0x0C  # ... and pushes Message Data to +0Ch
    data_dword = cs.u32(offset + data_offset)
    mask = pending = None
    if fields["per_vector_masking"]:
        mask = cs.u32(offset + data_offset + 4)  # Figures 7-46/7-47: Mask right after the data DWORD
        pending = cs.u32(offset + data_offset + 8)
    return Msi(
        offset=offset,
        message_control=control,
        **fields,
        message_address=cs.u32(offset + 0x04),
        message_upper_address=upper,
        data_offset=data_offset,
        message_data=bits(data_dword, 15, 0),
        extended_message_data=bits(data_dword, 31, 16),
        mask_bits=mask,
        pending_bits=pending,
    )


@dataclass
class MsiX:
    offset: int  # absolute offset of the capability's first byte
    message_control: int  # +02h, raw 16 bits (7.7.2.2 Table 7-47)
    table_size_code: int  # bits 10:0, encoded N-1
    function_mask: bool  # bit 14: every vector masked regardless of per-entry bits
    enable: bool  # bit 15
    table_register: int  # +04h raw (7.7.2.3 Table 7-48)
    table_bir: int  # bits 2:0: which BAR holds the table
    table_offset: int  # bits 31:3, the low 3 bits read as 0 (QWORD aligned)
    pba_register: int  # +08h raw (7.7.2.4 Table 7-49)
    pba_bir: int
    pba_offset: int

    @property
    def table_size(self) -> int:
        """N entries; the field holds N-1 (Table 7-47), so 17 entries read as 16."""
        return self.table_size_code + 1

    @property
    def table_bar_offset(self) -> int | None:
        return BIR_TO_BAR_OFFSET.get(self.table_bir)  # None for the reserved codes 6 and 7

    @property
    def pba_bar_offset(self) -> int | None:
        return BIR_TO_BAR_OFFSET.get(self.pba_bir)

    @property
    def structure_length(self) -> int:
        return MSIX_STRUCTURE_LENGTH


def decode_msix(cs: ConfigSpace, offset: int) -> MsiX:
    """Spec 7.7.2, the 12-byte MSI-X structure at absolute `offset`."""
    control = cs.u16(offset + 0x02)
    table = cs.u32(offset + 0x04)
    pba = cs.u32(offset + 0x08)
    return MsiX(
        offset=offset,
        message_control=control,
        table_size_code=bits(control, 10, 0),
        function_mask=bit(control, 14),
        enable=bit(control, 15),
        table_register=table,
        table_bir=bits(table, 2, 0),
        table_offset=table & ~0x7,  # bits 31:3; ~0x7 clears the BIR bits (same ~mask idea as header.py)
        pba_register=pba,
        pba_bir=bits(pba, 2, 0),
        pba_offset=pba & ~0x7,
    )
