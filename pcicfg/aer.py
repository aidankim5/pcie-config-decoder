"""Advanced Error Reporting, extended capability ID 0001h (spec 7.8.4).

[Taught] Aidan decoded the GPU's AER block at 420h by hand: the Uncorrectable
Error Status, Mask and Severity registers, the Correctable Error Status and
Mask, the Capabilities and Control register, and the Header Log. The finding
that matters for fleet telemetry: the GPU's Correctable Error Status reads
00002000h, bit 13, one logged Advisory Non-Fatal Error.

Layout (7.8.4 Figure 7-122), offsets relative to the capability's start:
  +00h Extended Capability Header       (7.8.4.1)
  +04h Uncorrectable Error Status       (7.8.4.2, Table 7-100)
  +08h Uncorrectable Error Mask         (7.8.4.3, Table 7-101)
  +0Ch Uncorrectable Error Severity     (7.8.4.4, Table 7-102)
  +10h Correctable Error Status         (7.8.4.5, Table 7-103)
  +14h Correctable Error Mask           (7.8.4.6, Table 7-104)
  +18h Advanced Error Capabilities and Control (7.8.4.7, Table 7-105)
  +1Ch Header Log, four DWORDs          (7.8.4.8, Table 7-106, Figure 7-130)
  +2Ch Root Error Command               (7.8.4.9)   Root Ports and Root Complex
  +30h Root Error Status                (7.8.4.10)  Event Collectors only; read
  +34h Error Source Identification      (7.8.4.11)  zero on other Functions
  +38h TLP Prefix Log, four DWORDs      (7.8.4.12)  only when TLP Prefix Log Present

The three uncorrectable registers share one bit layout, and so do the two
correctable ones; each is written once below and reused, which is exactly
how the spec presents them. A set bit means: Status, the error happened;
Mask, the error is not reported; Severity, the error is reported as fatal.

Header Log byte order (7.8.4.8, quoted): "byte 0 of the header is located in
byte 3 of the Header Log Register, byte 1 of the header is in byte 2 ... and
so forth." So each DWORD read little-endian already has header byte 0 in its
top byte, and printing the four DWORDs as 8-digit numbers shows the header in
the order it went over the link, the way lspci prints HeaderLog.
"""

from dataclasses import dataclass

from .header import bit, bits
from .parse import ConfigSpace
from .pcie_cap import Register, hex_text, make_register, reserved_text

# Bit positions shared by Uncorrectable Error Status / Mask / Severity (Tables 7-100 to 7-102).
UNCORRECTABLE_BITS = [
    (4, "Data Link Protocol Error"),
    (5, "Surprise Down Error"),
    (12, "Poisoned TLP Received"),
    (13, "Flow Control Protocol Error"),
    (14, "Completion Timeout"),
    (15, "Completer Abort"),
    (16, "Unexpected Completion"),
    (17, "Receiver Overflow"),
    (18, "Malformed TLP"),
    (19, "ECRC Error"),
    (20, "Unsupported Request Error"),
    (21, "ACS Violation"),
    (22, "Uncorrectable Internal Error"),
    (23, "MC Blocked TLP"),
    (24, "AtomicOp Egress Blocked"),
    (25, "TLP Prefix Blocked Error"),
    (26, "Poisoned TLP Egress Blocked"),
]
UNCORRECTABLE_RESERVED = [(0, 0, "Undefined (was Link Training Error)", reserved_text), (3, 1, "Reserved", reserved_text),
                          (11, 6, "Reserved", reserved_text), (31, 27, "Reserved", reserved_text)]

# Bit positions shared by Correctable Error Status / Mask (Tables 7-103, 7-104).
CORRECTABLE_BITS = [
    (0, "Receiver Error"),
    (6, "Bad TLP"),
    (7, "Bad DLLP"),
    (8, "REPLAY_NUM Rollover"),
    (12, "Replay Timer Timeout"),
    (13, "Advisory Non-Fatal Error"),
    (14, "Corrected Internal Error"),
    (15, "Header Log Overflow"),
]
CORRECTABLE_RESERVED = [(5, 1, "Reserved", reserved_text), (11, 9, "Reserved", reserved_text), (31, 16, "Reserved", reserved_text)]

# Spec 5.0 default of the Severity register: bits 4, 5, 13, 17, 18, 22 set = 00462030h (Table 7-102).
SEVERITY_DEFAULT = 0x00462030


def error_layout(named: list[tuple[int, str]], reserved: list[tuple], fmt, note: str) -> list[tuple]:
    """A layout with one row per named error bit plus the reserved ranges, in bit order."""
    rows = [(n, n, name, fmt, note) for n, name in named] + reserved
    return sorted(rows, key=lambda row: row[1])  # by low bit, so the rows print in register order


STATUS_TEXT = {0: "-", 1: "+ (error occurred; RW1CS, write 1 to clear)"}
MASK_TEXT = {0: "reported", 1: "masked (not logged, not reported)"}
SEVERITY_TEXT = {0: "non-fatal", 1: "fatal"}

UE_STATUS = error_layout(UNCORRECTABLE_BITS, UNCORRECTABLE_RESERVED, STATUS_TEXT, "RW1CS")
UE_MASK = error_layout(UNCORRECTABLE_BITS, UNCORRECTABLE_RESERVED, MASK_TEXT, "RWS")
UE_SEVERITY = error_layout(UNCORRECTABLE_BITS, UNCORRECTABLE_RESERVED, SEVERITY_TEXT, "RWS")
CE_STATUS = error_layout(CORRECTABLE_BITS, CORRECTABLE_RESERVED, STATUS_TEXT, "RW1CS")
CE_MASK = error_layout(CORRECTABLE_BITS, CORRECTABLE_RESERVED, MASK_TEXT, "RWS")

# 7.8.4.7 Table 7-105, Advanced Error Capabilities and Control, offset 18h.
CAPS_CONTROL = [
    (4, 0, "First Error Pointer", lambda v: f"bit {v} of Uncorrectable Error Status", "meaningful while that status bit is set (an inference from 7.8.4.7 and 6.2)"),
    (5, 5, "ECRC Generation Capable", None),
    (6, 6, "ECRC Generation Enable", None),
    (7, 7, "ECRC Check Capable", None),
    (8, 8, "ECRC Check Enable", None),
    (9, 9, "Multiple Header Recording Capable", None),
    (10, 10, "Multiple Header Recording Enable", None),
    (11, 11, "TLP Prefix Log Present", None, "RsvdP unless End-End TLP Prefix Supported"),
    (12, 12, "Completion Timeout Prefix/Header Log Capable", None),
    (31, 13, "RsvdP", reserved_text),
]

# 7.8.4.9 Table 7-107, Root Error Command, offset 2Ch.
ROOT_ERROR_COMMAND = [
    (0, 0, "Correctable Error Reporting Enable", None),
    (1, 1, "Non-Fatal Error Reporting Enable", None),
    (2, 2, "Fatal Error Reporting Enable", None),
    (31, 3, "RsvdP", reserved_text),
]
# 7.8.4.10 Table 7-108, Root Error Status, offset 30h.
ERR_COR_SUBCLASS = {0: "ECS Legacy", 1: "ECS SIG_SFW", 2: "ECS SIG_OS", 3: "ECS Extended"}
ROOT_ERROR_STATUS = [
    (0, 0, "ERR_COR Received", None, "RW1CS"),
    (1, 1, "Multiple ERR_COR Received", None, "RW1CS"),
    (2, 2, "ERR_FATAL/NONFATAL Received", None, "RW1CS"),
    (3, 3, "Multiple ERR_FATAL/NONFATAL Received", None, "RW1CS"),
    (4, 4, "First Uncorrectable Fatal", None, "RW1CS"),
    (5, 5, "Non-Fatal Error Messages Received", None, "RW1CS"),
    (6, 6, "Fatal Error Messages Received", None, "RW1CS"),
    (8, 7, "ERR_COR Subclass", ERR_COR_SUBCLASS, "valid while ERR_COR Received is set; Table 2-22"),
    (26, 9, "RsvdZ", reserved_text),
    (31, 27, "Advanced Error Interrupt Message Number", lambda v: f"{v}"),
]
# 7.8.4.11, Error Source Identification, offset 34h: two Requester IDs (bus 15:8, device 7:3, function 2:0).
ERROR_SOURCE_ID = [
    (15, 0, "ERR_COR Source Identification", hex_text(16), "Requester ID of the last ERR_COR"),
    (31, 16, "ERR_FATAL/NONFATAL Source Identification", hex_text(16), "Requester ID of the first ERR_FATAL/NONFATAL"),
]

ROOT_PORT_TYPES = {4, 10}  # Root Port, Root Complex Event Collector (7.5.3.2)


def aer_structure_length(caps_control: int, is_root: bool) -> int:
    """Bytes in the structure: 2Ch for a non-root Function, 38h with the Root Error registers,
    48h when the TLP Prefix Log is present (7.8.4 Figure 7-122).

    A choice, like the other structure sizes: the spec draws the whole figure
    for every Function and says which registers are reserved where.
    """
    if bit(caps_control, 11):  # TLP Prefix Log Present: the log at 38h exists, so everything before it too
        return 0x48
    return 0x38 if is_root else 0x2C


@dataclass
class Aer:
    offset: int  # absolute offset of the capability header
    version: int  # header bits 19:16
    is_root: bool  # Root Port or Event Collector: the Root Error registers apply
    registers: list[Register]
    header_log: list[int]  # four DWORDs at +1Ch, each read little-endian
    tlp_prefix_log: list[int] | None  # four DWORDs at +38h when TLP Prefix Log Present

    def register(self, key: str) -> Register:
        for r in self.registers:
            if r.key == key:
                return r
        raise KeyError(key)

    def _set_names(self, key: str) -> list[str]:
        r = self.register(key)
        return [f.name for f in r.fields if f.hi == f.lo and f.value == 1 and not f.name.startswith(("Reserved", "Undefined", "RsvdP", "RsvdZ"))]

    @property
    def uncorrectable_errors(self) -> list[str]:
        return self._set_names("ue_status")

    @property
    def correctable_errors(self) -> list[str]:
        return self._set_names("ce_status")

    @property
    def uncorrectable_masked(self) -> list[str]:
        return self._set_names("ue_mask")

    @property
    def fatal_errors(self) -> list[str]:
        """Errors whose Severity bit is set: reported as ERR_FATAL when they occur."""
        return self._set_names("ue_severity")

    @property
    def correctable_masked(self) -> list[str]:
        return self._set_names("ce_mask")

    @property
    def first_error_pointer(self) -> int:
        return self.register("caps_control").value("First Error Pointer")

    @property
    def severity_is_spec_default(self) -> bool:
        return self.register("ue_severity").raw == SEVERITY_DEFAULT

    @property
    def header_log_wire_bytes(self) -> bytes:
        """The logged TLP header in link order: DWORD n big-endian gives header bytes 4n..4n+3 (7.8.4.8)."""
        return b"".join(dw.to_bytes(4, "big") for dw in self.header_log)

    @property
    def structure_length(self) -> int:
        return aer_structure_length(self.register("caps_control").raw, self.is_root)

    @property
    def summary(self) -> str:
        """The two lines of a fleet health check: what happened, and what would be fatal."""
        ue = ", ".join(self.uncorrectable_errors) or "none"
        ce = ", ".join(self.correctable_errors) or "none"
        return f"uncorrectable errors logged: {ue}; correctable errors logged: {ce}; first error pointer bit {self.first_error_pointer}"


def decode_aer(cs: ConfigSpace, offset: int, is_root: bool = False) -> Aer:
    """Spec 7.8.4: every AER register at absolute `offset`; Root Error registers only when is_root."""
    header = cs.u32(offset)
    caps_control = cs.u32(offset + 0x18)
    regs = [
        make_register("ue_status", "Uncorrectable Error Status", "7.8.4.2", 0x04, 32, cs.u32(offset + 0x04), UE_STATUS),
        make_register("ue_mask", "Uncorrectable Error Mask", "7.8.4.3", 0x08, 32, cs.u32(offset + 0x08), UE_MASK),
        make_register("ue_severity", "Uncorrectable Error Severity", "7.8.4.4", 0x0C, 32, cs.u32(offset + 0x0C), UE_SEVERITY),
        make_register("ce_status", "Correctable Error Status", "7.8.4.5", 0x10, 32, cs.u32(offset + 0x10), CE_STATUS),
        make_register("ce_mask", "Correctable Error Mask", "7.8.4.6", 0x14, 32, cs.u32(offset + 0x14), CE_MASK),
        make_register("caps_control", "Advanced Error Capabilities and Control", "7.8.4.7", 0x18, 32, caps_control, CAPS_CONTROL),
    ]
    header_log = [cs.u32(offset + 0x1C + 4 * n) for n in range(4)]
    if is_root:
        regs += [
            make_register("root_error_command", "Root Error Command", "7.8.4.9", 0x2C, 32, cs.u32(offset + 0x2C), ROOT_ERROR_COMMAND),
            make_register("root_error_status", "Root Error Status", "7.8.4.10", 0x30, 32, cs.u32(offset + 0x30), ROOT_ERROR_STATUS),
            make_register("error_source_id", "Error Source Identification", "7.8.4.11", 0x34, 32, cs.u32(offset + 0x34), ERROR_SOURCE_ID),
        ]
    prefix_log = None
    if bit(caps_control, 11):
        prefix_log = [cs.u32(offset + 0x38 + 4 * n) for n in range(4)]
    return Aer(
        offset=offset,
        version=bits(header, 19, 16),
        is_root=is_root,
        registers=regs,
        header_log=header_log,
        tlp_prefix_log=prefix_log,
    )
