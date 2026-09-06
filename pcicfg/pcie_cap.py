"""The PCI Express Capability, ID 10h (spec 7.5.3): every register.

[Taught] Aidan decoded the GPU's PCI Express capability by hand, including
Link Status 0x1101 at capability offset 12h (absolute 8Ah): 2.5 GT/s, x16,
downgraded from the 16 GT/s the Link Capabilities register allows.

Structure (7.5.3 Figure 7-21), offsets relative to the capability's start:
  +00h Capability ID (10h) / +01h Next Capability Pointer   (7.5.3.1)
  +02h PCI Express Capabilities (16 bits)                    (7.5.3.2)
  +04h Device Capabilities (32)  +08h Device Control (16)  +0Ah Device Status (16)
  +0Ch Link Capabilities (32)    +10h Link Control (16)    +12h Link Status (16)
  +14h Slot Capabilities (32)    +18h Slot Control (16)    +1Ah Slot Status (16)
  +1Ch Root Control (16)         +1Eh Root Capabilities (16)  +20h Root Status (32)
  +24h Device Capabilities 2     +28h Device Control 2     +2Ah Device Status 2
  +2Ch Link Capabilities 2       +30h Link Control 2       +32h Link Status 2
  +34h Slot Capabilities 2       +38h Slot Control 2       +3Ah Slot Status 2
Registers that do not apply to a Function read as zero: endpoints have no
Slot or Root registers (spec 7.5.3, page 718).

Every bit range below was transcribed from the register's own table in the
spec text and checked by two independent readers; the encodings (speeds,
widths, payload sizes, latencies, timeouts) come from the same tables. The
code is laid out as those tables: one row per field, high bit, low bit, name,
and how to read the value.

Structure size (a choice, following Linux pci_regs.h): Capability Version 2
or higher runs to +3Bh, 60 bytes, with the Slot 2 registers hardwired zero on
Functions without slots; version 1 ends after Link Status (+13h, 20 bytes)
or, for Root Complex Integrated Endpoints and Event Collectors that have no
Link, after Device Status (+0Bh, 12 bytes).
"""

from dataclasses import dataclass

from .header import bit, bits
from .parse import ConfigSpace

# --- encodings, each from the table named ----------------------------------------

# Link speeds: Max Link Speed (7.5.3.6), Current Link Speed (7.5.3.8) and Target Link Speed
# (7.5.3.19) all hold an index into the Supported Link Speeds Vector; code n means vector bit
# n-1, and Table 7-33 (7.5.3.18) gives the speed for each vector bit.
SPEED_GTS = {1: 2.5, 2: 5.0, 3: 8.0, 4: 16.0, 5: 32.0}
SUPPORTED_SPEEDS_VECTOR = [2.5, 5.0, 8.0, 16.0, 32.0]  # Table 7-33: vector bit 0 .. bit 4; bits 6:5 RsvdP


def speed_text(code: int) -> str:
    if code in SPEED_GTS:
        return f"{SPEED_GTS[code]:g} GT/s"
    if code in (6, 7):
        return f"code {code}: vector bit {code - 1}, reserved in PCIe 5.0"
    return f"code {code}: reserved"


# Maximum Link Width (7.5.3.6) and Negotiated Link Width (7.5.3.8), bits 9:4.
WIDTHS = {1: "x1", 2: "x2", 4: "x4", 8: "x8", 12: "x12", 16: "x16", 32: "x32"}


def width_text(code: int) -> str:
    return WIDTHS.get(code, f"code {code}: reserved")


# Max_Payload_Size Supported (7.5.3.3), Max_Payload_Size and Max_Read_Request_Size (7.5.3.4).
PAYLOAD_BYTES = {0: 128, 1: 256, 2: 512, 3: 1024, 4: 2048, 5: 4096}


def payload_text(code: int) -> str:
    return f"{PAYLOAD_BYTES[code]} bytes" if code in PAYLOAD_BYTES else f"code {code}: reserved"


# 7.5.3.2 Table 7-18, Device/Port Type bits 7:4.
DEVICE_PORT_TYPES = {
    0: "PCI Express Endpoint",
    1: "Legacy PCI Express Endpoint",
    4: "Root Port of PCI Express Root Complex",
    5: "Upstream Port of PCI Express Switch",
    6: "Downstream Port of PCI Express Switch",
    7: "PCI Express to PCI/PCI-X Bridge",
    8: "PCI/PCI-X to PCI Express Bridge",
    9: "Root Complex Integrated Endpoint",
    10: "Root Complex Event Collector",
}

# 7.5.3.3 Table 7-19.
PHANTOM_FUNCTIONS = {0: "none", 1: "1 bit (Functions 0-3 implemented)", 2: "2 bits (Functions 0-1)", 3: "3 bits (Function 0 only)"}
L0S_ACCEPTABLE = {0: "max 64 ns", 1: "max 128 ns", 2: "max 256 ns", 3: "max 512 ns", 4: "max 1 us", 5: "max 2 us", 6: "max 4 us", 7: "no limit"}
L1_ACCEPTABLE = {0: "max 1 us", 1: "max 2 us", 2: "max 4 us", 3: "max 8 us", 4: "max 16 us", 5: "max 32 us", 6: "max 64 us", 7: "no limit"}
POWER_SCALE = {0: "1.0x", 1: "0.1x", 2: "0.01x", 3: "0.001x"}

# 7.5.3.6 Table 7-22.
ASPM_SUPPORT = {0: "no ASPM", 1: "L0s", 2: "L1", 3: "L0s and L1"}
L0S_EXIT = {0: "< 64 ns", 1: "64 ns to < 128 ns", 2: "128 ns to < 256 ns", 3: "256 ns to < 512 ns",
            4: "512 ns to < 1 us", 5: "1 us to < 2 us", 6: "2 us to 4 us", 7: "> 4 us"}
L1_EXIT = {0: "< 1 us", 1: "1 us to < 2 us", 2: "2 us to < 4 us", 3: "4 us to < 8 us",
           4: "8 us to < 16 us", 5: "16 us to < 32 us", 6: "32 us to 64 us", 7: "> 64 us"}

# 7.5.3.7 Table 7-23.
ASPM_CONTROL = {0: "disabled", 1: "L0s entry enabled", 2: "L1 entry enabled", 3: "L0s and L1 entry enabled"}
RCB = {0: "64 bytes", 1: "128 bytes"}
DRS_SIGNALING = {0: "DRS not reported", 1: "DRS interrupt enabled", 2: "DRS to FRS signaling enabled", 3: "undefined"}

# 7.5.3.10 Table 7-26.
INDICATOR = {0: "reserved", 1: "on", 2: "blink", 3: "off"}
POWER_CONTROLLER = {0: "power on", 1: "power off"}

# 7.5.3.15 Table 7-31. Completion Timeout ranges: A 50 us-10 ms, B 10 ms-250 ms, C 250 ms-4 s, D 4 s-64 s.
CT_RANGES = {0: "not programmable (50 us to 50 ms)", 1: "A", 2: "B", 3: "A and B", 6: "B and C",
             7: "A, B and C", 14: "B, C and D", 15: "A, B, C and D"}
TPH_COMPLETER = {0: "not supported", 1: "TPH Completer", 2: "reserved", 3: "TPH and Extended TPH Completer"}
LN_SYSTEM_CLS = {0: "not supported or not in effect", 1: "64-byte cachelines", 2: "128-byte cachelines", 3: "reserved"}
OBFF_SUPPORT = {0: "not supported", 1: "Message signaling", 2: "WAKE# signaling", 3: "WAKE# and Message signaling"}
MAX_E2E_PREFIXES = {1: "1", 2: "2", 3: "3", 0: "4"}
EMERGENCY_POWER = {0: "not supported", 1: "device-specific trigger", 2: "form-factor or device-specific trigger", 3: "reserved"}

# 7.5.3.16 Table 7-32.
CT_VALUES = {0: "50 us to 50 ms (default)", 1: "50 us to 100 us", 2: "1 ms to 10 ms", 5: "16 ms to 55 ms",
             6: "65 ms to 210 ms", 9: "260 ms to 900 ms", 10: "1 s to 3.5 s", 13: "4 s to 13 s", 14: "17 s to 64 s"}
OBFF_ENABLE = {0: "disabled", 1: "Message signaling, variation A", 2: "Message signaling, variation B", 3: "WAKE# signaling"}

# 7.5.3.19 / 7.5.3.20.
DEEMPHASIS = {0: "-6 dB", 1: "-3.5 dB"}
CROSSLINK_RESOLUTION = {0: "unsupported", 1: "resolved as Upstream Port", 2: "resolved as Downstream Port", 3: "not completed"}
DOWNSTREAM_PRESENCE = {0: "Link Down, presence not determined", 1: "Link Down, component not present",
                       2: "Link Down, component present", 3: "reserved", 4: "Link Up, component present",
                       5: "Link Up, component present and DRS received", 6: "reserved", 7: "reserved"}


def speeds_vector_text(vector: int) -> str:
    """The Supported Link Speeds Vector as a list: bit n set -> SUPPORTED_SPEEDS_VECTOR[n]."""
    names = [f"{s:g}" for n, s in enumerate(SUPPORTED_SPEEDS_VECTOR) if bit(vector, n)]
    if bits(vector, 6, 5):
        names.append("reserved bits 6:5 set")
    return (", ".join(names) + " GT/s") if names else "none"


# --- the generic register: a list of fields, as the spec tables are ------------------

@dataclass
class Field:
    hi: int
    lo: int
    name: str
    value: int
    text: str  # what the value means, from the spec's table
    note: str = ""  # attribute or applicability, e.g. "RW1C", "Downstream Ports only"

    @property
    def bits_label(self) -> str:
        return str(self.hi) if self.hi == self.lo else f"{self.hi}:{self.lo}"


@dataclass
class Register:
    key: str  # short name used in JSON and tests, e.g. "link_status"
    name: str
    section: str
    offset: int  # relative to the capability's start
    width: int  # bits
    raw: int
    fields: list[Field]

    def field(self, name: str) -> Field:
        for f in self.fields:
            if f.name == name:
                return f
        raise KeyError(name)

    def value(self, name: str) -> int:
        return self.field(name).value

    def is_set(self, name: str) -> bool:
        return self.value(name) != 0


def decode_fields(raw: int, layout: list[tuple]) -> list[Field]:
    """Apply a layout (rows of hi, lo, name, how-to-read[, note]) to a register value.

    how-to-read is None for a single bit (printed + or -), a dict for an
    enumeration (value -> meaning, unknown values say 'reserved'), or a
    function that turns the value into text.
    """
    out = []
    for row in layout:
        hi, lo, name, fmt = row[:4]
        note = row[4] if len(row) > 4 else ""
        value = bits(raw, hi, lo)
        if fmt is None:
            text = "+" if value else "-"
        elif isinstance(fmt, dict):
            text = fmt.get(value, f"reserved ({value})")
        else:
            text = fmt(value)
        out.append(Field(hi, lo, name, value, text, note))
    return out


def make_register(key: str, name: str, section: str, offset: int, width: int, raw: int, layout: list[tuple]) -> Register:
    return Register(key, name, section, offset, width, raw, decode_fields(raw, layout))


def hex_text(width: int):
    """A how-to-read for raw numeric fields: print as hex of the field's own width."""
    digits = (width + 3) // 4  # 4 bits per hex digit, rounded up
    return lambda v: f"{v:0{digits}x}h"


def reserved_text(v: int) -> str:
    return "0" if v == 0 else f"{v:x}h (reserved bits set)"


# --- the layouts: one row per field, straight from the spec tables -------------------

# 7.5.3.2 Table 7-18, PCI Express Capabilities Register, offset 02h.
PCIE_CAPABILITIES = [
    (3, 0, "Capability Version", lambda v: f"{v}" + ("" if v == 2 else " (spec 5.0 requires 2)")),
    (7, 4, "Device/Port Type", DEVICE_PORT_TYPES),
    (8, 8, "Slot Implemented", None, "Downstream Ports only"),
    (13, 9, "Interrupt Message Number", lambda v: f"{v}", "MSI/MSI-X vector for this capability's status bits"),
    (14, 14, "Undefined (was TCS Routing)", reserved_text),
    (15, 15, "RsvdP", reserved_text),
]

# 7.5.3.3 Table 7-19, Device Capabilities Register, offset 04h.
DEVICE_CAPABILITIES = [
    (2, 0, "Max_Payload_Size Supported", payload_text),
    (4, 3, "Phantom Functions Supported", PHANTOM_FUNCTIONS),
    (5, 5, "Extended Tag Field Supported", lambda v: "8-bit Tag" if v else "5-bit Tag"),
    (8, 6, "Endpoint L0s Acceptable Latency", L0S_ACCEPTABLE),
    (11, 9, "Endpoint L1 Acceptable Latency", L1_ACCEPTABLE),
    (14, 12, "Undefined (legacy Attention Button / Indicators)", reserved_text),
    (15, 15, "Role-Based Error Reporting", None),
    (16, 16, "ERR_COR Subclass Capable", None),
    (17, 17, "RsvdP", reserved_text),
    (25, 18, "Captured Slot Power Limit Value", lambda v: f"{v}", "Upstream Ports only; Watts = value x scale"),
    (27, 26, "Captured Slot Power Limit Scale", POWER_SCALE),
    (28, 28, "Function Level Reset Capability", None),
    (31, 29, "RsvdP (bit 30 is TEE-IO Supported in later revisions)", reserved_text),
]

# 7.5.3.4 Table 7-20, Device Control Register, offset 08h.
DEVICE_CONTROL = [
    (0, 0, "Correctable Error Reporting Enable", None),
    (1, 1, "Non-Fatal Error Reporting Enable", None),
    (2, 2, "Fatal Error Reporting Enable", None),
    (3, 3, "Unsupported Request Reporting Enable", None),
    (4, 4, "Enable Relaxed Ordering", None),
    (7, 5, "Max_Payload_Size", payload_text),
    (8, 8, "Extended Tag Field Enable", None),
    (9, 9, "Phantom Functions Enable", None),
    (10, 10, "Aux Power PM Enable", None, "RWS, sticky"),
    (11, 11, "Enable No Snoop", None),
    (14, 12, "Max_Read_Request_Size", payload_text),
    (15, 15, "Initiate Function Level Reset / Bridge Configuration Retry Enable", None, "reads 0; meaning depends on Function type"),
]

# 7.5.3.5 Table 7-21, Device Status Register, offset 0Ah.
DEVICE_STATUS = [
    (0, 0, "Correctable Error Detected", None, "RW1C"),
    (1, 1, "Non-Fatal Error Detected", None, "RW1C"),
    (2, 2, "Fatal Error Detected", None, "RW1C"),
    (3, 3, "Unsupported Request Detected", None, "RW1C"),
    (4, 4, "AUX Power Detected", None),
    (5, 5, "Transactions Pending", None),
    (6, 6, "Emergency Power Reduction Detected", None, "RW1C"),
    (15, 7, "RsvdZ", reserved_text),
]

# 7.5.3.6 Table 7-22, Link Capabilities Register, offset 0Ch.
LINK_CAPABILITIES = [
    (3, 0, "Max Link Speed", speed_text, "index into the Supported Link Speeds Vector"),
    (9, 4, "Maximum Link Width", width_text),
    (11, 10, "ASPM Support", ASPM_SUPPORT),
    (14, 12, "L0s Exit Latency", L0S_EXIT, "undefined when L0s is unsupported"),
    (17, 15, "L1 Exit Latency", L1_EXIT, "undefined when ASPM L1 is unsupported"),
    (18, 18, "Clock Power Management", None, "Upstream Ports: tolerates CLKREQ# clock removal in L1"),
    (19, 19, "Surprise Down Error Reporting Capable", None, "Downstream Ports only"),
    (20, 20, "Data Link Layer Link Active Reporting Capable", None, "Downstream Ports only"),
    (21, 21, "Link Bandwidth Notification Capability", None, "Root Ports and Switch Downstream Ports"),
    (22, 22, "ASPM Optionality Compliance", None),
    (23, 23, "RsvdP", reserved_text),
    (31, 24, "Port Number", lambda v: f"{v}"),
]

# 7.5.3.7 Table 7-23, Link Control Register, offset 10h.
LINK_CONTROL = [
    (1, 0, "ASPM Control", ASPM_CONTROL),
    (2, 2, "RsvdP", reserved_text),
    (3, 3, "Read Completion Boundary (RCB)", RCB),
    (4, 4, "Link Disable", None, "Downstream Ports only"),
    (5, 5, "Retrain Link", None, "reads 0; Downstream Ports only"),
    (6, 6, "Common Clock Configuration", None),
    (7, 7, "Extended Synch", None),
    (8, 8, "Enable Clock Power Management", None),
    (9, 9, "Hardware Autonomous Width Disable", None),
    (10, 10, "Link Bandwidth Management Interrupt Enable", None, "Downstream Ports only"),
    (11, 11, "Link Autonomous Bandwidth Interrupt Enable", None, "Downstream Ports only"),
    (13, 12, "RsvdP", reserved_text),
    (15, 14, "DRS Signaling Control", DRS_SIGNALING, "Downstream Ports only"),
]

# 7.5.3.8 Table 7-24, Link Status Register, offset 12h.
LINK_STATUS = [
    (3, 0, "Current Link Speed", speed_text, "index into the Supported Link Speeds Vector"),
    (9, 4, "Negotiated Link Width", width_text),
    (10, 10, "Undefined (was Link Training Error)", reserved_text),
    (11, 11, "Link Training", None, "Downstream Ports only"),
    (12, 12, "Slot Clock Configuration", None),
    (13, 13, "Data Link Layer Link Active", None, "valid only if Link Capabilities bit 20"),
    (14, 14, "Link Bandwidth Management Status", None, "RW1C; Downstream Ports only"),
    (15, 15, "Link Autonomous Bandwidth Status", None, "RW1C; Downstream Ports only"),
]

# 7.5.3.9 Table 7-25, Slot Capabilities, offset 14h.
SLOT_CAPABILITIES = [
    (0, 0, "Attention Button Present", None),
    (1, 1, "Power Controller Present", None),
    (2, 2, "MRL Sensor Present", None),
    (3, 3, "Attention Indicator Present", None),
    (4, 4, "Power Indicator Present", None),
    (5, 5, "Hot-Plug Surprise", None),
    (6, 6, "Hot-Plug Capable", None),
    (14, 7, "Slot Power Limit Value", lambda v: f"{v}", "Watts = value x scale; F0h-F2h = 250/275/300 W"),
    (16, 15, "Slot Power Limit Scale", POWER_SCALE),
    (17, 17, "Electromechanical Interlock Present", None),
    (18, 18, "No Command Completed Support", None),
    (31, 19, "Physical Slot Number", lambda v: f"{v}"),
]

# 7.5.3.10 Table 7-26, Slot Control, offset 18h.
SLOT_CONTROL = [
    (0, 0, "Attention Button Pressed Enable", None),
    (1, 1, "Power Fault Detected Enable", None),
    (2, 2, "MRL Sensor Changed Enable", None),
    (3, 3, "Presence Detect Changed Enable", None),
    (4, 4, "Command Completed Interrupt Enable", None),
    (5, 5, "Hot-Plug Interrupt Enable", None),
    (7, 6, "Attention Indicator Control", INDICATOR),
    (9, 8, "Power Indicator Control", INDICATOR),
    (10, 10, "Power Controller Control", POWER_CONTROLLER),
    (11, 11, "Electromechanical Interlock Control", None, "write 1 toggles; reads 0"),
    (12, 12, "Data Link Layer State Changed Enable", None),
    (13, 13, "Auto Slot Power Limit Disable", None),
    (14, 14, "In-Band PD Disable", None),
    (15, 15, "RsvdP", reserved_text),
]

# 7.5.3.11 Table 7-27, Slot Status, offset 1Ah.
SLOT_STATUS = [
    (0, 0, "Attention Button Pressed", None, "RW1C"),
    (1, 1, "Power Fault Detected", None, "RW1C"),
    (2, 2, "MRL Sensor Changed", None, "RW1C"),
    (3, 3, "Presence Detect Changed", None, "RW1C"),
    (4, 4, "Command Completed", None, "RW1C"),
    (5, 5, "MRL Sensor State", {0: "closed", 1: "open"}),
    (6, 6, "Presence Detect State", {0: "adapter not present", 1: "adapter present"}),
    (7, 7, "Electromechanical Interlock Status", {0: "disengaged", 1: "engaged"}),
    (8, 8, "Data Link Layer State Changed", None, "RW1C"),
    (15, 9, "RsvdP", reserved_text),
]

# 7.5.3.12 Table 7-28, Root Control, offset 1Ch.
ROOT_CONTROL = [
    (0, 0, "System Error on Correctable Error Enable", None),
    (1, 1, "System Error on Non-Fatal Error Enable", None),
    (2, 2, "System Error on Fatal Error Enable", None),
    (3, 3, "PME Interrupt Enable", None),
    (4, 4, "CRS Software Visibility Enable", None),
    (15, 5, "RsvdP", reserved_text),
]

# 7.5.3.13 Table 7-29, Root Capabilities, offset 1Eh.
ROOT_CAPABILITIES = [
    (0, 0, "CRS Software Visibility", None),
    (15, 1, "RsvdP", reserved_text),
]

# 7.5.3.14 Table 7-30, Root Status, offset 20h.
ROOT_STATUS = [
    (15, 0, "PME Requester ID", hex_text(16), "valid while PME Status is set"),
    (16, 16, "PME Status", None, "RW1C"),
    (17, 17, "PME Pending", None),
    (31, 18, "RsvdZ", reserved_text),
]

# 7.5.3.15 Table 7-31, Device Capabilities 2, offset 24h.
DEVICE_CAPABILITIES_2 = [
    (3, 0, "Completion Timeout Ranges Supported", CT_RANGES, "A 50us-10ms, B 10ms-250ms, C 250ms-4s, D 4s-64s"),
    (4, 4, "Completion Timeout Disable Supported", None),
    (5, 5, "ARI Forwarding Supported", None, "Downstream Ports only"),
    (6, 6, "AtomicOp Routing Supported", None, "Ports only"),
    (7, 7, "32-bit AtomicOp Completer Supported", None),
    (8, 8, "64-bit AtomicOp Completer Supported", None),
    (9, 9, "128-bit CAS Completer Supported", None),
    (10, 10, "No RO-enabled PR-PR Passing", None),
    (11, 11, "LTR Mechanism Supported", None),
    (13, 12, "TPH Completer Supported", TPH_COMPLETER),
    (15, 14, "LN System CLS", LN_SYSTEM_CLS, "Root Ports only"),
    (16, 16, "10-Bit Tag Completer Supported", None),
    (17, 17, "10-Bit Tag Requester Supported", None),
    (19, 18, "OBFF Supported", OBFF_SUPPORT),
    (20, 20, "Extended Fmt Field Supported", None),
    (21, 21, "End-End TLP Prefix Supported", None),
    (23, 22, "Max End-End TLP Prefixes", MAX_E2E_PREFIXES, "meaningful only if End-End TLP Prefix Supported"),
    (25, 24, "Emergency Power Reduction Supported", EMERGENCY_POWER),
    (26, 26, "Emergency Power Reduction Initialization Required", None),
    (30, 27, "RsvdP", reserved_text),
    (31, 31, "FRS Supported", None),
]

# 7.5.3.16 Table 7-32, Device Control 2, offset 28h.
DEVICE_CONTROL_2 = [
    (3, 0, "Completion Timeout Value", CT_VALUES),
    (4, 4, "Completion Timeout Disable", None),
    (5, 5, "ARI Forwarding Enable", None, "Downstream Ports only"),
    (6, 6, "AtomicOp Requester Enable", None),
    (7, 7, "AtomicOp Egress Blocking", None, "Ports only"),
    (8, 8, "IDO Request Enable", None),
    (9, 9, "IDO Completion Enable", None),
    (10, 10, "LTR Mechanism Enable", None),
    (11, 11, "Emergency Power Reduction Request", None),
    (12, 12, "10-Bit Tag Requester Enable", None),
    (14, 13, "OBFF Enable", OBFF_ENABLE),
    (15, 15, "End-End TLP Prefix Blocking", {0: "forwarding enabled", 1: "forwarding blocked"}, "Ports only"),
]

# 7.5.3.17, Device Status 2, offset 2Ah: a placeholder, all RsvdZ.
DEVICE_STATUS_2 = [(15, 0, "RsvdZ (placeholder register)", reserved_text)]

# 7.5.3.18 Table 7-33, Link Capabilities 2, offset 2Ch.
LINK_CAPABILITIES_2 = [
    (0, 0, "RsvdP", reserved_text),
    (7, 1, "Supported Link Speeds Vector", speeds_vector_text, "bit 0 = 2.5 GT/s ... bit 4 = 32.0 GT/s"),
    (8, 8, "Crosslink Supported", None),
    (15, 9, "Lower SKP OS Generation Supported Speeds Vector", speeds_vector_text),
    (22, 16, "Lower SKP OS Reception Supported Speeds Vector", speeds_vector_text),
    (23, 23, "Retimer Presence Detect Supported", None),
    (24, 24, "Two Retimers Presence Detect Supported", None),
    (30, 25, "RsvdP", reserved_text),
    (31, 31, "DRS Supported", None),
]

# 7.5.3.19 Table 7-34, Link Control 2, offset 30h.
LINK_CONTROL_2 = [
    (3, 0, "Target Link Speed", speed_text, "index into the Supported Link Speeds Vector"),
    (4, 4, "Enter Compliance", None),
    (5, 5, "Hardware Autonomous Speed Disable", None),
    (6, 6, "Selectable De-emphasis", DEEMPHASIS, "5.0 GT/s only"),
    (9, 7, "Transmit Margin", lambda v: "normal operating range" if v == 0 else f"{v} (Section 8.3.4)"),
    (10, 10, "Enter Modified Compliance", None),
    (11, 11, "Compliance SOS", None),
    (15, 12, "Compliance Preset/De-emphasis", lambda v: f"{v}" + (" (-6 dB at 5.0 GT/s; preset P0 at 8.0 GT/s and up)" if v == 0 else "")),
]

# 7.5.3.20 Table 7-35, Link Status 2, offset 32h.
LINK_STATUS_2 = [
    (0, 0, "Current De-emphasis Level", DEEMPHASIS, "5.0 GT/s only"),
    (1, 1, "Equalization 8.0 GT/s Complete", None),
    (2, 2, "Equalization 8.0 GT/s Phase 1 Successful", None),
    (3, 3, "Equalization 8.0 GT/s Phase 2 Successful", None),
    (4, 4, "Equalization 8.0 GT/s Phase 3 Successful", None),
    (5, 5, "Link Equalization Request 8.0 GT/s", None, "RW1CS"),
    (6, 6, "Retimer Presence Detected", None),
    (7, 7, "Two Retimers Presence Detected", None),
    (9, 8, "Crosslink Resolution", CROSSLINK_RESOLUTION),
    (11, 10, "RsvdZ (bit 10 is Flit Mode Status in PCIe 6.0)", reserved_text),
    (14, 12, "Downstream Component Presence", DOWNSTREAM_PRESENCE, "Downstream Ports with DRS only"),
    (15, 15, "DRS Message Received", None, "RW1C"),
]

# 7.5.3.21-23: Slot Capabilities 2 / Control 2 / Status 2. [Ahead] not decoded beyond the raw
# value; ports with slots only, and both fixtures read zero.
RAW_ONLY = [(31, 0, "raw (not decoded: ports with slots only)", hex_text(32))]
RAW_ONLY_16 = [(15, 0, "raw (not decoded: ports with slots only)", hex_text(16))]

# The structure, in order: key, name, section, relative offset, width in bits, layout.
REGISTER_TABLE = [
    ("pcie_capabilities", "PCI Express Capabilities", "7.5.3.2", 0x02, 16, PCIE_CAPABILITIES),
    ("device_capabilities", "Device Capabilities", "7.5.3.3", 0x04, 32, DEVICE_CAPABILITIES),
    ("device_control", "Device Control", "7.5.3.4", 0x08, 16, DEVICE_CONTROL),
    ("device_status", "Device Status", "7.5.3.5", 0x0A, 16, DEVICE_STATUS),
    ("link_capabilities", "Link Capabilities", "7.5.3.6", 0x0C, 32, LINK_CAPABILITIES),
    ("link_control", "Link Control", "7.5.3.7", 0x10, 16, LINK_CONTROL),
    ("link_status", "Link Status", "7.5.3.8", 0x12, 16, LINK_STATUS),
    ("slot_capabilities", "Slot Capabilities", "7.5.3.9", 0x14, 32, SLOT_CAPABILITIES),
    ("slot_control", "Slot Control", "7.5.3.10", 0x18, 16, SLOT_CONTROL),
    ("slot_status", "Slot Status", "7.5.3.11", 0x1A, 16, SLOT_STATUS),
    ("root_control", "Root Control", "7.5.3.12", 0x1C, 16, ROOT_CONTROL),
    ("root_capabilities", "Root Capabilities", "7.5.3.13", 0x1E, 16, ROOT_CAPABILITIES),
    ("root_status", "Root Status", "7.5.3.14", 0x20, 32, ROOT_STATUS),
    ("device_capabilities_2", "Device Capabilities 2", "7.5.3.15", 0x24, 32, DEVICE_CAPABILITIES_2),
    ("device_control_2", "Device Control 2", "7.5.3.16", 0x28, 16, DEVICE_CONTROL_2),
    ("device_status_2", "Device Status 2", "7.5.3.17", 0x2A, 16, DEVICE_STATUS_2),
    ("link_capabilities_2", "Link Capabilities 2", "7.5.3.18", 0x2C, 32, LINK_CAPABILITIES_2),
    ("link_control_2", "Link Control 2", "7.5.3.19", 0x30, 16, LINK_CONTROL_2),
    ("link_status_2", "Link Status 2", "7.5.3.20", 0x32, 16, LINK_STATUS_2),
    ("slot_capabilities_2", "Slot Capabilities 2", "7.5.3.21", 0x34, 32, RAW_ONLY),
    ("slot_control_2", "Slot Control 2", "7.5.3.22", 0x38, 16, RAW_ONLY_16),
    ("slot_status_2", "Slot Status 2", "7.5.3.23", 0x3A, 16, RAW_ONLY_16),
]

PORT_TYPES_WITHOUT_LINK = {9, 10}  # RCiEP and Root Complex Event Collector (7.5.3, page 718)


def pcie_structure_length(pcie_capabilities_value: int) -> int:
    """Bytes in the structure, from the Capability Version and Device/Port Type at +02h.

    A choice following Linux pci_regs.h: version 2 and up run to +3Bh (60);
    version 1 ends after Link Status (+13h, 20) or, with no Link registers
    (RCiEP, Event Collector), after Device Status (+0Bh, 12).
    """
    version = bits(pcie_capabilities_value, 3, 0)
    port_type = bits(pcie_capabilities_value, 7, 4)
    if version >= 2:
        return 0x3C
    return 0x0C if port_type in PORT_TYPES_WITHOUT_LINK else 0x14


@dataclass
class PcieCapability:
    offset: int  # absolute offset of the capability's first byte
    registers: list[Register]  # in structure order, only those inside structure_length

    def register(self, key: str) -> Register:
        for r in self.registers:
            if r.key == key:
                return r
        raise KeyError(key)

    @property
    def version(self) -> int:
        return self.register("pcie_capabilities").value("Capability Version")

    @property
    def device_port_type(self) -> int:
        return self.register("pcie_capabilities").value("Device/Port Type")

    @property
    def device_port_type_name(self) -> str:
        return self.register("pcie_capabilities").field("Device/Port Type").text

    @property
    def structure_length(self) -> int:
        return pcie_structure_length(self.register("pcie_capabilities").raw)

    @property
    def has_link_registers(self) -> bool:
        return self.device_port_type not in PORT_TYPES_WITHOUT_LINK

    @property
    def max_link_speed_code(self) -> int:
        return self.register("link_capabilities").value("Max Link Speed")

    @property
    def current_link_speed_code(self) -> int:
        return self.register("link_status").value("Current Link Speed")

    @property
    def max_link_width(self) -> int:
        return self.register("link_capabilities").value("Maximum Link Width")

    @property
    def negotiated_link_width(self) -> int:
        return self.register("link_status").value("Negotiated Link Width")

    @property
    def speed_downgraded(self) -> bool:
        """Current Link Speed below Max Link Speed: what lspci marks '(downgraded)'.

        The codes index the same vector, so comparing them compares speeds.
        """
        return 0 < self.current_link_speed_code < self.max_link_speed_code

    @property
    def width_downgraded(self) -> bool:
        return 0 < self.negotiated_link_width < self.max_link_width

    @property
    def link_summary(self) -> str:
        """lspci's LnkSta line in one string: 'Speed 2.5 GT/s (downgraded), Width x16'."""
        speed = speed_text(self.current_link_speed_code) + (" (downgraded)" if self.speed_downgraded else "")
        width = width_text(self.negotiated_link_width) + (" (downgraded)" if self.width_downgraded else "")
        return f"Speed {speed}, Width {width}"

    @property
    def max_payload_supported_bytes(self) -> int | None:
        return PAYLOAD_BYTES.get(self.register("device_capabilities").value("Max_Payload_Size Supported"))

    @property
    def max_payload_bytes(self) -> int | None:
        return PAYLOAD_BYTES.get(self.register("device_control").value("Max_Payload_Size"))

    @property
    def max_read_request_bytes(self) -> int | None:
        return PAYLOAD_BYTES.get(self.register("device_control").value("Max_Read_Request_Size"))

    @property
    def supported_speeds_gts(self) -> list[float]:
        vector = self.register("link_capabilities_2").value("Supported Link Speeds Vector")
        return [s for n, s in enumerate(SUPPORTED_SPEEDS_VECTOR) if bit(vector, n)]


def decode_pcie_capability(cs: ConfigSpace, offset: int) -> PcieCapability:
    """Spec 7.5.3: every register of the PCI Express Capability at absolute `offset`.

    Registers are read at offset + their relative offset with u16 or u32 by
    width; only the registers inside the structure (by version and type) are
    read, so a version-1 structure never reads past its own end.
    """
    caps_value = cs.u16(offset + 0x02)
    length = pcie_structure_length(caps_value)
    registers = []
    for key, name, section, rel, width, layout in REGISTER_TABLE:
        if rel + width // 8 > length:
            break
        raw = cs.u16(offset + rel) if width == 16 else cs.u32(offset + rel)
        registers.append(make_register(key, name, section, rel, width, raw, layout))
    return PcieCapability(offset=offset, registers=registers)
