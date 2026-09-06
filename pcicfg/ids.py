"""ID tables: capability IDs, class codes, and names for the devices in the fixtures.

Where each table comes from (spec vs. elsewhere):

- Standard capability IDs (one byte, spec 7.5.3.1 and the [PCI Code and ID
  Assignment] document) and extended capability IDs (16 bits, spec 7.6.3):
  the lists in the brief, cross-checked against Linux pci_regs.h
  (PCI_CAP_ID_*, PCI_EXT_CAP_ID_*).
- Class codes: assigned by PCI-SIG in the [PCI Code and ID Assignment]
  document, not in the Base spec. The names here are the ones lspci prints;
  the list covers every class on the machine the fixtures came from plus the
  ones the brief asks for. Anything else prints as "class 0xBBSSPP".
- Vendor and device names: PCI-SIG assigns vendor IDs; device IDs are the
  vendor's own. lspci looks them up in the pci.ids database. This file carries
  only the devices from tests/fixtures/ids.txt (lspci -nn on the fixture
  machine); everything else prints as the raw ID. That is a choice: shipping
  pci.ids (a 1 MB file) would bury the decoder in data it does not decode.

[Taught] / [Ahead] tags: TAUGHT_CAPS lists the capabilities Aidan has decoded
by hand. The rest are printed with their name and an "ahead" marker so the
tool never implies more than he can explain.
"""

# --- standard capabilities: 1-byte ID at byte 0 of each list entry (spec 7.5.3.1) ---
STANDARD_CAP_NAMES = {
    0x01: "Power Management",
    0x02: "AGP",
    0x03: "VPD",
    0x04: "Slot ID",
    0x05: "MSI",
    0x06: "CompactPCI Hot Swap",
    0x07: "PCI-X",
    0x08: "HyperTransport",
    0x09: "Vendor Specific",
    0x0A: "Debug Port",
    0x0B: "CompactPCI CRC",
    0x0C: "PCI Hot-Plug",
    0x0D: "Subsystem ID",
    0x0E: "AGP 8x",
    0x0F: "Secure Device",
    0x10: "PCI Express",
    0x11: "MSI-X",
    0x12: "SATA",
    0x13: "Advanced Features",
    0x14: "Enhanced Allocation",
    0x15: "FPB",
}

# --- extended capabilities: 16-bit ID in bits 15:0 of the header DWORD (spec 7.6.3) ---
EXTENDED_CAP_NAMES = {
    0x0001: "Advanced Error Reporting",
    0x0002: "Virtual Channel",
    0x0003: "Device Serial Number",
    0x0004: "Power Budgeting",
    0x0005: "Root Complex Link Declaration",
    0x0006: "Root Complex Internal Link Control",
    0x0007: "Root Complex Event Collector Endpoint Association",
    0x0008: "Multi-Function Virtual Channel",
    0x0009: "Virtual Channel (MFVC variant)",
    0x000A: "Root Complex Register Block",
    0x000B: "Vendor-Specific Extended",
    0x000C: "Configuration Access Correlation",
    0x000D: "Access Control Services",
    0x000E: "Alternative Routing-ID Interpretation",
    0x000F: "Address Translation Services",
    0x0010: "Single Root I/O Virtualization",
    0x0011: "Multi-Root I/O Virtualization",
    0x0012: "Multicast",
    0x0013: "Page Request Interface",
    0x0015: "Resizable BAR",
    0x0016: "Dynamic Power Allocation",
    0x0017: "TPH Requester",
    0x0018: "Latency Tolerance Reporting",
    0x0019: "Secondary PCI Express",
    0x001A: "Protocol Multiplexing",
    0x001B: "Process Address Space ID",
    0x001C: "LN Requester",
    0x001D: "Downstream Port Containment",
    0x001E: "L1 PM Substates",
    0x001F: "Precision Time Measurement",
    0x0020: "PCI Express over M-PHY",
    0x0021: "FRS Queueing",
    0x0022: "Readiness Time Reporting",
    0x0023: "Designated Vendor-Specific Extended",
    0x0024: "VF Resizable BAR",
    0x0025: "Data Link Feature",
    0x0026: "Physical Layer 16.0 GT/s",
    0x0027: "Lane Margining at the Receiver",
    0x0028: "Hierarchy ID",
    0x0029: "Native PCIe Enclosure Management",
    0x002A: "Physical Layer 32.0 GT/s",
    0x002B: "Alternate Protocol",
    0x002C: "System Firmware Intermediary",
}

# Capabilities Aidan has decoded by hand (rule 5 in CLAUDE.md). Everything else is "ahead".
TAUGHT_STANDARD_CAPS = {0x01, 0x05, 0x10, 0x11}  # PM, MSI, PCI Express, MSI-X
TAUGHT_EXTENDED_CAPS = {0x0001}  # AER


def standard_cap_name(cap_id: int) -> str:
    return STANDARD_CAP_NAMES.get(cap_id, f"unknown capability ID {cap_id:#04x}")


def extended_cap_name(cap_id: int) -> str:
    return EXTENDED_CAP_NAMES.get(cap_id, f"unknown extended capability ID {cap_id:#06x}")


# --- class codes: (base class, sub-class) -> name; a 3-tuple adds the programming interface ---
CLASS_NAMES = {
    (0x01, 0x04): "RAID bus controller",
    (0x01, 0x06): "SATA controller",
    (0x01, 0x08): "Non-Volatile memory controller",
    (0x01, 0x08, 0x02): "Non-Volatile memory controller (NVM Express)",
    (0x02, 0x00): "Ethernet controller",
    (0x02, 0x80): "Network controller",
    (0x03, 0x00): "VGA compatible controller",
    (0x04, 0x03): "Audio device",
    (0x05, 0x00): "RAM memory",
    (0x06, 0x00): "Host bridge",
    (0x06, 0x01): "ISA bridge",
    (0x06, 0x04): "PCI bridge",
    (0x07, 0x80): "Communication controller",
    (0x0C, 0x03): "USB controller",
    (0x0C, 0x05): "SMBus",
    (0x0C, 0x80): "Serial bus controller",
    (0x11, 0x80): "Signal processing controller",
}


def class_name(base: int, sub: int, prog_if: int) -> str:
    """Most specific name available: (base, sub, prog-if), then (base, sub), then the raw code."""
    return CLASS_NAMES.get(
        (base, sub, prog_if),
        CLASS_NAMES.get((base, sub), f"class {base:02x}{sub:02x}{prog_if:02x}"),
    )


# --- vendors and devices seen in tests/fixtures/ids.txt (lspci -nn on the fixture machine) ---
VENDOR_NAMES = {
    0x10DE: "NVIDIA Corporation",
    0x144D: "Samsung Electronics Co Ltd",
    0x8086: "Intel Corporation",
    0x1458: "Gigabyte Technology Co., Ltd",
    0x1BB1: "Seagate Technology PLC",
}

DEVICE_NAMES = {
    (0x10DE, 0x2489): "GA104 [GeForce RTX 3060 Ti Lite Hash Rate]",
    (0x10DE, 0x228B): "GA104 High Definition Audio Controller",
    (0x144D, 0xA80C): "NVMe SSD Controller S4LV008[Pascal]",
    (0x1BB1, 0x5016): "FireCuda 520/IronWolf 525 SSD",
    (0x8086, 0xA700): "Raptor Lake-S Host Bridge/DRAM Controller",
    (0x8086, 0xA70D): "Raptor Lake PCI Express 5.0 Graphics Port (PEG010)",
    (0x8086, 0xA74D): "Raptor Lake PCI Express 4.0 Graphics Port",
    (0x8086, 0xA77D): "Raptor Lake Crashlog and Telemetry",
    (0x8086, 0xA77F): "RST Volume Management Device Controller",
    (0x8086, 0x7A60): "Raptor Lake USB 3.2 Gen 2x2 (20 Gb/s) XHCI Host Controller",
    (0x8086, 0x7A27): "Raptor Lake PCH Shared SRAM",
    (0x8086, 0x7A4C): "Raptor Lake Serial IO I2C Host Controller #0",
    (0x8086, 0x7A4D): "Raptor Lake Serial IO I2C Host Controller #1",
    (0x8086, 0x7A4E): "Raptor Lake Serial IO I2C Host Controller #2",
    (0x8086, 0x7A68): "Raptor Lake CSME HECI #1",
    (0x8086, 0x7A62): "Raptor Lake SATA AHCI Controller",
    (0x8086, 0x7A48): "Raptor Lake PCI Express Root Port #25",
    (0x8086, 0x7A40): "Raptor Lake PCI Express Root Port #17",
    (0x8086, 0x7A38): "Raptor Lake PCI Express Root Port #1",
    (0x8086, 0x7A3B): "Raptor Lake PCI Express Root Port #4",
    (0x8086, 0x7A30): "Raptor Lake PCI Express Root Port #9",
    (0x8086, 0x7A04): "Z790 Chipset LPC/eSPI Controller",
    (0x8086, 0x7A50): "Raptor Lake High Definition Audio Controller",
    (0x8086, 0x7A23): "700 Series Chipset SMBus Controller",
    (0x8086, 0x7A24): "Raptor Lake SPI (flash) Controller",
    (0x8086, 0x272B): "Wi-Fi 7(802.11be) AX1775*/AX1790*/BE20*/BE401/BE1750* 2x2",
    (0x8086, 0x125C): "Ethernet Controller I226-V",
}


def vendor_name(vendor_id: int) -> str:
    return VENDOR_NAMES.get(vendor_id, f"vendor {vendor_id:04x}")


def device_name(vendor_id: int, device_id: int) -> str:
    return DEVICE_NAMES.get((vendor_id, device_id), f"device {device_id:04x}")
