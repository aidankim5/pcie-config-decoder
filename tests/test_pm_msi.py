"""Module 4 tests: Power Management, MSI and MSI-X on both fixtures, checked
against lspci's lines in the same file, plus synthetic MSI layouts.
"""

from pathlib import Path

from pcicfg.caps import walk_standard_caps
from pcicfg.msi import decode_msi, decode_msix, msi_structure_length
from pcicfg.parse import ConfigSpace, load_config_space
from pcicfg.pm import decode_power_management

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


# --- Power Management ---------------------------------------------------------------

def test_gpu_power_management_at_60h():
    # Bytes at 60h: 01 68 03 48 08 00 00 00 -> PMC 4803h, PMCSR 0008h.
    # lspci: Power Management version 3; Flags: PMEClk- DSI- D1- D2- AuxCurrent=0mA
    #        PME(D0+,D1-,D2-,D3hot+,D3cold-); Status: D0 NoSoftRst+ PME-Enable- DSel=0 DScale=0 PME-
    pm = decode_power_management(load_config_space(GPU), 0x60)
    assert pm.pmc == 0x4803 and pm.pmcsr == 0x0008
    assert pm.version == 3
    assert not pm.pme_clock and not pm.dsi and not pm.d1_support and not pm.d2_support
    assert pm.aux_current_code == 0 and pm.aux_current_ma == 0
    assert pm.pme_support == 0b01001 and pm.pme_states == ["D0", "D3hot"]
    assert pm.power_state == 0 and pm.power_state_name == "D0"
    assert pm.no_soft_reset and not pm.pme_enable and not pm.pme_status
    assert pm.data_select == 0 and pm.data_scale == 0 and pm.data == 0


def test_ssd_power_management_at_40h():
    # Bytes at 40h: 01 50 13 00 08 00 00 00 -> PMC 0013h: version 3 and bit 4 Immediate
    # Readiness on Return to D0 (the SSD's Status register bit 0 says the same).
    # lspci: PME(D0-,D1-,D2-,D3hot-,D3cold-); Status: D0 NoSoftRst+
    pm = decode_power_management(load_config_space(SSD), 0x40)
    assert pm.pmc == 0x0013 and pm.version == 3 and pm.immediate_readiness
    assert pm.pme_support == 0 and pm.pme_states == []
    assert pm.power_state_name == "D0" and pm.no_soft_reset


def test_pm_encodings_on_hand_built_values():
    data = bytearray(256)
    data[0x40:0x48] = bytes.fromhex("01 00 ff ff 03 81 00 2a")  # PMC ffffh, PMCSR 8103h, Data 2ah
    pm = decode_power_management(ConfigSpace(bytes(data)), 0x40)
    assert pm.version == 7 and pm.pme_clock and pm.dsi and pm.d1_support and pm.d2_support
    assert pm.aux_current_ma == 375  # code 111b
    assert pm.pme_states == ["D0", "D1", "D2", "D3hot", "D3cold"]
    assert pm.power_state_name == "D3hot" and pm.pme_enable and pm.pme_status
    assert pm.data == 0x2A


# --- MSI ------------------------------------------------------------------------------

def test_gpu_msi_at_68h():
    # Bytes at 68h: 05 78 81 00 | 58 0d e0 fe | 00 00 00 00 | 00 00 00 00
    # lspci: MSI: Enable+ Count=1/1 Maskable- 64bit+; Address: 00000000fee00d58  Data: 0000
    msi = decode_msi(load_config_space(GPU), 0x68)
    assert msi.message_control == 0x0081
    assert msi.enable and msi.address_64bit and not msi.per_vector_masking
    assert msi.vectors_capable == 1 and msi.vectors_enabled == 1
    assert msi.message_address == 0xFEE00D58 and msi.message_upper_address == 0
    assert msi.full_address == 0x00000000FEE00D58
    assert msi.data_offset == 0x0C and msi.message_data == 0x0000
    assert msi.mask_bits is None and msi.pending_bits is None
    assert msi.structure_length == 16


def test_ssd_msi_at_50h():
    # Bytes at 50h: 05 70 8a 00 ... -> Message Control 008Ah.
    # lspci: MSI: Enable- Count=1/32 Maskable- 64bit+
    msi = decode_msi(load_config_space(SSD), 0x50)
    assert msi.message_control == 0x008A
    assert not msi.enable and msi.address_64bit
    assert msi.multiple_message_capable == 0b101 and msi.vectors_capable == 32
    assert msi.multiple_message_enable == 0 and msi.vectors_enabled == 1
    assert msi.message_address == 0 and msi.message_data == 0


def test_msi_layouts_follow_message_control():
    # Figures 7-44 to 7-47: 32-bit / 64-bit, with / without per-vector masking.
    assert msi_structure_length(0x0000) == 12  # 32-bit, no masking
    assert msi_structure_length(0x0080) == 16  # 64-bit
    assert msi_structure_length(0x0100) == 20  # 32-bit with Mask and Pending
    assert msi_structure_length(0x0180) == 24  # 64-bit with Mask and Pending

    data = bytearray(256)
    # 32-bit + per-vector masking at 40h: Message Control 0101h (enable, PVM), address, data, mask, pending
    data[0x40:0x54] = bytes.fromhex("05 00 01 01  00 10 e0 fe  34 12 78 56  0f 00 00 00  05 00 00 00")
    msi = decode_msi(ConfigSpace(bytes(data)), 0x40)
    assert not msi.address_64bit and msi.per_vector_masking
    assert msi.message_upper_address is None and msi.data_offset == 0x08
    assert msi.message_data == 0x1234 and msi.extended_message_data == 0x5678
    assert msi.mask_offset == 0x0C and msi.mask_bits == 0x0000000F
    assert msi.pending_offset == 0x10 and msi.pending_bits == 0x00000005
    assert msi.structure_length == 20


# --- MSI-X ----------------------------------------------------------------------------

def test_ssd_msix_at_b0h():
    # Bytes at B0h: 11 00 10 80 | 00 30 00 00 | 00 20 00 00
    # lspci: MSI-X: Enable+ Count=17 Masked-; Vector table: BAR=0 offset=00003000; PBA: BAR=0 offset=00002000
    msix = decode_msix(load_config_space(SSD), 0xB0)
    assert msix.message_control == 0x8010
    assert msix.table_size_code == 16 and msix.table_size == 17
    assert msix.enable and not msix.function_mask
    assert msix.table_bir == 0 and msix.table_offset == 0x3000 and msix.table_bar_offset == 0x10
    assert msix.pba_bir == 0 and msix.pba_offset == 0x2000
    assert msix.structure_length == 12


def test_msix_bir_and_offset_split():
    data = bytearray(256)
    data[0x40:0x4C] = bytes.fromhex("11 00 ff 47  0d 40 00 00  16 80 00 00")
    msix = decode_msix(ConfigSpace(bytes(data)), 0x40)
    assert msix.table_size == 0x7FF + 1 == 2048  # all 11 bits set
    assert msix.function_mask and not msix.enable
    assert msix.table_bir == 5 and msix.table_offset == 0x4008 and msix.table_bar_offset == 0x24
    assert msix.pba_bir == 6 and msix.pba_bar_offset is None  # reserved BIR code


# --- the chain now knows MSI's size ---------------------------------------------------

def test_chain_structure_lengths_include_msi():
    gpu = walk_standard_caps(load_config_space(GPU))
    assert [c.structure_length for c in gpu.entries] == [8, 16, None, 0x14]  # PCIe still None
    ssd = walk_standard_caps(load_config_space(SSD))
    assert [c.structure_length for c in ssd.entries] == [8, 16, None, 12]


# --- rendering and CLI ------------------------------------------------------------------

def test_cli_prints_pm_msi_msix_blocks(capsys):
    import json

    from pcicfg.cli import NOT_YET, main

    assert main(["decode", str(SSD)]) == NOT_YET
    out = capsys.readouterr().out
    assert "-- 40h Power Management (ID 01, spec 7.5.2, 8 bytes)  [ahead" in out
    assert "  +02h (42h) PMC                  0013       version 3; PME Clock-; Immediate Readiness+; DSI-; Aux current 0 mA; D1-; D2-; PME from: none" in out
    assert "  +04h (44h) PMCSR                0008       D0; No Soft Reset+; PME_En-;" in out
    assert "-- 50h MSI (ID 05, spec 7.7.1, 16 bytes: 64-bit address, no per-vector masking)" in out
    assert "  +02h (52h) Message Control      008a       Enable-; 1 of 32 vectors (codes 0/5, 2^code); 64-bit Address+; Per-Vector Masking-" in out
    assert "-- B0h MSI-X (ID 11, spec 7.7.2, 12 bytes)  [ahead" in out
    assert "  +02h (B2h) Message Control      8010       Enable+; Function Mask-; Table Size code 16 = 17 entries" in out
    assert "  +04h (B4h) Table Offset/BIR     00003000   BIR 0 = BAR at 10h, offset 3000h" in out
    assert "  +08h (B8h) PBA Offset/BIR       00002000   BIR 0 = BAR at 10h, offset 2000h" in out

    assert main(["decode", str(GPU)]) == NOT_YET
    out = capsys.readouterr().out
    assert "  +02h (6Ah) Message Control      0081       Enable+; 1 of 1 vectors (codes 0/0, 2^code); 64-bit Address+" in out
    assert "  +04h (6Ch) Message Address      fee00d58" in out
    assert "  +08h (70h) Message Upper Addr   00000000   bits 63:32 -> full address 00000000fee00d58" in out
    assert "  +0Ch (74h) Message Data         0000" in out
    assert "  +02h (62h) PMC                  4803       version 3; PME Clock-; Immediate Readiness-; DSI-; Aux current 0 mA; D1-; D2-; PME from: D0, D3hot" in out

    assert main(["decode", str(SSD), "--json"]) == NOT_YET
    doc = json.loads(capsys.readouterr().out)
    entries = doc["standard_capabilities"]["entries"]
    assert entries[0]["decoded"]["version"] == 3 and entries[0]["decoded"]["immediate_readiness"] is True
    assert entries[1]["decoded"]["multiple_message_capable"] == 5
    assert entries[2]["decoded"] is None  # PCI Express: module 5
    assert entries[3]["decoded"]["table_size_code"] == 16


def test_cli_flags_a_structure_that_does_not_fit(capsys, tmp_path):
    from pcicfg.cli import NOT_YET, main

    # Re-point the PCI Express entry's next pointer (byte 71h) at F8h and put an MSI-X header
    # there: only 8 bytes remain before 100h, and the structure needs 12.
    data = bytearray(load_config_space(SSD).data[:256])
    data[0x71] = 0xF8
    data[0xF8:0xFC] = bytes.fromhex("11 00 10 80")
    p = tmp_path / "msix_tail.bin"
    p.write_bytes(bytes(data))
    assert main(["decode", str(p)]) == NOT_YET
    out = capsys.readouterr().out
    assert "-- F8h MSI-X (ID 11, spec 7.7.2)" in out
    assert "[problem: only 8 bytes before the next start; the structure needs 12]" in out
