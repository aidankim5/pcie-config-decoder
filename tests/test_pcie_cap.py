"""Module 5 tests: the PCI Express capability of both fixtures, every acceptance
value from the brief checked against lspci's lines in the same file.
"""

from pathlib import Path

import pytest

from pcicfg.caps import walk_standard_caps
from pcicfg.parse import ConfigSpace, load_config_space
from pcicfg.pcie_cap import (
    PcieCapability,
    decode_pcie_capability,
    pcie_structure_length,
    speed_text,
    speeds_vector_text,
    width_text,
)

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


@pytest.fixture
def gpu() -> PcieCapability:
    return decode_pcie_capability(load_config_space(GPU), 0x78)


@pytest.fixture
def ssd() -> PcieCapability:
    return decode_pcie_capability(load_config_space(SSD), 0x70)


def set_names(reg):
    """Names of the single-bit fields that are 1."""
    return {f.name for f in reg.fields if f.hi == f.lo and f.value == 1}


# --- encodings ------------------------------------------------------------------------

def test_speed_width_payload_encodings():
    assert speed_text(1) == "2.5 GT/s" and speed_text(4) == "16 GT/s" and speed_text(5) == "32 GT/s"
    assert "reserved" in speed_text(0) and "reserved in PCIe 5.0" in speed_text(6)
    assert width_text(16) == "x16" and width_text(4) == "x4" and "reserved" in width_text(3)
    assert speeds_vector_text(0b0001111) == "2.5, 5, 8, 16 GT/s"
    assert speeds_vector_text(0) == "none"


def test_structure_length_by_version_and_type():
    assert pcie_structure_length(0x0012) == 0x3C  # v2 Legacy Endpoint (the GPU)
    assert pcie_structure_length(0x0001) == 0x14  # v1 endpoint with a Link
    assert pcie_structure_length(0x0091) == 0x0C  # v1 RCiEP: no Link registers


# --- GPU: 0x78, the brief's acceptance list ---------------------------------------------

def test_gpu_pcie_capabilities_register(gpu):
    reg = gpu.register("pcie_capabilities")
    assert reg.raw == 0x0012 and reg.offset == 0x02
    assert gpu.version == 2
    assert gpu.device_port_type == 1 and gpu.device_port_type_name == "Legacy PCI Express Endpoint"
    assert reg.value("Interrupt Message Number") == 0 and not reg.is_set("Slot Implemented")
    assert gpu.structure_length == 60 and len(gpu.registers) == 22


def test_gpu_device_capabilities(gpu):
    # lspci: DevCap: MaxPayload 256 bytes, PhantFunc 0, Latency L0s unlimited, L1 <64us, ExtTag+ RBE+ FLReset+
    reg = gpu.register("device_capabilities")
    assert reg.raw == 0x112C8DE1
    assert reg.field("Max_Payload_Size Supported").text == "256 bytes" and gpu.max_payload_supported_bytes == 256
    assert reg.value("Phantom Functions Supported") == 0
    assert reg.field("Extended Tag Field Supported").text == "8-bit Tag"
    assert reg.field("Endpoint L0s Acceptable Latency").text == "no limit"
    assert reg.field("Endpoint L1 Acceptable Latency").text == "max 64 us"
    assert reg.is_set("Role-Based Error Reporting") and reg.is_set("Function Level Reset Capability")
    assert reg.value("Captured Slot Power Limit Value") == 75 and reg.value("Captured Slot Power Limit Scale") == 0


def test_gpu_device_control_and_status(gpu):
    # lspci: DevCtl: CorrErr+ NonFatalErr+ FatalErr+ UnsupReq+ RlxdOrd+ ExtTag+ PhantFunc- AuxPwr- NoSnoop+ FLReset-
    #        MaxPayload 256 bytes, MaxReadReq 512 bytes; DevSta: all '-'
    ctl = gpu.register("device_control")
    assert ctl.raw == 0x293F
    assert set_names(ctl) == {
        "Correctable Error Reporting Enable",
        "Non-Fatal Error Reporting Enable",
        "Fatal Error Reporting Enable",
        "Unsupported Request Reporting Enable",
        "Enable Relaxed Ordering",
        "Extended Tag Field Enable",
        "Enable No Snoop",
    }
    assert gpu.max_payload_bytes == 256 and gpu.max_read_request_bytes == 512
    assert gpu.register("device_status").raw == 0 and set_names(gpu.register("device_status")) == set()


def test_gpu_link_capabilities(gpu):
    # lspci: LnkCap: Port #0, Speed 16GT/s, Width x16, ASPM L0s L1, Exit Latency L0s <512ns, L1 <4us
    #        ClockPM+ Surprise- LLActRep- BwNot- ASPMOptComp+
    reg = gpu.register("link_capabilities")
    assert reg.raw == 0x00453D04 and reg.offset == 0x0C
    assert reg.field("Max Link Speed").text == "16 GT/s" and gpu.max_link_speed_code == 4
    assert reg.field("Maximum Link Width").text == "x16" and gpu.max_link_width == 16
    assert reg.field("ASPM Support").text == "L0s and L1"
    assert reg.field("L0s Exit Latency").text == "256 ns to < 512 ns"
    assert reg.field("L1 Exit Latency").text == "2 us to < 4 us"
    assert set_names(reg) == {"Clock Power Management", "ASPM Optionality Compliance"}
    assert reg.value("Port Number") == 0


def test_gpu_link_control(gpu):
    # lspci: LnkCtl: ASPM Disabled; RCB 64 bytes, LnkDisable- CommClk+ ExtSynch- ClockPM+ ...
    reg = gpu.register("link_control")
    assert reg.raw == 0x0140
    assert reg.field("ASPM Control").text == "disabled"
    assert reg.field("Read Completion Boundary (RCB)").text == "64 bytes"
    assert set_names(reg) == {"Common Clock Configuration", "Enable Clock Power Management"}


def test_gpu_link_status_1101_is_downgraded(gpu):
    # lspci: LnkSta: Speed 2.5GT/s (downgraded), Width x16; TrErr- Train- SlotClk+ DLActive- BWMgmt- ABWMgmt-
    reg = gpu.register("link_status")
    assert reg.raw == 0x1101 and reg.offset == 0x12 and gpu.offset + reg.offset == 0x8A
    assert reg.field("Current Link Speed").text == "2.5 GT/s" and gpu.current_link_speed_code == 1
    assert reg.field("Negotiated Link Width").text == "x16" and gpu.negotiated_link_width == 16
    assert gpu.speed_downgraded and not gpu.width_downgraded
    assert gpu.link_summary == "Speed 2.5 GT/s (downgraded), Width x16"
    assert set_names(reg) == {"Slot Clock Configuration"}


def test_gpu_slot_and_root_registers_read_zero(gpu):
    for key in ("slot_capabilities", "slot_control", "slot_status", "root_control", "root_capabilities", "root_status"):
        assert gpu.register(key).raw == 0


def test_gpu_device_capabilities_2_and_control_2(gpu):
    # lspci: DevCap2: Completion Timeout: Range AB, TimeoutDis+ LTR- 10BitTagComp+ 10BitTagReq+ OBFF Via message
    reg = gpu.register("device_capabilities_2")
    assert reg.raw == 0x00070013
    assert reg.field("Completion Timeout Ranges Supported").text == "A and B"
    assert reg.is_set("Completion Timeout Disable Supported") and not reg.is_set("LTR Mechanism Supported")
    assert reg.is_set("10-Bit Tag Completer Supported") and reg.is_set("10-Bit Tag Requester Supported")
    assert reg.field("OBFF Supported").text == "Message signaling"
    # lspci: DevCtl2: Completion Timeout: 50us to 50ms, TimeoutDis- ... LTR- OBFF Disabled
    ctl = gpu.register("device_control_2")
    assert ctl.raw == 0 and ctl.field("Completion Timeout Value").text == "50 us to 50 ms (default)"
    assert ctl.field("OBFF Enable").text == "disabled"


def test_gpu_link_2_registers(gpu):
    # lspci: LnkCap2: Supported Link Speeds: 2.5-16GT/s, Crosslink- Retimer+ 2Retimers+ DRS-
    cap2 = gpu.register("link_capabilities_2")
    assert cap2.raw == 0x0180001E
    assert cap2.field("Supported Link Speeds Vector").text == "2.5, 5, 8, 16 GT/s"
    assert gpu.supported_speeds_gts == [2.5, 5.0, 8.0, 16.0]
    assert set_names(cap2) == {"Retimer Presence Detect Supported", "Two Retimers Presence Detect Supported"}
    # lspci: LnkCtl2: Target Link Speed: 16GT/s, ... Compliance Preset/De-emphasis: -6dB de-emphasis, 0dB preshoot
    ctl2 = gpu.register("link_control_2")
    assert ctl2.raw == 0x0004 and ctl2.field("Target Link Speed").text == "16 GT/s"
    assert ctl2.field("Transmit Margin").text == "normal operating range"
    # lspci: LnkSta2: Current De-emphasis Level: -6dB, EqualizationComplete+ Phase1+ Phase2+ Phase3+ ... CrosslinkRes: unsupported
    sta2 = gpu.register("link_status_2")
    assert sta2.raw == 0x001E
    assert sta2.field("Current De-emphasis Level").text == "-6 dB"
    assert set_names(sta2) == {
        "Equalization 8.0 GT/s Complete",
        "Equalization 8.0 GT/s Phase 1 Successful",
        "Equalization 8.0 GT/s Phase 2 Successful",
        "Equalization 8.0 GT/s Phase 3 Successful",
    }
    assert sta2.field("Crosslink Resolution").text == "unsupported"


# --- SSD: 0x70 ---------------------------------------------------------------------------

def test_ssd_is_a_pci_express_endpoint_at_16gts_x4(ssd):
    assert ssd.version == 2 and ssd.device_port_type_name == "PCI Express Endpoint"
    assert ssd.register("device_capabilities").raw == 0x112C8FE2 and ssd.max_payload_supported_bytes == 512
    assert ssd.register("device_control").raw == 0x293F and ssd.max_payload_bytes == 256
    cap = ssd.register("link_capabilities")
    assert cap.raw == 0x00477844 and cap.field("Max Link Speed").text == "16 GT/s" and cap.field("Maximum Link Width").text == "x4"
    assert cap.field("ASPM Support").text == "L1" and cap.field("L1 Exit Latency").text == "32 us to 64 us"
    sta = ssd.register("link_status")
    assert sta.raw == 0x1044 and ssd.link_summary == "Speed 16 GT/s, Width x4"
    assert not ssd.speed_downgraded and not ssd.width_downgraded


def test_ssd_device_2_and_link_2(ssd):
    # lspci: DevCap2: Completion Timeout: Range ABCD, TimeoutDis+ LTR+ 10BitTagComp+ 10BitTagReq- OBFF Not Supported
    cap2 = ssd.register("device_capabilities_2")
    assert cap2.raw == 0x0001081F and cap2.field("Completion Timeout Ranges Supported").text == "A, B, C and D"
    assert cap2.is_set("LTR Mechanism Supported") and not cap2.is_set("10-Bit Tag Requester Supported")
    assert cap2.field("OBFF Supported").text == "not supported"
    # lspci: DevCtl2: ... LTR+
    assert ssd.register("device_control_2").raw == 0x0400 and ssd.register("device_control_2").is_set("LTR Mechanism Enable")
    # lspci: LnkSta2: ... CrosslinkRes: Upstream Port
    assert ssd.register("link_status_2").raw == 0x011E
    assert ssd.register("link_status_2").field("Crosslink Resolution").text == "resolved as Upstream Port"


# --- structure length feeds the chain ----------------------------------------------------

def test_chain_knows_the_pcie_structure_length():
    chain = walk_standard_caps(load_config_space(GPU))
    assert chain.find(0x10).structure_length == 60  # equals its span: 78h to B4h
    chain = walk_standard_caps(load_config_space(SSD))
    assert chain.find(0x10).structure_length == 60  # inside its 64-byte span to B0h


def test_cli_prints_the_pcie_capability(capsys):
    import json

    from pcicfg.cli import NOT_YET, main

    assert main(["decode", str(GPU)]) == NOT_YET
    out = capsys.readouterr().out
    assert "-- 78h PCI Express (ID 10, spec 7.5.3, 60 bytes: version 2, Legacy PCI Express Endpoint)" in out
    assert "  Link: Speed 2.5 GT/s (downgraded), Width x16" in out
    assert "  +12h (8Ah) Link Status          1101       spec 7.5.3.8" in out
    assert "        3:0    Current Link Speed                                 1     2.5 GT/s  (index into the Supported Link Speeds Vector)" in out
    assert "        9:4    Negotiated Link Width                              16    x16" in out
    assert "  +0Ch (84h) Link Capabilities    00453d04   spec 7.5.3.6" in out
    assert "  +14h (8Ch) Slot Capabilities    00000000   spec 7.5.3.9; ports with slots / Root Ports only; reads zero on this Function" in out
    assert "  +2Ah (A2h) Device Status 2      0000       spec 7.5.3.17; placeholder register, RsvdZ" in out

    assert main(["decode", str(SSD), "--json"]) == NOT_YET
    doc = json.loads(capsys.readouterr().out)
    pcie = doc["standard_capabilities"]["entries"][2]["decoded"]
    assert pcie["link_summary"] == "Speed 16 GT/s, Width x4" and pcie["speed_downgraded"] is False
    link_status = [r for r in pcie["registers"] if r["key"] == "link_status"][0]
    assert link_status["raw"] == 0x1044 and link_status["fields"][0]["text"] == "16 GT/s"


def test_version_1_structure_stops_after_link_status():
    data = bytearray(load_config_space(GPU).data)
    data[0x7A] = 0x11  # version 1, Legacy Endpoint
    cap = decode_pcie_capability(ConfigSpace(bytes(data)), 0x78)
    assert cap.structure_length == 0x14
    assert [r.key for r in cap.registers][-1] == "link_status"
