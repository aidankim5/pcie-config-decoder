"""Module 9 tests: parsing the Windows PnP properties (from a saved capture, on any
OS) and, on Windows only, the live cross-check of `pcicfg list` against the
by-hand decode of the GPU's dump.
"""

import json
import sys
from pathlib import Path

import pytest

from pcicfg.parse import load_config_space
from pcicfg.pcie_cap import decode_pcie_capability
from pcicfg.win.enum import (
    PROPERTY_KEYS,
    functions_as_json,
    list_pci_functions,
    parse_hardware_ids,
    parse_pnp_json,
    powershell_script,
    render_list,
)

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
PNP = FIXTURES / "windows_pnp.json"  # captured on the fixture machine with the same PowerShell


def test_hardware_id_parsing():
    assert parse_hardware_ids(["PCI\\VEN_10DE&DEV_2489&SUBSYS_40771458&REV_A1"]) == (0x10DE, 0x2489, 0x4077, 0x1458, 0xA1)
    assert parse_hardware_ids("PCI\\VEN_8086&DEV_A700") == (0x8086, 0xA700, None, None, None)
    with pytest.raises(ValueError):
        parse_hardware_ids(["ACPI\\PNP0A08"])


def test_capture_parses_to_27_functions_sorted_by_bdf():
    rows = parse_pnp_json(PNP.read_text(encoding="utf-8"))
    assert len(rows) == 27
    bdfs = [r.bdf for r in rows]
    assert bdfs == sorted(bdfs, key=lambda b: (int(b[:2], 16), int(b[3:5], 16), int(b[6])))
    assert bdfs[0] == "00:00.0" and "01:00.0" in bdfs and "02:00.0" in bdfs


def test_capture_gpu_row_matches_the_fixture_dump():
    rows = {r.bdf: r for r in parse_pnp_json(PNP.read_text(encoding="utf-8"))}
    gpu = rows["01:00.0"]
    assert gpu.vid_did == "10de:2489" and gpu.subsystem_vendor_id == 0x1458 and gpu.subsystem_id == 0x4077
    assert gpu.revision == 0xA1 and gpu.class_code == 0x030000 and gpu.class_name == "VGA compatible controller"
    assert gpu.device_type == 3 and gpu.device_type_name == "PCI Express legacy endpoint"  # lspci: Legacy Endpoint
    # What Windows reports vs what the dump's Link Capabilities / Device Capabilities say:
    cap = decode_pcie_capability(load_config_space(GPU), 0x78)
    assert gpu.max_link_speed == cap.max_link_speed_code == 4  # 16 GT/s
    assert gpu.max_link_width == cap.max_link_width == 16
    assert gpu.max_payload == cap.register("device_capabilities").value("Max_Payload_Size Supported") == 1  # 256
    assert gpu.current_payload == cap.register("device_control").value("Max_Payload_Size") == 1
    assert gpu.max_read_request == cap.register("device_control").value("Max_Read_Request_Size") == 2  # 512
    assert gpu.ue_severity == 0x00462030  # Windows exposes AER's UE Severity too; same value as the dump
    assert gpu.aer_present is True
    # The current speed is whatever the link was doing when the capture was taken.
    assert gpu.current_link_speed in (1, 2, 3, 4) and gpu.current_link_width == 16


def test_capture_devices_without_a_link_say_so():
    rows = {r.bdf: r for r in parse_pnp_json(PNP.read_text(encoding="utf-8"))}
    smbus = rows["00:1f.4"]
    assert not smbus.has_link and smbus.link_text.startswith("no PCI Express link")
    assert smbus.device_type == 0 and smbus.class_code == 0x0C0500
    root = rows["00:01.0"]
    assert root.device_type == 8 and root.device_type_name == "PCI Express Root Port"
    assert root.link_text.startswith("Root Port")  # Windows gives ports no link properties; say so, not "no link"


def test_render_list_rows():
    rows = parse_pnp_json(PNP.read_text(encoding="utf-8"))
    text = render_list(rows)
    gpu_line = [ln for ln in text.splitlines() if ln.startswith("01:00.0")][0]
    assert gpu_line.startswith("01:00.0  10de:2489  0300  NVIDIA GeForce RTX 3060 Ti")
    assert "(max 16GT/s x16)" in gpu_line and "MPS 256/256 MRRS 512" in gpu_line
    wifi_line = [ln for ln in text.splitlines() if ln.startswith("05:00.0")][0]
    assert "LnkSta 8GT/s x1 (max 16GT/s x1) downgraded" in wifi_line


def test_json_rows_carry_derived_fields():
    rows = parse_pnp_json(PNP.read_text(encoding="utf-8"))
    docs = functions_as_json(rows)
    gpu = [d for d in docs if d["bdf"] == "01:00.0"][0]
    assert gpu["class_name"] == "VGA compatible controller" and gpu["max_link_speed"] == 4
    json.dumps(docs)  # must be serializable


def test_powershell_script_lists_every_key():
    script = powershell_script()
    assert all(k in script for k in PROPERTY_KEYS)
    assert "ConvertTo-Json" in script and "PCI\\*" in script


@pytest.mark.skipif(sys.platform != "win32", reason="reads Windows PnP properties")
def test_live_list_matches_the_gpu_dump():
    rows = {r.bdf: r for r in list_pci_functions()}
    assert "01:00.0" in rows, "the RTX 3060 Ti at 01:00.0 is the fixture machine's GPU"
    gpu = rows["01:00.0"]
    cap = decode_pcie_capability(load_config_space(GPU), 0x78)
    assert gpu.vid_did == "10de:2489"
    assert gpu.max_link_speed == cap.max_link_speed_code and gpu.max_link_width == cap.max_link_width
    assert gpu.max_read_request == cap.register("device_control").value("Max_Read_Request_Size")
