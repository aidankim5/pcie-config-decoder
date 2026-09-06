"""Module 10 tests: the Layer 3 spike. The address arithmetic of both hardware paths
(CF8/CFC and ECAM), BDF parsing, and the honest report `pcicfg dump` prints when it
cannot read bytes. The probe itself only runs on Windows.
"""

import sys

import pytest

from pcicfg.cli import BAD_INPUT, NOT_YET, OK, main
from pcicfg.win.kldbg import KldbgStatus
from pcicfg.win.raw import (
    FRAME_BY_PATH,
    PawnIoStatus,
    cf8_address,
    ecam_address,
    parse_bdf,
    probe_pawnio,
    report,
)


# A security-on path with nothing wrong with it, so the report falls through to
# whatever PawnIO has to say. Used by the tests that pin that fallback wording.
WORKING_KLDBG = KldbgStatus(platform_ok=True, debug_boot=True, elevated=True, service_present=True, opened=True)


def test_bdf_parsing():
    assert parse_bdf("01:00.0") == (1, 0, 0)
    assert parse_bdf("0000:02:00.0") == (2, 0, 0)  # lspci's domain form
    assert parse_bdf("ff:1f.7") == (0xFF, 0x1F, 7)
    for bad in ("nonsense", "01:00", "01.00.0", "0001:01:00.0", "01:20.0", "01:00.8", "100:00.0"):
        with pytest.raises(ValueError):
            parse_bdf(bad)


def test_cf8_address_is_the_spec_figure():
    # Spec 7.2.1 Figure 7-1: bit 31 Enable, 23:16 bus, 15:11 device, 10:8 function,
    # 7:2 register number, 1:0 zero. 01:00.0 offset 00h:
    assert cf8_address(1, 0, 0, 0x00) == 0x80010000
    assert cf8_address(1, 0, 0, 0x34) == 0x80010034  # Capabilities Pointer
    assert cf8_address(0, 0x1F, 4, 0x10) == 0x8000FC10  # 00:1f.4, BAR0
    assert cf8_address(1, 0, 0, 0x37) == cf8_address(1, 0, 0, 0x34)  # the data port returns a DWORD
    with pytest.raises(ValueError):
        cf8_address(1, 0, 0, 0x100)  # six bits of register number stop at 256 bytes


def test_ecam_address_is_the_spec_calculation():
    # Spec 7.2.2: base + (bus << 20) + (device << 15) + (function << 12) + offset.
    base = 0xC0000000
    assert ecam_address(base, 0, 0, 0, 0) == base
    assert ecam_address(base, 1, 0, 0) == base + (1 << 20)
    assert ecam_address(base, 0, 0x1F, 4) == base + (0x1F << 15) + (4 << 12)
    assert ecam_address(base, 1, 0, 0, 0x100) == base + (1 << 20) + 0x100  # the extended chain
    with pytest.raises(ValueError):
        ecam_address(base, 1, 0, 0, 4096)


def test_the_two_paths_reach_different_frame_sizes():
    assert FRAME_BY_PATH == {"CF8/CFC": 256, "ECAM": 4096}


def test_report_names_the_blocker_and_both_alternatives():
    status = PawnIoStatus(dll_present=True, version="2.0.0", opened=False,
                          open_hresult=-2147024891, open_meaning="Access is denied", elevated=False)
    text = report(status, "01:00.0", kldbg_status=WORKING_KLDBG)
    assert "no bytes read" in text and "0x80070005" in text and "not elevated" in text
    assert "RW-Everything" in text and "sudo lspci -vvv -xxxx -s 01:00.0" in text
    assert "/sys/bus/pci/devices/0000:01:00.0/config" in text
    assert "pcicfg list" in text  # the layer that does work on Windows


def test_report_when_the_library_is_missing():
    text = report(PawnIoStatus(dll_present=False, dll_error="not found"), "01:00.0", kldbg_status=WORKING_KLDBG)
    assert "not loadable" in text and "github.com/namazso/PawnIO" in text


def test_report_when_pawnio_opens_but_no_module_exposes_config_reads():
    text = report(PawnIoStatus(dll_present=True, version="2.0.0", opened=True, open_hresult=0, elevated=True),
                  "01:00.0", kldbg_status=WORKING_KLDBG)
    assert "pci_config_read_dword" in text and "test signed" in text


def test_the_security_on_path_owns_the_blocker_line_when_it_is_the_one_missing():
    """`pcicfg dump` tries kldbgdrv first, so when that is what is unavailable it is
    what the user is told to fix -- not PawnIO, which is a recorded dead end."""
    pawnio = PawnIoStatus(dll_present=True, opened=False, open_hresult=-2147024891,
                          open_meaning="Access is denied", elevated=False)
    needs_reboot = KldbgStatus(platform_ok=True, debug_boot=False, elevated=True, service_present=True)
    text = report(pawnio, "01:00.0", kldbg_status=needs_reboot)
    assert "Blocked by: this machine was not booted with kernel debugging enabled" in text
    assert "debug boot      off" in text
    # and with the security-on path healthy, PawnIO's own blocker is what is left to say
    assert "Blocked by: pawnio_open returned" in report(pawnio, "01:00.0", kldbg_status=WORKING_KLDBG)


def test_dump_exits_3_with_the_report_and_1_on_a_bad_bdf(capsys):
    assert main(["dump", "01:00.0"]) == NOT_YET
    out = capsys.readouterr().out
    assert "pcicfg dump 01:00.0: no bytes read." in out and "RW-Everything" in out
    assert main(["dump", "01:00"]) == BAD_INPUT
    assert "expected bus:device.function" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "win32", reason="asks the Windows driver")
def test_probe_answers_without_changing_anything():
    status = probe_pawnio()
    assert isinstance(status.blocker, str) and status.blocker
    if status.dll_present:
        assert status.version  # pawnio_version answers without any privilege


# --- whether a raw read can happen on this machine at all --------------------------------

from unittest.mock import patch  # noqa: E402
from pathlib import Path  # noqa: E402

from pcicfg.parse import load_config_space  # noqa: E402
from pcicfg.win.raw import (  # noqa: E402
    DumpResult,
    EcamRegion,
    driver_blocklisted,
    dump_config_space,
    ecam_region_for,
    memory_integrity_enabled,
    read_ecam_regions,
)

GPU_TXT = Path(__file__).parent / "fixtures" / "rtx3060ti_01-00.0.txt"


def test_driver_blocklisted_reads_the_policy_blob(tmp_path):
    # A blocklist policy names blocked drivers as text inside the signed blob; the substring test
    # finds RwDrv whether the name sits in ASCII bytes or UTF-16.
    policy = tmp_path / "driversipolicy.p7b"
    policy.write_bytes(b"\x00stuff FileName=RwDrv.sys more\x00")
    assert driver_blocklisted("RwDrv", str(policy)) is True
    assert driver_blocklisted("NoSuchDrv", str(policy)) is False
    assert driver_blocklisted("RwDrv", str(tmp_path / "missing.p7b")) is None


def test_dump_config_space_refuses_when_blocklisted_and_memory_integrity_on():
    with patch("pcicfg.win.raw.memory_integrity_enabled", return_value=True), \
         patch("pcicfg.win.raw.driver_blocklisted", return_value=True):
        out = dump_config_space("01:00.0")
    assert out.data is None and "blocklist" in out.reason and "Memory Integrity" in out.reason


def test_dump_config_space_points_at_rw_when_it_could_load():
    with patch("pcicfg.win.raw.memory_integrity_enabled", return_value=False), \
         patch("pcicfg.win.raw.driver_blocklisted", return_value=True), \
         patch("pcicfg.win.raw.find_rw_everything", return_value=r"C:\RW\Rw.exe"):
        out = dump_config_space("01:00.0")
    assert out.data is None and "RW-Everything" in out.reason and "pcicfg decode" in out.reason


def test_dump_config_space_validates_the_bdf():
    with pytest.raises(ValueError):
        dump_config_space("nonsense")


def test_report_states_the_memory_integrity_and_blocklist_facts():
    status = PawnIoStatus(dll_present=True, version="2.0.0", opened=False,
                          open_hresult=-2147024891, open_meaning="Access is denied", elevated=False)
    with patch("pcicfg.win.raw.memory_integrity_enabled", return_value=True), \
         patch("pcicfg.win.raw.driver_blocklisted", return_value=True):
        text = report(status, "01:00.0")
    assert "Memory Integrity on" in text and "vulnerable-driver blocklist" in text
    assert "Ubuntu live USB" in text  # the route that works whatever the security settings


def test_cmd_dump_decodes_when_a_backend_returns_bytes(capsys):
    """The decode wiring: if a backend ever returns bytes (a machine where a driver loads),
    `pcicfg dump` decodes them like `pcicfg decode`."""
    want = load_config_space(GPU_TXT).data[:4096]
    with patch("pcicfg.win.raw.dump_config_space", return_value=DumpResult(want, method="test backend")):
        assert main(["dump", "01:00.0"]) == OK
    out = capsys.readouterr().out
    assert "Type 0 header (spec 7.5.1.1, 7.5.1.2)" in out and "PCI Express (ID 10" in out


def test_ecam_region_address_math():
    region = EcamRegion(base=0xC0000000, segment=0, start_bus=0, end_bus=224)
    assert region.covers(1) and not region.covers(1, segment=1)
    assert region.physical_address(1, 0, 0) == 0xC0100000
    assert region.physical_address(2, 0, 0, 0x100) == 0xC0200100


@pytest.mark.skipif(sys.platform != "win32", reason="reads the ACPI MCFG table")
def test_live_mcfg_gives_an_ecam_base():
    regions = read_ecam_regions()
    assert regions, "a PCIe machine has an MCFG table"
    r = ecam_region_for(1)
    assert r is not None and r.base % 0x100000 == 0


@pytest.mark.skipif(sys.platform != "win32", reason="reads Windows security state")
def test_live_memory_integrity_reads_a_bool():
    assert memory_integrity_enabled() in (True, False, None)
