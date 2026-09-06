"""Module 10 tests: the Layer 3 spike. The address arithmetic of both hardware paths
(CF8/CFC and ECAM), BDF parsing, and the honest report `pcicfg dump` prints when it
cannot read bytes. The probe itself only runs on Windows.
"""

import sys

import pytest

from pcicfg.cli import BAD_INPUT, NOT_YET, main
from pcicfg.win.raw import (
    FRAME_BY_PATH,
    PawnIoStatus,
    cf8_address,
    ecam_address,
    parse_bdf,
    probe_pawnio,
    report,
)


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
    text = report(status, "01:00.0")
    assert "no bytes read" in text and "0x80070005" in text and "not elevated" in text
    assert "RW-Everything" in text and "sudo lspci -vvv -xxxx -s 01:00.0" in text
    assert "/sys/bus/pci/devices/0000:01:00.0/config" in text
    assert "pcicfg list" in text  # the layer that does work on Windows


def test_report_when_the_library_is_missing():
    text = report(PawnIoStatus(dll_present=False, dll_error="not found"), "01:00.0")
    assert "not loadable" in text and "github.com/namazso/PawnIO" in text


def test_report_when_pawnio_opens_but_no_module_exposes_config_reads():
    text = report(PawnIoStatus(dll_present=True, version="2.0.0", opened=True, open_hresult=0, elevated=True), "01:00.0")
    assert "pci_config_read_dword" in text and "test signed" in text


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
