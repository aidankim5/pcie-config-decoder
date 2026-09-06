"""Module 10 tests: the Layer 3 spike. The address arithmetic of both hardware paths
(CF8/CFC and ECAM), BDF parsing, and the honest report `pcicfg dump` prints when it
cannot read bytes. The probe itself only runs on Windows.
"""

import sys

import pytest

from pcicfg.cli import BAD_INPUT, NOT_YET, OK, main
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


# --- reading through RW-Everything (mocked, since it is not installed here) --------------

from unittest.mock import patch  # noqa: E402

from pcicfg.parse import load_config_space  # noqa: E402
from pcicfg.win.raw import (  # noqa: E402
    DumpResult,
    EcamRegion,
    dump_config_space,
    ecam_region_for,
    parse_rw_dwords,
    read_ecam_regions,
    read_via_rw_everything,
)

from pathlib import Path  # noqa: E402

GPU_TXT = Path(__file__).parent / "fixtures" / "rtx3060ti_01-00.0.txt"


def _rw_transcript(data: bytes) -> str:
    """What Rw.exe prints for one RPCIE32 read per DWORD, over `data`, in order."""
    lines = []
    for off in range(0, len(data), 4):
        value = int.from_bytes(data[off:off + 4], "little")
        # Rw.exe echoes the request and prints the result after '='; the echo also has hex.
        lines.append(f"PCIE Cfg Bus 0x01 Dev 0x00 Fun 0x00 Off 0x{off:X} = 0x{value:08X}")
    return "\r\n".join(lines) + "\r\n"


def test_parse_rw_dwords_takes_the_value_after_equals():
    text = "Bus 0x01 Dev 0x00 Off 0x10 = 0x84000000\nOff 0x14 = 0x0000000C\n"
    assert parse_rw_dwords(text) == [0x84000000, 0x0000000C]
    assert parse_rw_dwords("no results here") == []


def test_read_via_rw_everything_reassembles_the_fixture_bytes():
    want = load_config_space(GPU_TXT).data[:4096]
    completed = type("R", (), {"returncode": 0, "stdout": _rw_transcript(want).encode(), "stderr": b""})()
    with patch("subprocess.run", return_value=completed) as run:
        got = read_via_rw_everything(1, 0, 0, 4096, r"C:\fake\Rw.exe")
    assert got == want  # exact 4096-byte round trip through the RPCIE32 read + little-endian assembly
    # the command it built: 1024 RPCIE32 reads, one per DWORD
    argv = run.call_args[0][0]
    command = [a for a in argv if a.startswith("/Command=")][0]
    assert command.count("RPCIE32") == 1024
    assert argv[0] == r"C:\fake\Rw.exe" and "/Stdout" in argv


def test_read_via_rw_everything_refuses_a_short_or_failed_read():
    short = type("R", (), {"returncode": 0, "stdout": b"Off 0x0 = 0x12345678\n", "stderr": b""})()
    with patch("subprocess.run", return_value=short):
        try:
            read_via_rw_everything(1, 0, 0, 4096, r"C:\fake\Rw.exe")
            assert False, "should have refused a 1-of-1024 read"
        except RuntimeError as e:
            assert "expected 1024" in str(e)
    failed = type("R", (), {"returncode": 1, "stdout": b"", "stderr": b"needs admin"})()
    with patch("subprocess.run", return_value=failed):
        try:
            read_via_rw_everything(1, 0, 0, 4096, r"C:\fake\Rw.exe")
            assert False
        except RuntimeError as e:
            assert "needs admin" in str(e)


def test_dump_config_space_reports_when_rw_is_absent():
    with patch("pcicfg.win.raw.find_rw_everything", return_value=None):
        out = dump_config_space("01:00.0")
    assert out.data is None and "RW-Everything" in out.reason


def test_dump_config_space_reads_when_rw_is_present():
    want = load_config_space(GPU_TXT).data[:4096]
    completed = type("R", (), {"returncode": 0, "stdout": _rw_transcript(want).encode(), "stderr": b""})()
    with patch("pcicfg.win.raw.find_rw_everything", return_value=r"C:\fake\Rw.exe"), \
         patch("subprocess.run", return_value=completed):
        out = dump_config_space("01:00.0")
    assert out.data == want and "RW-Everything" in out.method


def test_cmd_dump_decodes_a_successful_read(capsys):
    """When a backend returns bytes, `pcicfg dump` decodes them like `pcicfg decode`."""
    want = load_config_space(GPU_TXT).data[:4096]
    with patch("pcicfg.win.raw.dump_config_space", return_value=DumpResult(want, method="RW-Everything (test)")):
        assert main(["dump", "01:00.0"]) == OK
    out = capsys.readouterr().out
    assert "Type 0 header (spec 7.5.1.1, 7.5.1.2)" in out
    assert "10de" in out and "PCI Express (ID 10" in out


def test_ecam_region_address_math():
    region = EcamRegion(base=0xC0000000, segment=0, start_bus=0, end_bus=224)
    assert region.covers(1) and not region.covers(1, segment=1)
    assert region.physical_address(1, 0, 0) == 0xC0100000
    assert region.physical_address(2, 0, 0, 0x100) == 0xC0200100


import sys as _sys  # noqa: E402


@pytest.mark.skipif(_sys.platform != "win32", reason="reads the ACPI MCFG table")
def test_live_mcfg_gives_an_ecam_base():
    regions = read_ecam_regions()
    assert regions, "a PCIe machine has an MCFG table"
    r = ecam_region_for(1)
    assert r is not None and r.base % 0x100000 == 0
