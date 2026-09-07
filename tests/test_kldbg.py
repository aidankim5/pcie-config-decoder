"""Module 11 tests: the security-on path, through Microsoft's Kernel Local Debugging Driver.

The IOCTL encoding and the two bit-packed address fields are checked against the
structures the driver expects. The important one is `read_config_space`: it must
measure how far each read actually reached rather than assume a frame size, so a
fake reader stands in for the driver and the tests pin what happens when the
bus-data path stops at 256 bytes, when it reaches all 4096, and when neither
works. Nothing here needs Windows or the driver.
"""

import pytest

from pcicfg.cli import describe_read
from pcicfg.win.kldbg import (
    COMPATIBLE_FRAME,
    EXTENDED_FRAME,
    IOCTL_KLDBG,
    SYSDBG_READ_BUS_DATA,
    SYSDBG_READ_PHYSICAL,
    ConfigRead,
    KldbgStatus,
    read_config_space,
    segment_bus_number,
    slot_number,
)
from pcicfg.win.raw import DumpResult, EcamRegion


def test_ioctl_code_is_the_one_the_driver_registers():
    # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function 0x1, METHOD_NEITHER=3,
    # FILE_READ_ACCESS|FILE_WRITE_ACCESS=3) packs to 0x0022C007. Get this wrong and
    # DeviceIoControl fails with ERROR_INVALID_FUNCTION rather than reading anything.
    assert IOCTL_KLDBG == 0x0022C007


def test_sysdbg_command_numbers():
    assert (SYSDBG_READ_PHYSICAL, SYSDBG_READ_BUS_DATA) == (10, 18)


def test_slot_number_packs_device_and_function():
    # PCI_SLOT_NUMBER: device number in bits 4:0, function number in bits 7:5.
    assert slot_number(0, 0) == 0
    assert slot_number(0x1F, 0) == 0x1F
    assert slot_number(0, 7) == 0xE0
    assert slot_number(0x1F, 4) == 0x9F  # 00:1f.4, the SMBus controller on this machine


def test_segment_bus_number_packs_bus_and_segment():
    # PCI_SEGMENT_BUS_NUMBER: bus in bits 7:0, segment in bits 23:8.
    assert segment_bus_number(0x01) == 0x01
    assert segment_bus_number(0xFF) == 0xFF
    assert segment_bus_number(0x02, segment=1) == 0x102


class FakeReader:
    """A stand-in for the driver: answers bus-data reads up to a limit, ECAM reads up to another."""

    def __init__(self, bus_data_limit: int, physical_limit: int = 0, frame_base: int = 0xC0100000):
        self.bus_data_limit = bus_data_limit
        self.physical_limit = physical_limit
        self.frame_base = frame_base  # this Function's own frame: C0000000h + (bus 1 << 20)

    def read_bus_data(self, bus, device, function, offset, length):
        if offset + length > self.bus_data_limit:
            return None
        return bytes([(offset + i) & 0xFF for i in range(length)])

    def read_physical(self, address, length):
        offset = address - self.frame_base
        if offset < 0 or offset + length > self.physical_limit:
            return None
        return bytes([0xAA] * length)


@pytest.fixture
def one_ecam_region(monkeypatch):
    """Pretend the MCFG table maps bus 0-255 of segment 0 at C0000000h."""
    region = EcamRegion(base=0xC0000000, segment=0, start_bus=0, end_bus=255)
    monkeypatch.setattr("pcicfg.win.kldbg.ecam_region_for", lambda bus, segment=0: region)
    return region


def test_bus_data_reaching_the_whole_frame_needs_no_ecam_read(one_ecam_region):
    """When HalGetBusDataByOffset covers all 4096 bytes, that is the answer and ECAM is not touched."""
    got = read_config_space("01:00.0", reader=FakeReader(bus_data_limit=EXTENDED_FRAME))
    assert got.size == EXTENDED_FRAME
    assert got.bus_data_bytes == EXTENDED_FRAME
    assert got.physical_bytes == 0
    assert got.ecam_address is None  # never consulted
    assert "SysDbgReadBusData" in got.method
    assert got.frame == "the full 4096-byte extended frame (spec 7.2.2)"


def test_bus_data_stopping_at_256_falls_back_to_ecam(one_ecam_region):
    """The documented risk: the HAL read covers only the PCI-compatible frame.

    The extended capabilities live at 100h and up, so stopping at 256 would lose
    them. The ECAM read is the fallback that still reaches them, and the result
    must report both numbers rather than only the one that won.
    """
    reader = FakeReader(bus_data_limit=COMPATIBLE_FRAME, physical_limit=EXTENDED_FRAME)
    got = read_config_space("01:00.0", reader=reader)
    assert got.bus_data_bytes == COMPATIBLE_FRAME  # measured, not assumed
    assert got.physical_bytes == EXTENDED_FRAME
    assert got.size == EXTENDED_FRAME
    assert got.ecam_address == 0xC0000000 + (1 << 20)  # 01:00.0, spec 7.2.2
    assert "SysDbgReadPhysical" in got.method
    assert got.data == bytes([0xAA] * EXTENDED_FRAME)


def test_neither_path_reaching_past_256_keeps_the_256_bytes_and_says_so(one_ecam_region):
    """When ECAM is refused too, the 256 bytes are still returned, with a note explaining."""
    reader = FakeReader(bus_data_limit=COMPATIBLE_FRAME, physical_limit=0)
    got = read_config_space("01:00.0", reader=reader)
    assert got.size == COMPATIBLE_FRAME
    assert got.frame == "the 256-byte PCI-compatible frame only (spec 7.2.1)"
    assert "SysDbgReadBusData" in got.method
    assert got.physical_bytes == 0


def test_a_partial_first_block_is_measured_to_the_dword(one_ecam_region):
    """A refusal partway through the first 256 bytes is retried in dwords to find the edge."""
    got = read_config_space("01:00.0", reader=FakeReader(bus_data_limit=64, physical_limit=0))
    assert got.bus_data_bytes == 64
    assert got.size == 64
    assert got.frame == "64 bytes"


def test_no_mcfg_entry_is_reported_rather_than_guessed(monkeypatch):
    monkeypatch.setattr("pcicfg.win.kldbg.ecam_region_for", lambda bus, segment=0: None)
    got = read_config_space("01:00.0", reader=FakeReader(bus_data_limit=COMPATIBLE_FRAME))
    assert got.size == COMPATIBLE_FRAME
    assert any("no ACPI MCFG entry" in n for n in got.notes)


def test_blocker_names_the_first_unmet_condition_in_order():
    """Debug boot, then elevation, then the service: the order the user must fix them in."""
    assert "not Windows" in KldbgStatus(platform_ok=False).blocker
    assert "bcdedit /debug on" in KldbgStatus(platform_ok=True, debug_boot=False, elevated=True).blocker
    assert "not elevated" in KldbgStatus(platform_ok=True, debug_boot=True, elevated=False).blocker
    assert "service is not installed" in KldbgStatus(
        platform_ok=True, debug_boot=True, elevated=True, service_present=False
    ).blocker
    ok = KldbgStatus(platform_ok=True, debug_boot=True, elevated=True, service_present=True, opened=True)
    assert ok.blocker == "" and ok.usable


def test_secure_boot_closes_this_path_and_the_blocker_explains_why():
    """Measured on the machine this was built for: Secure Boot policy protects the BCD
    `debug` element, so `bcdedit /debug on` is refused and no privilege changes that.
    The blocker has to say that rather than send someone to a command that cannot work."""
    closed = KldbgStatus(platform_ok=True, debug_boot=False, secure_boot=True,
                         elevated=True, service_present=True)
    assert "Secure Boot policy" in closed.blocker
    assert "bigger weakening" in closed.blocker  # and why we do not just turn it off

    # With Secure Boot off, the same state is merely one reboot away.
    reboot_away = KldbgStatus(platform_ok=True, debug_boot=False, secure_boot=False, elevated=True)
    assert "reboot" in reboot_away.blocker and "Secure Boot" not in reboot_away.blocker


def test_report_distinguishes_debug_off_from_debug_unavailable():
    from pcicfg.win.kldbg import report as kldbg_report

    closed = " | ".join(kldbg_report(KldbgStatus(platform_ok=True, debug_boot=False, secure_boot=True)))
    assert "cannot be turned on: Secure Boot policy protects it" in closed
    assert "Secure Boot     on" in closed

    fixable = " | ".join(kldbg_report(KldbgStatus(platform_ok=True, debug_boot=False, secure_boot=False)))
    assert "bcdedit /debug on, then reboot" in fixable


def test_describe_read_states_the_method_and_both_measurements():
    detail = ConfigRead(
        data=bytes(EXTENDED_FRAME), method="kldbgdrv SysDbgReadPhysical at ECAM 0xC0100000 (spec 7.2.2)",
        bus_data_bytes=256, physical_bytes=4096, ecam_address=0xC0100000,
    )
    text = "\n".join(describe_read(DumpResult(detail.data, method=detail.method, detail=detail)))
    assert "got 4096 bytes: the full 4096-byte extended frame (spec 7.2.2)" in text
    assert "SysDbgReadBusData reached 256 bytes" in text
    assert "SysDbgReadPhysical at ECAM 0xC0100000 reached 4096 bytes" in text


def test_describe_read_without_detail_still_names_the_method():
    text = "\n".join(describe_read(DumpResult(b"\x00" * 256, method="some other backend")))
    assert text == "# read by some other backend"
