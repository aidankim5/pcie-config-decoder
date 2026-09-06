"""Module 2 tests: the Type 0 header of both fixtures, checked against the
values lspci printed at the top of the same fixture file (the acceptance list
in the brief), and the Type 1 bus numbers on a synthetic bridge header.
"""

import json
from pathlib import Path

import pytest

from pcicfg.cli import NOT_YET, main
from pcicfg.header import (
    Type0Header,
    Type1Header,
    bits,
    decode_bars,
    decode_command,
    decode_header,
    decode_header_type,
    decode_status,
    decode_type0_header,
)
from pcicfg.parse import ConfigSpace, load_config_space
from pcicfg.render import render_header

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


def names_set(bit_list):
    return {b.name for b in bit_list if b.set}


def dword(value: int) -> bytes:
    """The inverse of int.from_bytes in parse.py: 0x0000000C -> bytes 0c 00 00 00."""
    return value.to_bytes(4, "little")


# --- bit helpers ---------------------------------------------------------------

def test_bits_helper():
    assert bits(0x80, 6, 0) == 0  # Header Type 0x80: layout field is 0
    assert bits(0x80, 7, 7) == 1  # ... and the multi-function bit is 1
    assert bits(0x0407, 2, 0) == 0b111  # Command 0x0407: bits 2:0 all set


# --- GPU: RTX 3060 Ti, 01:00.0 -------------------------------------------------

# @pytest.fixture: pytest runs this once per test that lists `gpu` as a parameter and
# passes in the return value. (Unrelated to the dump files in tests/fixtures/.)
@pytest.fixture
def gpu() -> Type0Header:
    h = decode_header(load_config_space(GPU))
    assert isinstance(h, Type0Header)  # decode_header may return either header class
    return h


def test_gpu_ids_and_class(gpu):
    assert gpu.function_present
    assert gpu.vendor_id == 0x10DE and gpu.vendor_name == "NVIDIA Corporation"
    assert gpu.device_id == 0x2489
    assert gpu.revision_id == 0xA1
    assert gpu.class_code == 0x030000
    assert (gpu.base_class, gpu.sub_class, gpu.prog_if) == (0x03, 0x00, 0x00)
    assert gpu.class_name == "VGA compatible controller"
    assert gpu.prog_if_name == "VGA controller"
    assert gpu.subsystem_vendor_id == 0x1458 and gpu.subsystem_id == 0x4077
    assert gpu.subsystem_name == "device 4077"  # lspci: "Gigabyte Technology Co., Ltd Device 4077"


def test_gpu_command_0407(gpu):
    # lspci: Control: I/O+ Mem+ BusMaster+ ... DisINTx+
    assert gpu.command == 0x0407
    assert names_set(gpu.command_bits) == {
        "I/O Space Enable",
        "Memory Space Enable",
        "Bus Master Enable",
        "Interrupt Disable",
    }


def test_gpu_status_0010(gpu):
    # lspci: Status: Cap+ ... everything else '-'
    assert gpu.status == 0x0010
    assert names_set(gpu.status_bits) == {"Capabilities List"}
    assert gpu.has_capabilities_list
    assert gpu.devsel_timing == 0


def test_gpu_header_type_and_cache_line(gpu):
    assert gpu.header_type == 0x80
    assert gpu.header_layout == 0 and gpu.multi_function
    assert gpu.layout_name == "Type 0" and gpu.layout_is_defined
    assert gpu.cache_line_size == 0x10  # 16 DWORDs = 64 bytes, as lspci printed
    assert gpu.latency_timer == 0
    assert gpu.bist == 0


def test_gpu_bars(gpu):
    # lspci: Region 0: Memory at 84000000 (32-bit, non-prefetchable)
    #        Region 1: Memory at 4000000000 (64-bit, prefetchable)
    #        Region 3: Memory at 4200000000 (64-bit, prefetchable)
    #        Region 5: I/O ports at 4000
    by_index = {b.index: b for b in gpu.bars}
    assert sorted(by_index) == [0, 1, 3, 5]  # slots 2 and 4 are the upper halves of 1 and 3
    b0, b1, b3, b5 = by_index[0], by_index[1], by_index[3], by_index[5]
    assert (b0.kind, b0.address, b0.width, b0.prefetchable) == ("memory", 0x84000000, 32, False)
    assert (b1.kind, b1.address, b1.width, b1.prefetchable) == ("memory", 0x4000000000, 64, True)
    assert b1.offset == 0x14 and b1.raw == 0x0000000C and b1.upper_raw == 0x00000040
    assert (b3.kind, b3.address, b3.width, b3.prefetchable) == ("memory", 0x4200000000, 64, True)
    assert b3.offset == 0x1C
    assert (b5.kind, b5.address, b5.offset) == ("io", 0x4000, 0x24)
    assert all("not determinable" in b.size_note for b in gpu.bars)
    assert all(b.problem == "" for b in gpu.bars)


def test_gpu_rom_capptr_interrupt(gpu):
    # lspci: Expansion ROM at 85000000 [disabled]
    assert gpu.expansion_rom == 0x85000000
    assert gpu.expansion_rom_address == 0x85000000 and not gpu.expansion_rom_enabled
    assert gpu.expansion_rom_validation_status == 0
    assert gpu.cardbus_cis == 0
    assert gpu.capabilities_pointer == 0x60 and gpu.capabilities_pointer_raw == 0x60
    assert gpu.interrupt_pin == 1 and gpu.interrupt_pin_name == "INTA"  # lspci: pin A
    assert gpu.interrupt_line == 0xFF
    assert gpu.min_gnt == 0 and gpu.max_lat == 0


# --- SSD: Samsung 990 PRO, 02:00.0 ---------------------------------------------

@pytest.fixture
def ssd() -> Type0Header:
    return decode_type0_header(load_config_space(SSD))


def test_ssd_ids_and_class(ssd):
    assert ssd.vendor_id == 0x144D and ssd.device_id == 0xA80C
    assert ssd.class_code == 0x010802
    assert ssd.class_name == "Non-Volatile memory controller (NVM Express)"
    assert ssd.prog_if_name == "NVM Express"
    assert ssd.subsystem_vendor_id == 0x144D and ssd.subsystem_id == 0xA801
    assert ssd.subsystem_name == "SSD 990 PRO"  # lspci: Subsystem: Samsung Electronics Co Ltd SSD 990 PRO


def test_ssd_command_0406_and_status_0011(ssd):
    # lspci: Control: I/O- Mem+ BusMaster+ ... DisINTx+
    assert ssd.command == 0x0406
    assert names_set(ssd.command_bits) == {
        "Memory Space Enable",
        "Bus Master Enable",
        "Interrupt Disable",
    }
    assert ssd.status == 0x0011
    assert names_set(ssd.status_bits) == {"Immediate Readiness", "Capabilities List"}


def test_ssd_header_type_bars_capptr(ssd):
    assert ssd.header_type == 0x00 and not ssd.multi_function
    # lspci: Region 0: Memory at 85f00000 (64-bit, non-prefetchable)
    assert [b.index for b in ssd.bars] == [0, 2, 3, 4, 5]  # BAR0 is 64-bit and eats slot 1
    b0 = ssd.bars[0]
    assert (b0.kind, b0.address, b0.width, b0.prefetchable) == ("memory", 0x85F00000, 64, False)
    assert b0.raw == 0x85F00004  # bits 2:1 = 10b (64-bit) show up as the 4
    assert all(b.kind == "empty" for b in ssd.bars[1:])
    assert ssd.expansion_rom == 0
    assert ssd.capabilities_pointer == 0x40
    assert ssd.interrupt_pin_name == "INTA"


# --- register decoders on hand-built values ------------------------------------

def test_decode_command_all_named_bits():
    assert names_set(decode_command(0x0547)) == {
        "I/O Space Enable",
        "Memory Space Enable",
        "Bus Master Enable",
        "Parity Error Response",
        "SERR# Enable",
        "Interrupt Disable",
    }
    assert names_set(decode_command(0)) == set()


def test_decode_status_rw1c_bits():
    assert names_set(decode_status(0x8100)) == {"Master Data Parity Error", "Detected Parity Error"}
    assert bits(0x0600, 10, 9) == 0b11  # DEVSEL Timing field, if a legacy device set it


def test_decode_header_type():
    assert decode_header_type(0x00) == (0, False)
    assert decode_header_type(0x80) == (0, True)
    assert decode_header_type(0x01) == (1, False)
    assert decode_header_type(0x81) == (1, True)


def test_bar_walk_stops_after_64bit_pair():
    data = bytearray(64)
    data[0x10:0x14] = dword(0x0000000C)  # 64-bit prefetchable, low half 0
    data[0x14:0x18] = dword(0x00000001)  # upper half: address bit 32
    data[0x18:0x1C] = dword(0x0000E001)  # I/O at E000
    bars = decode_bars(ConfigSpace(bytes(data)), 6)
    assert [b.index for b in bars] == [0, 2, 3, 4, 5]
    assert bars[0].address == 0x100000000 and bars[0].width == 64
    assert bars[1].kind == "io" and bars[1].address == 0xE000


def test_64bit_bar_in_last_slot_does_not_read_past_24h():
    data = bytearray(64)
    data[0x24:0x28] = dword(0xF000000C)  # 64-bit BAR in slot 5
    data[0x28:0x2C] = dword(0x12345678)  # Cardbus CIS: must NOT be used
    bars = decode_bars(ConfigSpace(bytes(data)), 6)
    last = bars[-1]
    assert last.index == 5 and last.upper_raw is None and last.address == 0xF0000000
    assert last.width == 64  # what bits 2:1 encode, even though the upper half is missing
    assert "last slot" in last.problem
    assert len(bars) == 6


def test_reserved_bar_type_is_flagged():
    data = bytearray(64)
    data[0x10:0x14] = dword(0x80000002)  # bits 2:1 = 01b, reserved
    bar = decode_bars(ConfigSpace(bytes(data)), 6)[0]
    assert bar.kind == "memory" and bar.width == 32 and "reserved memory type 01" in bar.problem


def test_io_bar_reserved_bit_1_is_flagged():
    data = bytearray(64)
    data[0x10:0x14] = dword(0x0000E003)  # I/O BAR with bit 1 set
    bar = decode_bars(ConfigSpace(bytes(data)), 6)[0]
    assert bar.kind == "io" and bar.address == 0xE000 and "bit 1 is reserved" in bar.problem


def test_capabilities_pointer_low_bits_are_masked_but_kept():
    data = bytearray(load_config_space(GPU).data[:64])
    data[0x34] = 0x63
    h = decode_header(ConfigSpace(bytes(data)))
    assert h.capabilities_pointer_raw == 0x63 and h.capabilities_pointer == 0x60
    assert "34h Capabilities Ptr   63                   -> 60h (bits 1:0 are reserved" in render_header(h)


# --- Type 1: bus numbers only ------------------------------------------------------

def test_type1_bus_numbers_on_synthetic_bridge():
    # Take the SSD bytes, flip Header Type to 01h, and write bus numbers 00/02/02 at 18h-1Ah.
    data = bytearray(load_config_space(SSD).data)
    data[0x0E] = 0x01
    data[0x18], data[0x19], data[0x1A] = 0x00, 0x02, 0x02
    h = decode_header(ConfigSpace(bytes(data)))
    assert isinstance(h, Type1Header)
    assert h.layout_name == "Type 1 (bridge)"
    assert (h.primary_bus, h.secondary_bus, h.subordinate_bus) == (0, 2, 2)
    assert len(h.bars) == 1 and h.bars[0].width == 64  # two slots, both eaten by the 64-bit BAR
    assert "[ahead" in render_header(h)


# --- dumps that are not a normal endpoint --------------------------------------------

def test_reserved_header_layout_is_not_labeled_taught():
    data = bytearray(load_config_space(SSD).data)
    data[0x0E] = 0x02
    text = render_header(decode_header(ConfigSpace(bytes(data))))
    assert "reserved" in text.splitlines()[1]
    assert "[taught]" not in text


def test_all_ff_dump_is_reported_as_no_function_present():
    h = decode_header(ConfigSpace(bytes([0xFF] * 256)))
    assert not h.function_present
    text = render_header(h)
    assert "no Function is present" in text.splitlines()[1]
    assert "BAR0" not in text  # nothing after the common fields is printed


# --- rendering -------------------------------------------------------------------

def test_render_header_gpu_lines(gpu):
    text = render_header(gpu)
    assert text.splitlines()[0] == (
        "VGA compatible controller: NVIDIA Corporation GA104 [GeForce RTX 3060 Ti Lite Hash Rate]"
        " (rev a1) (prog-if 00 [VGA controller])"
    )
    assert "  04h Command            0407                 set: I/O Space Enable, Memory Space Enable, Bus Master Enable, Interrupt Disable" in text
    assert "  0Ch Cache Line Size    10                   16 DWORDs = 64 bytes" in text
    assert "  14h BAR1               0000000c 18h:00000040 Memory at 4000000000 (64-bit, prefetchable)" in text
    assert "  24h BAR5               00004001             I/O ports at 4000" in text
    assert "  2Ch Subsystem          1458:4077            Gigabyte Technology Co., Ltd device 4077" in text
    assert "  30h Expansion ROM      85000000             at 85000000, disabled" in text
    assert "  34h Capabilities Ptr   60" in text
    assert "  3Ch Interrupt Line     ff                   ff = unknown / no connection" in text
    assert "[taught]" in text


def test_render_header_ssd_lines(ssd):
    text = render_header(ssd)
    assert "  0Ch Cache Line Size    10                   16 DWORDs = 64 bytes" in text
    assert "  10h BAR0               85f00004 14h:00000000 Memory at 85f00000 (64-bit, non-prefetchable)" in text
    assert "  2Ch Subsystem          144d:a801            Samsung Electronics Co Ltd SSD 990 PRO" in text
    assert "  30h Expansion ROM      00000000             reads as zero: no Expansion ROM, or not assigned" in text


def test_cli_decode_prints_header_then_says_what_is_missing(capsys):
    # capsys is a fixture pytest supplies; readouterr() returns what was printed to stdout and stderr.
    assert main(["decode", str(SSD)]) == NOT_YET
    captured = capsys.readouterr()
    assert "Non-Volatile memory controller (NVM Express): Samsung" in captured.out
    assert "capability chains: not built yet" in captured.err


def test_cli_json_has_header(capsys):
    assert main(["decode", str(GPU), "--json"]) == NOT_YET
    doc = json.loads(capsys.readouterr().out)
    assert doc["header"]["vendor_id"] == 0x10DE
    assert doc["header"]["bars"][1]["address"] == 0x4000000000
