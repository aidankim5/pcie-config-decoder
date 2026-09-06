"""Module 1 tests: text -> bytes -> text, and the little-endian readers.

Every expected value here can be checked by eye against the hex rows in the
fixture files under tests/fixtures/.

The brief lists four parser tests. Two live here: the hex dump round-trips to
exactly 4096 bytes, and byte 0x78 of the GPU file is 0x10 / byte 0x82 of the
SSD file is 0x44. Two are owed to later modules: "a 256-byte input decodes the
header and standard chain and reports 'extended space not present in dump'"
(header, caps, extcaps modules) and "a corrupted next-pointer does not loop
forever" (caps module). Only the size half of the 256-byte case is tested now.
"""

from pathlib import Path

import pytest

from pcicfg.cli import OK, main
from pcicfg.parse import (
    ConfigSpace,
    ParseError,
    load_config_space,
    parse_lspci_all,
    parse_lspci_block,
    parse_lspci_hex,
    split_lspci_blocks,
)
from pcicfg.render import render_hex

FIXTURES = Path(__file__).parent / "fixtures"  # __file__ = this test file; / joins path parts
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


def _is_hex_row(line: str) -> bool:
    """A fixture line like '70: 00 00 ...', judged without the parser's own regex.

    partition(": ") splits at the first ": " into (before, ": ", after); when the
    separator is absent the middle part is "" and bool("") is False.
    """
    head, sep, _ = line.partition(": ")
    return bool(sep) and len(head) in (2, 3) and all(c in "0123456789abcdef" for c in head)


def _hex_rows(path: Path) -> list[str]:
    return [ln for ln in path.read_text().splitlines() if _is_hex_row(ln)]


# --- the two fixtures parse to exactly 4096 bytes ---------------------------

def test_gpu_round_trips_to_4096_bytes():
    cs = load_config_space(GPU)
    assert cs.size == 4096
    assert cs.has_extended_space
    assert cs.bdf == "01:00.0"
    assert cs.description.startswith("VGA compatible controller")
    assert cs.origin == "lspci text"


def test_ssd_round_trips_to_4096_bytes():
    cs = load_config_space(SSD)
    assert cs.size == 4096
    assert cs.bdf == "02:00.0"
    assert cs.description.startswith("Non-Volatile memory controller")


def test_fixtures_have_256_rows_of_16():
    for path in (GPU, SSD):
        rows = _hex_rows(path)
        assert len(rows) == 256
        assert all(len(r.split(": ", 1)[1].split()) == 16 for r in rows)


# --- single bytes at absolute offsets, checked by eye against the rows ------

def test_gpu_byte_0x78_is_pcie_capability_id():
    # Row "70:" column 8 (the ninth byte, offset 0x78) in rtx3060ti_01-00.0.txt is "10".
    assert load_config_space(GPU).data[0x78] == 0x10


def test_ssd_byte_0x82_is_0x44():
    # Row "80:" column 2 (the third byte, offset 0x82) in samsung990pro_02-00.0.txt is "44".
    assert load_config_space(SSD).data[0x82] == 0x44


# --- little-endian readers ------------------------------------------------

def test_little_endian_flip_on_gpu_header():
    cs = load_config_space(GPU)
    assert cs.u16(0x00) == 0x10DE  # bytes "de 10" -> Vendor ID
    assert cs.u16(0x02) == 0x2489  # bytes "89 24" -> Device ID
    assert cs.u32(0x10) == 0x84000000  # bytes "00 00 00 84" -> BAR0
    assert cs.u8(0x34) == 0x60  # Capabilities Pointer, one byte, no flip


def test_little_endian_flip_on_ssd_header():
    cs = load_config_space(SSD)
    assert cs.u16(0x00) == 0x144D
    assert cs.u16(0x02) == 0xA80C
    assert cs.u8(0x34) == 0x40


def test_readers_refuse_offsets_past_the_end():
    cs = ConfigSpace(data=bytes(256))  # 256 zero bytes: an empty 256-byte dump
    assert cs.u8(0xFF) == 0
    with pytest.raises(IndexError):
        cs.u16(0xFF)  # would need byte 0x100
    with pytest.raises(IndexError):
        cs.u32(0x100)
    with pytest.raises(IndexError):
        cs.u8(-1)  # Python would happily read the last byte; a config space has no offset -1


def test_bytes_at_refuses_negative_length():
    cs = ConfigSpace(data=bytes(range(256)))
    assert cs.bytes_at(0x10, 4) == bytes([0x10, 0x11, 0x12, 0x13])
    with pytest.raises(ValueError):
        cs.bytes_at(0x10, -4)  # Python slicing would silently return b""
    with pytest.raises(ValueError):
        cs.bytes_at(300, -100)


# --- parse -> render reproduces lspci's hex block exactly -------------------

def test_render_hex_reproduces_gpu_rows():
    cs = load_config_space(GPU)
    assert render_hex(cs.data) == "\n".join(_hex_rows(GPU))


def test_render_hex_reproduces_ssd_rows():
    cs = load_config_space(SSD)
    assert render_hex(cs.data) == "\n".join(_hex_rows(SSD))


def test_render_hex_with_base_rebases_labels():
    # A capability at 0x78 printed "from 00": labels restart at 00, 10, ...
    cs = load_config_space(GPU)
    # 0x3C = 60 bytes = the whole PCI Express capability structure
    # (spec 7.5.3, Figure 7-21: its last register, Slot Status 2, sits at 3Ah-3Bh).
    cap = cs.bytes_at(0x78, 0x3C)
    assert render_hex(cap, base=0).splitlines()[0].startswith("00: 10 b4 12 00")
    # With base=0x78 the labels are absolute again.
    assert render_hex(cap, base=0x78).splitlines()[0].startswith("78: 10 b4")


# --- 256-byte input: header + standard chain only, no extended space --------

def test_256_byte_dump_has_no_extended_space():
    # First 16 rows x 16 bytes = the 256-byte PCI-compatible frame.
    data = parse_lspci_hex("\n".join(_hex_rows(GPU)[:16]))
    assert len(data) == 256
    cs = ConfigSpace(data=data)
    assert not cs.has_extended_space
    assert cs.frame.startswith("PCI-compatible space, 256 bytes")


# --- raw binary input -------------------------------------------------------
# tmp_path: pytest fills this parameter with a fresh temporary folder just by
# seeing the name (pytest calls this a "fixture"; unrelated to tests/fixtures/).

def test_raw_binary_file_loads(tmp_path):
    data = load_config_space(GPU).data
    p = tmp_path / "01-00.0.config"
    p.write_bytes(data)
    cs = load_config_space(p)
    assert cs.data == data
    assert cs.bdf is None
    assert cs.size == 4096
    assert cs.origin == "raw image"


def test_raw_binary_256_bytes(tmp_path):
    p = tmp_path / "small.bin"
    p.write_bytes(load_config_space(SSD).data[:256])
    cs = load_config_space(p)
    assert cs.size == 256 and not cs.has_extended_space


def test_raw_64_byte_header_only_image(tmp_path):
    p = tmp_path / "hdr.bin"
    p.write_bytes(load_config_space(GPU).data[:64])
    cs = load_config_space(p)
    assert cs.size == 64 and cs.frame.startswith("header only")


def test_raw_image_of_odd_size_is_rejected(tmp_path):
    p = tmp_path / "odd.bin"
    p.write_bytes(bytes(128))  # a multiple of 4, but not a configuration-space frame
    with pytest.raises(ParseError):
        load_config_space(p)


def test_garbage_file_is_rejected(tmp_path):
    p = tmp_path / "junk.txt"
    p.write_text("this is not a dump\n")  # 19 or 20 bytes depending on line endings
    # match= is a regular expression searched for in the error message.
    with pytest.raises(ParseError, match="no hex rows.*64, 256, or 4096"):
        load_config_space(p)


def test_non_text_file_gets_an_honest_error(tmp_path):
    p = tmp_path / "binary.dat"
    p.write_bytes(b"\x80\x81\x82" * 7)  # 21 bytes that are neither UTF-8 nor a frame
    with pytest.raises(ParseError, match="not UTF-8 or UTF-16 text"):
        load_config_space(p)


# --- malformed text ---------------------------------------------------------

def test_non_contiguous_rows_raise():
    text = (
        "00: de 10 89 24 07 04 10 00 a1 00 00 03 10 00 80 00\n"
        "20: 42 00 00 00 01 40 00 00 00 00 00 00 58 14 77 40\n"
    )
    with pytest.raises(ParseError, match="contiguous"):
        parse_lspci_hex(text)


def test_row_with_wrong_byte_count_raises():
    rows = _hex_rows(GPU)[:4]
    rows[-1] += " aa"  # a 17th byte on the last row, which no earlier row can catch
    with pytest.raises(ParseError, match="17 bytes on the row"):
        parse_lspci_hex("\n".join(rows))


def test_total_must_be_a_frame_size():
    with pytest.raises(ParseError, match="48 bytes of hex rows"):
        parse_lspci_hex("\n".join(_hex_rows(GPU)[:3]))  # 3 rows = 48 bytes, not a frame


def test_no_rows_raise():
    with pytest.raises(ParseError, match="no hex rows"):
        parse_lspci_hex("01:00.0 VGA compatible controller: nothing here\n")


def test_crlf_and_bom_are_tolerated(tmp_path):
    body = GPU.read_text().replace("\n", "\r\n")
    p = tmp_path / "crlf.txt"
    # EF BB BF = the UTF-8 byte order mark Notepad puts at the start of a file.
    p.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
    cs = load_config_space(p)
    assert cs.size == 4096 and cs.u16(0) == 0x10DE


def test_utf16_file_from_powershell_is_accepted(tmp_path):
    # Windows PowerShell 5.1 writes `... > dump.txt` as UTF-16 LE with an FF FE marker.
    p = tmp_path / "ps.txt"
    p.write_bytes(GPU.read_text().encode("utf-16"))
    cs = load_config_space(p)
    assert cs.size == 4096 and cs.bdf == "01:00.0"


def test_uppercase_hex_is_accepted():
    data = parse_lspci_hex("\n".join(_hex_rows(GPU)[:4]).upper())
    assert data[:2] == b"\xde\x10"


# --- the device line ----------------------------------------------------------

def test_domain_prefixed_bdf_lines():
    rows = "\n".join(_hex_rows(GPU)[:4])
    assert parse_lspci_block("0000:01:00.0 VGA x\n" + rows).bdf == "0000:01:00.0"  # lspci -D
    assert parse_lspci_block("10000:e1:00.0 NVMe x\n" + rows).bdf == "10000:e1:00.0"  # Intel VMD
    assert parse_lspci_block(" 01:00.0 VGA x\n" + rows).bdf == "01:00.0"  # hand-pasted, indented


# --- multi-device listings --------------------------------------------------

def test_multi_device_listing_splits_per_bdf():
    text = GPU.read_text() + "\n" + SSD.read_text()
    devs = parse_lspci_all(text)
    assert [d.bdf for d in devs] == ["01:00.0", "02:00.0"]
    assert devs[0].u16(0) == 0x10DE and devs[1].u16(0) == 0x144D
    assert all(d.size == 4096 for d in devs)


def test_split_blocks_keeps_decoded_text_with_its_device():
    text = GPU.read_text() + "\n" + SSD.read_text()
    blocks = split_lspci_blocks(text)
    assert len(blocks) == 2
    assert "Capabilities: [60] Power Management" in blocks[0]
    assert "Capabilities: [40] Power Management" in blocks[1]


def test_device_without_rows_is_skipped_in_a_listing():
    text = "00:1f.0 ISA bridge: no rows here\n\n" + SSD.read_text()
    devs = parse_lspci_all(text)
    assert [d.bdf for d in devs] == ["02:00.0"]


def test_decode_refuses_multi_device_file(tmp_path):
    p = tmp_path / "all.txt"
    p.write_text(GPU.read_text() + "\n" + SSD.read_text())
    with pytest.raises(ParseError, match="pcicfg all"):
        load_config_space(p)


def test_lspci_answer_key_is_kept():
    cs = load_config_space(GPU)
    assert "LnkSta:\tSpeed 2.5GT/s (downgraded), Width x16" in cs.lspci_text
    assert "00: de 10" not in cs.lspci_text  # hex rows are not part of the answer key


# --- command line -------------------------------------------------------------

def test_cli_hex_block_is_lspci_exact(tmp_path, capsys):
    # capsys: pytest captures what the program prints so the test can inspect it.
    # Exit code is OK now that every decoder module is in.
    assert main(["decode", str(GPU), "--hex"]) == OK
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("# 01:00.0 VGA compatible controller")
    assert "(lspci text)" in out[1]
    first = out.index("00: de 10 89 24 07 04 10 00 a1 00 00 03 10 00 80 00")
    assert out[first : first + 256] == _hex_rows(GPU)  # the whole block, byte for byte
    assert out[first - 1] == ""  # a blank line separates the decoded view from the bytes


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["list"]) == 3
    assert main(["decode", str(tmp_path), "--hex"]) == 1  # a directory, not a file
    assert main(["decode", str(tmp_path / "missing.txt"), "--hex"]) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
