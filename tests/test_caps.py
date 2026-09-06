"""Module 3 tests: the standard capability chain of both fixtures (every offset
and ID from the "Capabilities: [xx]" lines lspci printed in the same file),
and the guards on corrupted chains.
"""

import json
from pathlib import Path

from pcicfg.caps import MAX_HOPS, walk_standard_caps
from pcicfg.cli import NOT_YET, main
from pcicfg.parse import ConfigSpace, load_config_space
from pcicfg.render import render_annotated, render_chain

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


def summary(chain):
    """(offset, id, next) per entry, in link order."""
    return [(c.offset, c.cap_id, c.next_pointer) for c in chain.entries]


# --- the two fixtures ------------------------------------------------------------

def test_gpu_chain_exactly():
    # lspci: Capabilities: [60] Power Management, [68] MSI, [78] Express, [b4] Vendor Specific
    chain = walk_standard_caps(load_config_space(GPU))
    assert chain.has_list and chain.pointer == 0x60
    assert summary(chain) == [
        (0x60, 0x01, 0x68),
        (0x68, 0x05, 0x78),
        (0x78, 0x10, 0xB4),
        (0xB4, 0x09, 0x00),
    ]
    assert [c.name for c in chain.entries] == ["Power Management", "MSI", "PCI Express", "Vendor Specific"]
    assert chain.notes == []


def test_gpu_spans_and_vendor_specific_length():
    chain = walk_standard_caps(load_config_space(GPU))
    assert [c.span for c in chain.entries] == [8, 16, 60, 0x100 - 0xB4]
    vs = chain.find(0x09)
    assert vs.vendor_specific_length == 0x14  # lspci: Vendor Specific Information: Len=14
    assert vs.problem == ""
    pcie = chain.find(0x10)
    assert pcie.data[:2] == b"\x10\xb4"  # byte 0 = ID, byte 1 = next: two fields, no flip
    assert pcie.end == 0xB4


def test_ssd_chain_exactly():
    # lspci: Capabilities: [40] Power Management, [50] MSI, [70] Express, [b0] MSI-X
    chain = walk_standard_caps(load_config_space(SSD))
    assert chain.pointer == 0x40
    assert summary(chain) == [
        (0x40, 0x01, 0x50),
        (0x50, 0x05, 0x70),
        (0x70, 0x10, 0xB0),
        (0xB0, 0x11, 0x00),
    ]
    assert [c.name for c in chain.entries] == ["Power Management", "MSI", "PCI Express", "MSI-X"]
    assert [c.span for c in chain.entries] == [16, 32, 64, 0x100 - 0xB0]


def test_taught_tags_follow_claude_md_rule_5():
    chain = walk_standard_caps(load_config_space(SSD))
    assert {c.cap_id: c.taught for c in chain.entries} == {0x01: False, 0x05: True, 0x10: True, 0x11: False}


# --- guards on corrupted chains -----------------------------------------------------

def corrupted(path, patches):
    """The fixture's bytes with some offsets overwritten; patches is {offset: value}."""
    data = bytearray(load_config_space(path).data)
    for off, value in patches.items():
        data[off] = value
    return ConfigSpace(bytes(data))


def test_self_loop_stops():
    chain = walk_standard_caps(corrupted(GPU, {0x69: 0x68}))  # MSI points at itself
    assert summary(chain) == [(0x60, 0x01, 0x68), (0x68, 0x05, 0x68)]
    assert any("loops" in n for n in chain.notes)


def test_longer_loop_stops():
    chain = walk_standard_caps(corrupted(GPU, {0xB5: 0x60}))  # Vendor Specific points back to PM
    assert len(chain.entries) == 4
    assert any("60h was already visited" in n for n in chain.notes)


def test_pointer_into_header_stops():
    chain = walk_standard_caps(corrupted(GPU, {0x69: 0x30}))
    assert [c.offset for c in chain.entries] == [0x60, 0x68]
    assert any("points into the header" in n for n in chain.notes)


def test_unaligned_pointer_stops():
    chain = walk_standard_caps(corrupted(GPU, {0x69: 0x7A}))
    assert [c.offset for c in chain.entries] == [0x60, 0x68]
    assert any("not DWORD aligned" in n for n in chain.notes)


def test_capabilities_pointer_low_bits_are_masked():
    chain = walk_standard_caps(corrupted(GPU, {0x34: 0x63}))
    assert chain.pointer_raw == 0x63 and chain.pointer == 0x60
    assert [c.offset for c in chain.entries][:1] == [0x60]
    assert any("masked to 60h" in n for n in chain.notes)


def test_status_bit_4_clear_means_no_walk():
    chain = walk_standard_caps(corrupted(GPU, {0x06: 0x00}))  # Status low byte: bit 4 cleared
    assert not chain.has_list and chain.entries == []
    assert any("Status bit 4" in n for n in chain.notes)


def test_pointer_zero_is_an_empty_list():
    chain = walk_standard_caps(corrupted(GPU, {0x34: 0x00}))
    assert chain.has_list and chain.entries == [] and chain.notes == []


def test_header_only_dump_cannot_be_walked():
    chain = walk_standard_caps(ConfigSpace(load_config_space(GPU).data[:64]))
    assert chain.entries == []
    assert any("header only" in n for n in chain.notes)


def test_256_byte_dump_walks_the_whole_chain():
    chain = walk_standard_caps(ConfigSpace(load_config_space(GPU).data[:256]))
    assert [c.offset for c in chain.entries] == [0x60, 0x68, 0x78, 0xB4]
    assert chain.entries[-1].end == 0x100


def test_all_48_aligned_slots_walk_without_a_false_loop():
    # A chain through every DWORD-aligned start 40h, 44h, ..., FCh: 48 entries, no repeat.
    data = bytearray(256)
    data[0x06] = 0x10  # Status bit 4
    data[0x34] = 0x40
    for off in range(0x40, 0x100, 4):
        data[off] = 0x09  # Vendor Specific, so the ID is valid
        data[off + 1] = off + 4 if off + 4 < 0x100 else 0
        data[off + 2] = 4  # declared length fits the 4-byte slot
    chain = walk_standard_caps(ConfigSpace(bytes(data)))
    assert len(chain.entries) == MAX_HOPS == 48
    assert chain.notes == []
    assert all(c.span == 4 and c.problem == "" for c in chain.entries)


def test_bad_ids_are_flagged_not_hidden():
    chain = walk_standard_caps(corrupted(GPU, {0x68: 0x00}))  # MSI's ID byte zeroed
    assert chain.find(0x00).problem.startswith("ID 00h")
    chain = walk_standard_caps(corrupted(GPU, {0xB6: 0x60}))  # Vendor Specific length 60h > the 4Ch to 100h
    assert "runs past" in chain.find(0x09).problem


# --- rendering and CLI ----------------------------------------------------------------

def test_render_chain_gpu():
    text = render_chain(walk_standard_caps(load_config_space(GPU)))
    lines = text.splitlines()
    assert lines[0].startswith("Standard capability chain (spec 7.5.1.1.11; Capabilities Pointer 34h = 60h)")
    assert lines[1].startswith("  60h  ID 01  Power Management")
    assert "[ahead" in lines[1]  # PM registers are ahead until decoded by hand
    assert lines[3].startswith("  78h  ID 10  PCI Express") and "next b4h" in lines[3] and "60 bytes" in lines[3]
    assert lines[4].startswith("  B4h  ID 09  Vendor Specific (length 14h)") and "end of list" in lines[4]


def test_render_annotated_marks_starts_and_rebases():
    cs = load_config_space(GPU)
    text = render_annotated(cs, walk_standard_caps(cs))
    lines = text.splitlines()
    row60 = lines.index("60: 01 68 03 48 08 00 00 00 05 78 81 00 58 0d e0 fe")
    assert lines[row60 + 1] == "    ^^ 60h: Power Management (ID 01, next 68h)"
    assert lines[row60 + 2] == " " * 28 + "^^ 68h: MSI (ID 05, next 78h)"
    assert "== 78h PCI Express: 60 bytes, printed from 00 (relative offsets; add 78h for the absolute offset) ==" in lines
    i = lines.index("== 78h PCI Express: 60 bytes, printed from 00 (relative offsets; add 78h for the absolute offset) ==")
    assert lines[i + 1] == "00: 10 b4 12 00 e1 8d 2c 11 3f 29 00 00 04 3d 45 00"
    assert lines[i + 2].startswith("10: 40 01 01 11")  # Link Control 0140 and Link Status 1101 at relative 10h/12h


def test_cli_prints_chain_and_json_carries_it(capsys):
    assert main(["decode", str(SSD), "--annotate"]) == NOT_YET
    out = capsys.readouterr().out
    assert "  B0h  ID 11  MSI-X" in out
    assert "^^ 40h: Power Management (ID 01, next 50h)" in out
    assert main(["decode", str(GPU), "--json"]) == NOT_YET
    doc = json.loads(capsys.readouterr().out)
    entries = doc["standard_capabilities"]["entries"]
    assert [e["offset"] for e in entries] == [0x60, 0x68, 0x78, 0xB4]
    assert entries[2]["data"].startswith("10b41200")
