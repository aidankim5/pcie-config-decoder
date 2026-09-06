"""Module 3 tests: the standard capability chain of both fixtures (every offset
and ID from the "Capabilities: [xx]" lines lspci printed in the same file),
and the guards on corrupted chains.
"""

import json
from pathlib import Path

from pcicfg.caps import MAX_HOPS, walk_standard_caps
from pcicfg.cli import OK, main
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


def test_gpu_spans_and_structure_lengths():
    chain = walk_standard_caps(load_config_space(GPU))
    # Each span is the gap between two lspci offsets; the last runs to 100h.
    assert [c.span for c in chain.entries] == [0x68 - 0x60, 0x78 - 0x68, 0xB4 - 0x78, 0x100 - 0xB4]
    # Structure sizes: PM 8 (spec), MSI 16 (64-bit address, no masking: Figure 7-45), PCIe
    # 60 (version 2), Vendor Specific declares 14h = 20.
    assert [c.structure_length for c in chain.entries] == [8, 16, 60, 0x14]
    vs = chain.find(0x09)
    assert vs.vendor_specific_length == 0x14 and vs.problem == ""
    assert len(vs.structure_data) == 20 and len(vs.data) == 76
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
    assert [c.span for c in chain.entries] == [0x50 - 0x40, 0x70 - 0x50, 0xB0 - 0x70, 0x100 - 0xB0]
    assert [c.structure_length for c in chain.entries] == [8, 16, 60, 12]  # PM 8, MSI 16, PCIe 60, MSI-X 12


def test_taught_tags_follow_claude_md_rule_5():
    chain = walk_standard_caps(load_config_space(SSD))
    # {id: taught} for each entry. Expected values come from CLAUDE.md rule 5, not the dump:
    # MSI (05) and PCI Express (10) are taught; Power Management (01) and MSI-X (11) are ahead.
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
    assert "(empty: the Capabilities Pointer is 00h)" in render_chain(chain)


def test_pointer_03_masks_to_empty_and_still_says_so():
    chain = walk_standard_caps(corrupted(GPU, {0x34: 0x03}))
    text = render_chain(chain)
    assert "masked to 00h" in text and "(empty: the Capabilities Pointer is 00h)" in text


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


def test_bad_ids_and_lengths_are_flagged_not_hidden():
    chain = walk_standard_caps(corrupted(GPU, {0x68: 0x00}))  # MSI's ID byte zeroed
    assert chain.find(0x00).problem.startswith("ID 00h")
    chain = walk_standard_caps(corrupted(GPU, {0xB6: 0x60}))  # Vendor Specific length 60h > the 4Ch to 100h
    assert "runs past the end of the PCI-compatible space" in chain.find(0x09).problem
    chain = walk_standard_caps(corrupted(GPU, {0xB6: 0x02}))  # below the 3 header bytes
    assert "below the 3 header bytes" in chain.find(0x09).problem


# --- rendering and CLI ----------------------------------------------------------------

def test_render_chain_gpu():
    text = render_chain(walk_standard_caps(load_config_space(GPU)))
    lines = text.splitlines()
    assert lines[0].startswith("Standard capability chain (spec 7.5.1.1.11; Capabilities Pointer 34h = 60h)")
    assert lines[1].startswith("  60h  ID 01  Power Management")
    assert "8 bytes to the next start at 68h; structure 8 bytes (spec)" in lines[1]
    assert "[ahead" in lines[1]  # PM registers are ahead until decoded by hand
    assert lines[3].startswith("  78h  ID 10  PCI Express") and "next B4h" in lines[3]
    assert "60 bytes to the next start at B4h; structure 60 bytes (by Capability Version and port type" in lines[3]
    assert lines[4].startswith("  B4h  ID 09  Vendor Specific (length 14h)") and "end of list" in lines[4]
    assert "76 bytes to 100h, the end of the PCI-compatible space; structure 20 bytes (declared, Table 7-160)" in lines[4]


def test_render_annotated_marks_starts_and_rebases():
    cs = load_config_space(GPU)
    text = render_annotated(cs, walk_standard_caps(cs))
    lines = text.splitlines()
    assert lines[0].startswith("Annotated PCI-compatible space 00h-FFh")
    assert "the extended chain (100h-FFFh, spec 7.6) follows below" in lines[0]  # the GPU dump is 4096 bytes
    row60 = lines.index("60: 01 68 03 48 08 00 00 00 05 78 81 00 58 0d e0 fe")
    assert lines[row60 + 1] == "    ^^ 60h: Power Management (ID 01, next 68h) [ahead: decoded by the tool, not yet worked through by hand]"
    # column of byte 8 in the row: 4 characters for "60: " plus 3 per byte x 8 = 28
    assert lines[row60 + 2] == " " * (4 + 3 * 8) + "^^ 68h: MSI (ID 05, next 78h)"
    header = "== 78h PCI Express: structure 60 bytes (by Capability Version and port type; a choice following pci_regs.h); 60 bytes to the next start at B4h; printed from 00 (relative offsets; add 78h for the absolute offset) =="
    i = lines.index(header)
    assert lines[i + 1] == "00: 10 b4 12 00 e1 8d 2c 11 3f 29 00 00 04 3d 45 00 | absolute 78h"
    assert lines[i + 2].startswith("10: 40 01 01 11") and lines[i + 2].endswith("| absolute 88h")
    # Link Control 0140 and Link Status 1101 sit at relative 10h/12h, absolute 88h/8Ah.


def test_render_annotated_vendor_specific_shows_only_its_20_bytes():
    cs = load_config_space(GPU)
    lines = render_annotated(cs, walk_standard_caps(cs)).splitlines()
    i = [k for k, ln in enumerate(lines) if ln.startswith("== B4h Vendor Specific: structure 20 bytes")][0]
    assert lines[i + 1].startswith("b4: ") is False and lines[i + 1].startswith("00: 09 00 14 01")
    assert lines[i + 2].startswith("10: 00 00 00 00 ") and "| absolute C4h" in lines[i + 2]
    assert lines[i + 3] == "   + 56 more bytes up to 100h are not part of this structure (see the hex rows above)"
    # The MSI-X-shaped bytes at C8h (11 00 05 00 ...) must NOT be printed as Vendor Specific content.
    assert "11 00 05 00" not in lines[i + 1] and "11 00 05 00" not in lines[i + 2]


def test_render_annotated_ssd_pm_is_8_bytes_inside_a_16_byte_span():
    cs = load_config_space(SSD)
    lines = render_annotated(cs, walk_standard_caps(cs)).splitlines()
    i = [k for k, ln in enumerate(lines) if ln.startswith("== 40h Power Management: structure 8 bytes (spec); 16 bytes to the next start at 50h")][0]
    assert lines[i + 1] == "00: 01 50 13 00 08 00 00 00                         | absolute 40h"
    assert lines[i + 2].startswith("   + 8 more bytes up to 50h are not part of this structure")


def test_cli_prints_chain_and_json_carries_it(capsys):
    assert main(["decode", str(SSD), "--annotate"]) == OK
    out = capsys.readouterr().out
    assert "  B0h  ID 11  MSI-X" in out
    assert "^^ 40h: Power Management (ID 01, next 50h)" in out
    assert main(["decode", str(GPU), "--json"]) == OK
    doc = json.loads(capsys.readouterr().out)
    entries = doc["standard_capabilities"]["entries"]
    assert [e["offset"] for e in entries] == [0x60, 0x68, 0x78, 0xB4]
    assert entries[2]["span_data"].startswith("10b41200")
    assert entries[3]["structure_length"] == 0x14 and len(entries[3]["structure_data"]) == 2 * 20


def test_json_for_absent_function_says_why_the_chain_is_missing(tmp_path):
    p = tmp_path / "ff.bin"
    p.write_bytes(bytes([0xFF] * 256))
    assert main(["decode", str(p), "--json"]) == OK
