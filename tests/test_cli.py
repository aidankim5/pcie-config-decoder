"""Module 8 tests: the finished decode command, `all` over a multi-device listing,
JSON documents, and the brief's 256-byte acceptance case.
"""

import json
from pathlib import Path

from pcicfg.cli import BAD_INPUT, NOT_YET, OK, main
from pcicfg.parse import load_config_space

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


def test_decode_prints_every_section_and_exits_0(capsys):
    assert main(["decode", str(GPU)]) == OK
    captured = capsys.readouterr()
    assert captured.err == ""
    out = captured.out
    for marker in (
        "Type 0 header (spec 7.5.1.1, 7.5.1.2)  [taught]",
        "Standard capability chain (spec 7.5.1.1.11; Capabilities Pointer 34h = 60h)  [taught]",
        "-- 78h PCI Express (ID 10, spec 7.5.3, 60 bytes: version 2, Legacy PCI Express Endpoint)",
        "  Link: Speed 2.5 GT/s (downgraded), Width x16",
        "Extended capability chain (spec 7.6.1, 7.6.3; starts at 100h, one DWORD header each)  [taught]",
        "-- 420h AER (Advanced Error Reporting) (ID 0001 v2, header 60020001, 44 bytes)",
        "  summary: uncorrectable errors logged: none; correctable errors logged: Advisory Non-Fatal Error; first error pointer bit 0",
        "  +1Ch (43Ch) Header Log                                         00000000 00000000 00000000 00000000",
    ):
        assert marker in out, marker
    assert "not built yet" not in out


def test_256_byte_input_decodes_header_and_chain_and_reports_no_extended_space(tmp_path, capsys):
    # The brief's parser test: "a 256-byte input decodes the header and standard chain and
    # reports 'extended space not present in dump'".
    p = tmp_path / "gpu256.bin"
    p.write_bytes(load_config_space(GPU).data[:256])
    assert main(["decode", str(p)]) == OK
    out = capsys.readouterr().out
    assert "  00h Vendor ID          10de                 NVIDIA Corporation" in out
    assert "  78h  ID 10  PCI Express" in out
    assert "  Link: Speed 2.5 GT/s (downgraded), Width x16" in out
    assert "note: extended space not present in dump (256 bytes; the extended chain needs the 4096-byte ECAM frame, spec 7.2.2)" in out


def test_json_document_is_complete(capsys):
    assert main(["decode", str(SSD), "--json"]) == OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["bdf"] == "02:00.0" and doc["header"]["vendor_id"] == 0x144D
    std = doc["standard_capabilities"]["entries"]
    assert [e["id"] for e in std] == [0x01, 0x05, 0x10, 0x11]
    ext = doc["extended_capabilities"]["entries"]
    assert [e["offset"] for e in ext] == [0x100, 0x168, 0x188, 0x1AC, 0x1C4, 0x1CC, 0x350]
    aer = ext[0]["aer"]
    assert aer["correctable_errors"] == [] and aer["uncorrectable_masked"] == ["Uncorrectable Internal Error"]
    assert ext[4]["summary"] == "max snoop latency 15728640 ns, max no-snoop latency 15728640 ns"


def test_all_decodes_every_device_in_a_listing(tmp_path, capsys):
    listing = tmp_path / "lspci-vvv-xxxx.txt"
    listing.write_text(GPU.read_text() + "\n" + SSD.read_text())
    assert main(["all", str(listing)]) == OK
    captured = capsys.readouterr()
    assert captured.out.count("Type 0 header (spec 7.5.1.1, 7.5.1.2)  [taught]") == 2
    assert "# 01:00.0 VGA compatible controller" in captured.out and "# 02:00.0 Non-Volatile memory controller" in captured.out
    assert "2 device(s) decoded" in captured.err

    assert main(["all", str(listing), "--json"]) == OK
    docs = json.loads(capsys.readouterr().out)
    assert [d["bdf"] for d in docs] == ["01:00.0", "02:00.0"]


def test_all_rejects_a_file_without_hex_rows(tmp_path, capsys):
    p = tmp_path / "ids.txt"
    p.write_text((FIXTURES / "ids.txt").read_text())
    assert main(["all", str(p)]) == BAD_INPUT
    assert "not an lspci text listing" in capsys.readouterr().err


def test_layer_3_says_not_built_yet(capsys):
    assert main(["dump", "01:00.0"]) == NOT_YET
