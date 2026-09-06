"""Module 6 tests: the extended chain of both fixtures (every offset, ID and
version from lspci's "Capabilities: [xxx vN]" lines), the guards, and the
fully decoded extended capabilities against lspci's own lines.
"""

from pathlib import Path

from pcicfg.extcaps import (
    MAX_HOPS,
    decode_extended_registers,
    l1ss_summary,
    ltr_latency_ns,
    ltr_summary,
    walk_extended_caps,
)
from pcicfg.cli import OK, main
from pcicfg.parse import ConfigSpace, load_config_space

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


def summary(chain):
    """(offset, id, version, next) per entry, in link order."""
    return [(c.offset, c.cap_id, c.version, c.next_offset) for c in chain.entries]


# --- the two fixtures ------------------------------------------------------------------

def test_gpu_extended_chain_exactly_in_link_order():
    # lspci: [100 v1] Virtual Channel, [258 v1] L1 PM Substates, [128 v1] Power Budgeting,
    #        [420 v2] AER, [600 v1] Vendor Specific, [900 v1] Secondary PCIe, [bb0 v1] Resizable BAR,
    #        [c1c v1] Physical Layer 16.0 GT/s, [d00 v1] Lane Margining, [e00 v1] Data Link Feature
    chain = walk_extended_caps(load_config_space(GPU), max_link_width=16)
    assert chain.present and chain.notes == []
    assert summary(chain) == [
        (0x100, 0x0002, 1, 0x258),
        (0x258, 0x001E, 1, 0x128),  # backwards in memory: a pointer, not a position
        (0x128, 0x0004, 1, 0x420),
        (0x420, 0x0001, 2, 0x600),
        (0x600, 0x000B, 1, 0x900),
        (0x900, 0x0019, 1, 0xBB0),
        (0xBB0, 0x0015, 1, 0xC1C),
        (0xC1C, 0x0026, 1, 0xD00),
        (0xD00, 0x0027, 1, 0xE00),
        (0xE00, 0x0025, 1, 0x000),
    ]
    assert [c.taught for c in chain.entries] == [False, False, False, True, False, False, False, False, False, False]
    assert chain.entries[0].header == 0x25810002  # bytes 02 00 81 25 at 100h


def test_gpu_spans_and_structure_lengths():
    chain = walk_extended_caps(load_config_space(GPU), max_link_width=16)
    by_id = {c.cap_id: c for c in chain.entries}
    assert by_id[0x0002].span == 0x128 - 0x100 and by_id[0x0002].structure_length is None  # VC: ahead
    assert by_id[0x001E].span == 0x420 - 0x258 and by_id[0x001E].structure_length == 0x10
    assert by_id[0x0004].structure_length == 0x10
    assert by_id[0x0001].structure_length == 0x2C  # no TLP Prefix Log, not a Root Port
    assert by_id[0x000B].structure_length == 0x24  # VSEC Length declares it
    assert by_id[0x0019].structure_length == 0x0C + 2 * 16
    assert by_id[0x0026].structure_length == 0x20 + 16
    assert by_id[0x0027].structure_length == 0x08 + 4 * 16
    assert by_id[0x0025].structure_length == 0x0C and by_id[0x0025].span == 0x1000 - 0xE00
    assert all(c.problem == "" for c in chain.entries)


def test_ssd_extended_chain_exactly():
    # lspci: [100 v2] AER, [168 v1] Secondary PCIe, [188 v1] Physical Layer 16.0 GT/s,
    #        [1ac v1] Lane Margining, [1c4 v1] LTR, [1cc v1] L1 PM Substates, [350 v1] Data Link Feature
    chain = walk_extended_caps(load_config_space(SSD), max_link_width=4)
    assert summary(chain) == [
        (0x100, 0x0001, 2, 0x168),
        (0x168, 0x0019, 1, 0x188),
        (0x188, 0x0026, 1, 0x1AC),
        (0x1AC, 0x0027, 1, 0x1C4),
        (0x1C4, 0x0018, 1, 0x1CC),
        (0x1CC, 0x001E, 1, 0x350),
        (0x350, 0x0025, 1, 0x000),
    ]
    assert chain.find(0x0018).structure_length == 8 and chain.find(0x0018).span == 8


# --- frame and guards ------------------------------------------------------------------

def test_256_byte_dump_reports_extended_space_not_present():
    chain = walk_extended_caps(ConfigSpace(load_config_space(GPU).data[:256]))
    assert not chain.present and chain.entries == []
    assert any("extended space not present in dump" in n for n in chain.notes)


def test_all_zero_and_all_ones_headers_at_100h():
    data = bytearray(load_config_space(GPU).data)
    data[0x100:0x104] = bytes(4)
    chain = walk_extended_caps(ConfigSpace(bytes(data)))
    assert chain.present and chain.entries == [] and any("00000000h" in n for n in chain.notes)
    data[0x100:0x104] = b"\xff\xff\xff\xff"
    chain = walk_extended_caps(ConfigSpace(bytes(data)))
    assert chain.entries == [] and any("FFFFFFFFh" in n for n in chain.notes)


def patched(path, patches):
    data = bytearray(load_config_space(path).data)
    for off, value in patches.items():
        data[off] = value
    return ConfigSpace(bytes(data))


def test_loop_stops():
    # E00h's header ends the list (next 000h); point it back at 100h instead: byte E03h = 0x10 -> next 100h.
    chain = walk_extended_caps(patched(GPU, {0xE02: 0x01, 0xE03: 0x10}))
    assert len(chain.entries) == 10
    assert any("100h was already visited" in n for n in chain.notes)


def test_next_below_100h_and_unaligned_next_stop():
    # 100h header 25810002: next = 258h. Rewrite the top 12 bits: next = 080h (below 100h).
    chain = walk_extended_caps(patched(GPU, {0x102: 0x01, 0x103: 0x08}))
    assert [c.offset for c in chain.entries] == [0x100]
    assert any("below 100h" in n for n in chain.notes)
    # next = 259h: bits 1:0 set -> masked to 258h, noted, walk continues
    chain = walk_extended_caps(patched(GPU, {0x102: 0x91, 0x103: 0x25}))
    assert [c.offset for c in chain.entries][:2] == [0x100, 0x258]
    assert any("masked to 258h" in n for n in chain.notes)


def test_next_past_the_dump_stops():
    chain = walk_extended_caps(patched(GPU, {0xE02: 0xC1, 0xE03: 0xFF}))  # next = FFCh, header would need FFCh..FFFh: fits
    assert chain.entries[-1].offset == 0xFFC
    chain = walk_extended_caps(patched(GPU, {0xE02: 0xD1, 0xE03: 0xFF}))  # next = FFDh -> masked FFCh (bits 1:0 set)
    assert any("masked to FFCh" in n for n in chain.notes)


def test_more_than_64_hops_stops():
    data = bytearray(4096)
    data[0x06] = 0x10
    # 100 headers at 100h, 104h, ... each pointing to the next: ID 0003 (Device Serial Number), v1
    for n in range(100):
        off = 0x100 + 4 * n
        nxt = off + 4
        data[off:off + 4] = ((nxt << 20) | (1 << 16) | 0x0003).to_bytes(4, "little")
    chain = walk_extended_caps(ConfigSpace(bytes(data)))
    assert len(chain.entries) == MAX_HOPS == 64
    assert any("more than 64 hops" in n for n in chain.notes)


# --- fully decoded capabilities, against lspci ---------------------------------------------

def registers_by_key(cs, cap):
    return {r.key: r for r in decode_extended_registers(cs, cap)}


def test_ssd_ltr_matches_lspci():
    # lspci: Max snoop latency: 15728640ns / Max no snoop latency: 15728640ns
    cs = load_config_space(SSD)
    cap = walk_extended_caps(cs, 4).find(0x0018)
    regs = registers_by_key(cs, cap)
    assert regs["max_snoop"].raw == 0x100F and regs["max_snoop"].value("LatencyValue") == 15
    assert regs["max_snoop"].field("LatencyScale").text == "x 1,048,576 ns"
    assert ltr_latency_ns(0x100F) == 15728640
    assert ltr_summary(cs, cap) == "max snoop latency 15728640 ns, max no-snoop latency 15728640 ns"
    assert ltr_latency_ns(0x1801) is None  # scale 110b: not permitted


def test_gpu_l1_pm_substates_matches_lspci():
    # lspci: L1SubCap: PCI-PM_L1.2+ PCI-PM_L1.1+ ASPM_L1.2+ ASPM_L1.1+ L1_PM_Substates+
    #        PortCommonModeRestoreTime=255us PortTPowerOnTime=10us
    #        L1SubCtl1: all '-'; T_CommonMode=0us LTR1.2_Threshold=281600ns; L1SubCtl2: T_PwrOn=10us
    cs = load_config_space(GPU)
    cap = walk_extended_caps(cs, 16).find(0x001E)
    regs = registers_by_key(cs, cap)
    caps = regs["capabilities"]
    assert caps.raw == 0x0028FF1F
    assert all(caps.is_set(n) for n in ("PCI-PM L1.2 Supported", "PCI-PM L1.1 Supported", "ASPM L1.2 Supported", "ASPM L1.1 Supported", "L1 PM Substates Supported"))
    assert caps.field("Port Common_Mode_Restore_Time").text == "255 us"
    assert caps.field("Port T_POWER_ON Scale").text == "2 us" and caps.value("Port T_POWER_ON Value") == 5
    ctl1 = regs["control_1"]
    assert ctl1.raw == 0x41130000 and ctl1.value("LTR_L1.2_THRESHOLD_Value") == 275 and ctl1.field("LTR_L1.2_THRESHOLD_Scale").text == "x 1,024 ns"
    assert regs["control_2"].raw == 0x28
    assert "status" not in regs  # version 1: no Status register
    assert l1ss_summary(cs, cap) == (
        "supported: PCI-PM L1.2+ L1.1+ ASPM L1.2+ L1.1+; Port Common_Mode_Restore_Time 255 us; Port T_POWER_ON 10 us; "
        "enabled: PCI-PM L1.2- L1.1- ASPM L1.2- L1.1-; Common_Mode_Restore_Time 0 us; LTR_L1.2_THRESHOLD 281600 ns; T_POWER_ON 10 us"
    )


def test_ssd_l1_pm_substates_threshold_30720ns():
    # lspci: PortCommonModeRestoreTime=10us PortTPowerOnTime=10us; LTR1.2_Threshold=30720ns; T_PwrOn=10us
    cs = load_config_space(SSD)
    cap = walk_extended_caps(cs, 4).find(0x001E)
    assert "Port Common_Mode_Restore_Time 10 us; Port T_POWER_ON 10 us" in l1ss_summary(cs, cap)
    assert "LTR_L1.2_THRESHOLD 30720 ns; T_POWER_ON 10 us" in l1ss_summary(cs, cap)


def test_gpu_power_budgeting_vsec_secondary_pcie_dlf_phy16_margining():
    cs = load_config_space(GPU)
    chain = walk_extended_caps(cs, 16)
    # Power Budgeting (lspci prints only the header): header 42010004 at 128h, Data Select 0, System Allocated 0
    pb = registers_by_key(cs, chain.find(0x0004))
    assert pb["data_select"].raw == 0 and pb["capability"].value("System Allocated") == 0
    # VSEC: lspci 'Vendor Specific Information: ID=0001 Rev=1 Len=024'
    vsec = registers_by_key(cs, chain.find(0x000B))["vsec_header"]
    assert vsec.raw == 0x02410001 and vsec.value("VSEC ID") == 1 and vsec.value("VSEC Rev") == 1 and vsec.value("VSEC Length") == 0x24
    # Secondary PCIe: lspci 'LnkCtl3: LnkEquIntrruptEn- PerformEqu-', 'LaneErrStat: 0'
    sec = registers_by_key(cs, chain.find(0x0019))
    assert sec["link_control_3"].raw == 0 and sec["lane_error_status"].field("Lane Error Status Bits").text == "none"
    # Data Link Feature: capabilities and status both 80000001h
    dlf = registers_by_key(cs, chain.find(0x0025))
    assert dlf["capabilities"].raw == 0x80000001 and dlf["capabilities"].is_set("Local Scaled Flow Control Supported")
    assert dlf["status"].is_set("Remote Data Link Feature Supported Valid")
    # Physical Layer 16.0 GT/s: lspci 'Phy16Sta: EquComplete+ EquPhase1+ EquPhase2+ EquPhase3+ LinkEquRequest-'
    phy = registers_by_key(cs, chain.find(0x0026))
    assert phy["status"].raw == 0x0F and not phy["status"].is_set("Link Equalization Request 16.0 GT/s")
    assert phy["local_parity_mismatch"].raw == 0
    # Lane Margining: lspci 'PortCap: Uses Driver+', 'PortSta: MargReady+ MargSoftReady+'
    lm = registers_by_key(cs, chain.find(0x0027))
    assert lm["port_capabilities"].raw == 0x0001 and lm["port_status"].raw == 0x0003


def test_ssd_lane_margining_not_ready():
    # lspci: PortCap: Uses Driver-; PortSta: MargReady- MargSoftReady-
    cs = load_config_space(SSD)
    lm = registers_by_key(cs, walk_extended_caps(cs, 4).find(0x0027))
    assert lm["port_capabilities"].raw == 0 and lm["port_status"].raw == 0


def test_header_only_capabilities_have_no_registers():
    cs = load_config_space(GPU)
    chain = walk_extended_caps(cs, 16)
    assert decode_extended_registers(cs, chain.find(0x0002)) == []  # Virtual Channel: ahead
    assert decode_extended_registers(cs, chain.find(0x0015)) == []  # Resizable BAR: ahead


# --- modules 6-8 review fixes -----------------------------------------------------------

def test_aer_size_follows_port_type_and_prefix_support_not_a_status_bit():
    """The review's finding: bit 11 of Advanced Error Capabilities and Control is error state
    (is the logged prefix valid), not layout. What sizes AER is the Device/Port Type and
    Device Capabilities 2 bit 21."""
    data = bytearray(load_config_space(GPU).data)
    data[0x420 + 0x19] = 0x08  # caps_control bit 11 set: must not change the size
    cs = ConfigSpace(bytes(data))
    assert walk_extended_caps(cs, 16).find(0x0001).structure_length == 0x2C
    assert walk_extended_caps(cs, 16, is_root=True).find(0x0001).structure_length == 0x38
    assert walk_extended_caps(cs, 16, e2e_prefix=True).find(0x0001).structure_length == 0x48


def test_root_port_chain_line_and_block_agree(tmp_path, capsys):
    """A Root Port's AER prints Root Error registers at +2Ch..+37h, so the chain line and the
    block heading must say 56 bytes, not 44."""
    data = bytearray(load_config_space(GPU).data)
    data[0x7A] = 0x42  # PCI Express Capabilities: version 2, Root Port
    p = tmp_path / "rootport.bin"
    p.write_bytes(bytes(data))
    assert main(["decode", str(p)]) == OK
    out = capsys.readouterr().out
    assert "structure 56 bytes (by port type and End-End TLP Prefix Supported" in out
    assert "-- 420h AER (Advanced Error Reporting) (ID 0001 v2, header 60020001, 56 bytes)" in out
    assert "+2Ch (44Ch) Root Error Command" in out


def test_vsec_length_below_its_own_headers_is_flagged():
    data = bytearray(load_config_space(GPU).data)
    data[0x604 + 3] = 0x00  # VSEC Length (bits 31:20) -> 0
    data[0x604 + 2] = 0x10  # keep VSEC Rev 1, length nibble 0
    cap = walk_extended_caps(ConfigSpace(bytes(data)), 16).find(0x000B)
    assert cap.structure_length is None and "smaller than the 8 bytes" in cap.problem


def test_header_only_capabilities_say_header_only_and_are_tagged_ahead(capsys):
    assert main(["decode", str(GPU)]) == OK
    out = capsys.readouterr().out
    line = [ln for ln in out.splitlines() if ln.startswith("-- 100h Virtual Channel")][0]
    assert "[ahead: decoded by the tool, not yet worked through by hand]" in line
    assert "header only; first 64 bytes of" in out
