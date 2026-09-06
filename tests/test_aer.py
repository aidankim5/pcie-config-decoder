"""Module 7 tests: AER on both fixtures against lspci's UESta/UEMsk/UESvrt/CESta/
CEMsk/AERCap/HeaderLog lines, the Header Log byte order, and the Root registers.
"""

from pathlib import Path

from pcicfg.aer import SEVERITY_DEFAULT, aer_structure_length, decode_aer
from pcicfg.parse import ConfigSpace, load_config_space

FIXTURES = Path(__file__).parent / "fixtures"
GPU = FIXTURES / "rtx3060ti_01-00.0.txt"
SSD = FIXTURES / "samsung990pro_02-00.0.txt"


def test_gpu_aer_at_420h_acceptance():
    # lspci: UESta all '-'; UEMsk all '-'; UESvrt: DLP+ SDES+ FCP+ RxOF+ MalfTLP+ UncorrIntErr+;
    #        CESta: AdvNonFatalErr+; CEMsk: AdvNonFatalErr+ HeaderOF+; AERCap: First Error Pointer: 00,
    #        all capabilities '-'; HeaderLog: 00000000 x4
    aer = decode_aer(load_config_space(GPU), 0x420)
    assert aer.version == 2
    assert aer.register("ue_status").raw == 0 and aer.uncorrectable_errors == []
    assert aer.register("ue_mask").raw == 0 and aer.uncorrectable_masked == []
    assert aer.register("ue_severity").raw == 0x00462030 == SEVERITY_DEFAULT and aer.severity_is_spec_default
    assert aer.fatal_errors == [
        "Data Link Protocol Error",
        "Surprise Down Error",
        "Flow Control Protocol Error",
        "Receiver Overflow",
        "Malformed TLP",
        "Uncorrectable Internal Error",
    ]
    assert aer.register("ce_status").raw == 0x00002000
    assert aer.correctable_errors == ["Advisory Non-Fatal Error"]  # the finding: one logged advisory error
    assert aer.register("ce_mask").raw == 0x0000A000
    assert aer.correctable_masked == ["Advisory Non-Fatal Error", "Header Log Overflow"]
    assert aer.register("caps_control").raw == 0 and aer.first_error_pointer == 0
    assert aer.header_log == [0, 0, 0, 0]
    assert aer.tlp_prefix_log is None and aer.structure_length == 0x2C
    assert aer.summary == "uncorrectable errors logged: none; correctable errors logged: Advisory Non-Fatal Error; first error pointer bit 0"


def test_ssd_aer_at_100h_acceptance():
    # lspci: UEMsk: UncorrIntErr+; UESvrt as GPU; CESta all '-'; CEMsk: AdvNonFatalErr+ CorrIntErr+ HeaderOF+;
    #        AERCap: ECRCGenCap+ ECRCChkCap+ MultHdrRecCap+
    aer = decode_aer(load_config_space(SSD), 0x100)
    assert aer.register("ue_mask").raw == 0x00400000 and aer.uncorrectable_masked == ["Uncorrectable Internal Error"]
    assert aer.register("ue_severity").raw == 0x00462030
    assert aer.register("ce_status").raw == 0 and aer.correctable_errors == []
    assert aer.register("ce_mask").raw == 0x0000E000
    assert aer.correctable_masked == ["Advisory Non-Fatal Error", "Corrected Internal Error", "Header Log Overflow"]
    caps = aer.register("caps_control")
    assert caps.raw == 0x000002A0
    assert caps.is_set("ECRC Generation Capable") and caps.is_set("ECRC Check Capable") and caps.is_set("Multiple Header Recording Capable")
    assert not caps.is_set("ECRC Generation Enable") and not caps.is_set("ECRC Check Enable")


def test_register_texts_read_like_the_spec():
    aer = decode_aer(load_config_space(GPU), 0x420)
    sev = aer.register("ue_severity")
    assert sev.field("Data Link Protocol Error").text == "fatal"
    assert sev.field("Poisoned TLP Received").text == "non-fatal"
    mask = aer.register("ce_mask")
    assert mask.field("Advisory Non-Fatal Error").text == "masked (not logged, not reported)"
    assert mask.field("Bad TLP").text == "reported"
    assert aer.register("ce_status").field("Advisory Non-Fatal Error").text.startswith("+")


def test_header_log_byte_order_follows_7_8_4_8():
    # Write a TLP header 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF into the log the way the
    # spec says: header byte 0 in byte 3 of the first DWORD, so config bytes 43Ch.. = 33 22 11 00 ...
    data = bytearray(load_config_space(GPU).data)
    wire = bytes(range(0x00, 0x100, 0x11))  # 00 11 22 ... FF
    for n in range(4):
        data[0x420 + 0x1C + 4 * n : 0x420 + 0x1C + 4 * n + 4] = wire[4 * n : 4 * n + 4][::-1]  # [::-1] reverses the 4 bytes
    aer = decode_aer(ConfigSpace(bytes(data)), 0x420)
    assert aer.header_log == [0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF]  # lspci's HeaderLog view
    assert aer.header_log_wire_bytes == wire  # the header as it went over the link


def test_root_registers_and_tlp_prefix_log():
    data = bytearray(load_config_space(GPU).data)
    data[0x420 + 0x18] = 0x00
    data[0x420 + 0x19] = 0x08  # caps_control bit 11: TLP Prefix Log Present
    data[0x420 + 0x2C] = 0x07  # Root Error Command: all three enables
    data[0x420 + 0x30] = 0x81  # Root Error Status: ERR_COR Received, ECS = 01b (SIG_SFW)
    data[0x420 + 0x34 : 0x420 + 0x38] = bytes.fromhex("08 01 10 02")  # ERR_COR source 0108h (01:01.0), fatal source 0210h
    data[0x420 + 0x38 : 0x420 + 0x3C] = bytes.fromhex("78 56 34 12")
    aer = decode_aer(ConfigSpace(bytes(data)), 0x420, is_root=True)
    assert aer.structure_length == 0x48 and aer.tlp_prefix_log[0] == 0x12345678
    assert aer.register("root_error_command").is_set("Fatal Error Reporting Enable")
    status = aer.register("root_error_status")
    assert status.is_set("ERR_COR Received") and status.field("ERR_COR Subclass").text == "ECS SIG_SFW"
    src = aer.register("error_source_id")
    assert src.field("ERR_COR Source Identification").text == "0108h"
    assert src.field("ERR_FATAL/NONFATAL Source Identification").text == "0210h"
    assert aer_structure_length(0, is_root=True) == 0x38 and aer_structure_length(0, is_root=False) == 0x2C
