"""Power Management capability, ID 01h (spec 7.5.2), 8 bytes.

[Ahead] The tool decodes these registers; Aidan has not yet worked through
them by hand. The chain entry itself is taught. Every bit below comes from
the spec's own tables, read twice independently.

Layout (7.5.2, Figure 7-17), offsets relative to the capability's start:
  +00h Capability ID (01h)        +01h Next Capability Pointer
  +02h PMC, Power Management Capabilities (16 bits, 7.5.2.1 Table 7-13)
  +04h PMCSR, Power Management Control/Status (16 bits, 7.5.2.2 Table 7-14)
  +06h Reserved byte: Table 7-14 DWORD bits 21:16 RsvdP, 23:22 undefined
       ("defined in previous specifications"; Linux pci_regs.h still names
       them PPB_B2_B3 and BPCC_ENABLE, the old bridge extensions)
  +07h Data (8 bits, optional, 7.5.2.3 Table 7-15)

A frame note: the spec numbers Table 7-13 as one 32-bit register at offset
00h whose low 16 bits are the ID and next pointer, so the spec's bit 16 is
PMC bit 0 at +02h. This module reads the 16-bit PMC at +02h and uses the
16-bit bit numbers; each field comment gives the spec's DWORD bit too. The
same holds for PMCSR: Table 7-14 is a DWORD at 04h whose bits 15:0 are the
16-bit PMCSR, so those numbers need no shift.
"""

from dataclasses import dataclass

from .header import bit, bits
from .parse import ConfigSpace

STRUCTURE_LENGTH = 8  # 7.5.2 Figure 7-17: +00h through +07h

# PMC bits 8:6 Aux_Current (spec Table 7-13 bits 24:22): Vaux current the Function needs.
AUX_CURRENT_MA = {0: 0, 1: 55, 2: 100, 3: 160, 4: 220, 5: 270, 6: 320, 7: 375}

# PMCSR bits 1:0 PowerState (7.5.2.2 Table 7-14).
POWER_STATES = {0: "D0", 1: "D1", 2: "D2", 3: "D3hot"}

# PMC bits 15:11 PME_Support (spec bits 31:27): one bit per power state, lowest bit = D0.
PME_STATES = ["D0", "D1", "D2", "D3hot", "D3cold"]

# Data_Select (PMCSR bits 12:9) and Data_Scale (bits 14:13): positions from Table 7-14
# (7.5.2.2); the meaning of each value from Table 7-16 (7.5.2.3, Power Consumption /
# Dissipation Reporting). Data_Select 9-15 are Reserved there, and for them Data_Scale
# is "Reserved / TBD".
DATA_SELECT = {
    0: "D0 power consumed", 1: "D1 power consumed", 2: "D2 power consumed", 3: "D3 power consumed",
    4: "D0 power dissipated", 5: "D1 power dissipated", 6: "D2 power dissipated", 7: "D3 power dissipated",
    8: "common logic power consumption (multi-function device, Function 0 only)",
}
DATA_SCALE = {0: "unknown", 1: "0.1x", 2: "0.01x", 3: "0.001x"}


@dataclass
class PowerManagement:
    offset: int  # absolute offset of the capability's first byte
    pmc: int  # +02h, raw 16 bits
    version: int  # PMC 2:0 (spec 18:16): must be 011b = 3 for this spec
    pme_clock: bool  # PMC 3 (spec 19): legacy, hardwired 0 on PCIe
    # PMC 4 (spec 20), Immediate_Readiness_on_Return_to_D0: ready right after entering D0.
    # A different bit from the header's Status bit 0 "Immediate Readiness" (7.5.1.1.4), which
    # is about readiness after a reset. pci_regs.h still names this mask PCI_PM_CAP_RESERVED;
    # PCIe 5.0 Table 7-13 defines it. lspci does not print it.
    immediate_readiness: bool
    dsi: bool  # PMC 5 (spec 21): Device Specific Initialization needed after D0uninitialized
    aux_current_code: int  # PMC 8:6 (spec 24:22)
    d1_support: bool  # PMC 9 (spec 25)
    d2_support: bool  # PMC 10 (spec 26)
    pme_support: int  # PMC 15:11 (spec 31:27), raw 5-bit field
    pmcsr: int  # +04h, raw 16 bits
    power_state: int  # PMCSR 1:0
    no_soft_reset: bool  # PMCSR 3: D3hot -> D0 keeps the Function's state
    pme_enable: bool  # PMCSR 8
    data_select: int  # PMCSR 12:9
    data_scale: int  # PMCSR 14:13
    pme_status: bool  # PMCSR 15, RW1CS: a PME is pending
    reserved_byte: int  # +06h raw: Table 7-14 DWORD bits 21:16 RsvdP (byte 5:0), 23:22 undefined (byte 7:6)
    data: int  # +07h, optional Data register, 00h when not implemented

    @property
    def aux_current_ma(self) -> int:
        return AUX_CURRENT_MA[self.aux_current_code]

    @property
    def power_state_name(self) -> str:
        return POWER_STATES[self.power_state]

    @property
    def pme_states(self) -> list[str]:
        """The states the Function can raise PME from: PME_Support bit n set -> PME_STATES[n].

        enumerate() hands out (0, "D0"), (1, "D1"), ... so n is the bit to test for each name.
        """
        return [name for n, name in enumerate(PME_STATES) if bit(self.pme_support, n)]

    @property
    def data_select_name(self) -> str:
        # .get with a default: codes 9-15 are Reserved in Table 7-16
        return DATA_SELECT.get(self.data_select, "reserved")

    @property
    def data_scale_name(self) -> str:
        if self.data_select > 8:
            return "reserved/TBD"  # Table 7-16: no scale is defined for a reserved selection
        return DATA_SCALE[self.data_scale]

    @property
    def data_register_present(self) -> bool:
        """7.5.2.3: an unimplemented Data register reads 00h with Data_Select and Data_Scale
        hardwired to 0; any non-zero value among the three means something is there."""
        return bool(self.data or self.data_select or self.data_scale)


def decode_pmc(value: int) -> dict:
    """Spec 7.5.2.1, Power Management Capabilities (PMC), capability offset 02h, Table 7-13.

    Table 7-13 numbers a 32-bit register at offset 00h; the PMC proper is its
    bits 31:16, read here as a 16-bit value at +02h (spec bit n = PMC bit n-16).
    """
    return {
        "version": bits(value, 2, 0),
        "pme_clock": bit(value, 3),
        "immediate_readiness": bit(value, 4),
        "dsi": bit(value, 5),
        "aux_current_code": bits(value, 8, 6),
        "d1_support": bit(value, 9),
        "d2_support": bit(value, 10),
        "pme_support": bits(value, 15, 11),
    }


def decode_pmcsr(value: int) -> dict:
    """Spec 7.5.2.2, Power Management Control/Status (PMCSR), capability offset 04h, Table 7-14."""
    return {
        "power_state": bits(value, 1, 0),
        "no_soft_reset": bit(value, 3),
        "pme_enable": bit(value, 8),
        "data_select": bits(value, 12, 9),
        "data_scale": bits(value, 14, 13),
        "pme_status": bit(value, 15),
    }


def decode_power_management(cs: ConfigSpace, offset: int) -> PowerManagement:
    """Spec 7.5.2, the whole 8-byte structure at absolute `offset` (the chain entry's start)."""
    pmc = cs.u16(offset + 0x02)
    pmcsr = cs.u16(offset + 0x04)
    return PowerManagement(
        offset=offset,
        pmc=pmc,
        **decode_pmc(pmc),  # ** spreads the dict as keyword arguments, as in header.py
        pmcsr=pmcsr,
        **decode_pmcsr(pmcsr),
        reserved_byte=cs.u8(offset + 0x06),
        data=cs.u8(offset + 0x07),
    )
