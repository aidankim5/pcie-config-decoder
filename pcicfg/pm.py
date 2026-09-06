"""Power Management capability, ID 01h (spec 7.5.2), 8 bytes.

[Ahead] Aidan has not decoded these registers by hand yet; the chain entry
is taught, the register contents are not. Every bit below comes from the
spec's own tables, read twice independently.

Layout (7.5.2, Figure 7-17), offsets relative to the capability's start:
  +00h Capability ID (01h)        +01h Next Capability Pointer
  +02h PMC, Power Management Capabilities (16 bits, 7.5.2.1 Table 7-13)
  +04h PMCSR, Power Management Control/Status (16 bits, 7.5.2.2 Table 7-14)
  +06h Reserved byte (bits 5:0 RsvdP, bits 7:6 undefined, once bridge extensions)
  +07h Data (8 bits, optional, 7.5.2.3 Table 7-15)

A frame note: the spec numbers Table 7-13 as one 32-bit register at offset
00h whose low 16 bits are the ID and next pointer, so the spec's bit 16 is
PMC bit 0 at +02h. This module reads the 16-bit PMC at +02h and uses the
16-bit bit numbers; each field comment gives the spec's DWORD bit too.
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

# PMCSR bits 12:9 Data_Select and 14:13 Data_Scale (Table 7-14), for the optional Data register.
DATA_SELECT = {
    0: "D0 power consumed", 1: "D1 power consumed", 2: "D2 power consumed", 3: "D3 power consumed",
    4: "D0 power dissipated", 5: "D1 power dissipated", 6: "D2 power dissipated", 7: "D3 power dissipated",
    8: "common logic power (multi-function devices)",
}
DATA_SCALE = {0: "unknown", 1: "0.1x", 2: "0.01x", 3: "0.001x"}


@dataclass
class PowerManagement:
    offset: int  # absolute offset of the capability's first byte
    pmc: int  # +02h, raw 16 bits
    version: int  # PMC 2:0 (spec 18:16): must be 011b = 3 for this spec
    pme_clock: bool  # PMC 3 (spec 19): legacy, hardwired 0 on PCIe
    immediate_readiness: bool  # PMC 4 (spec 20): ready right after entering D0
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
    reserved_byte: int  # +06h raw (bits 5:0 RsvdP, 7:6 undefined)
    data: int  # +07h, optional Data register, 00h when not implemented

    @property
    def aux_current_ma(self) -> int:
        return AUX_CURRENT_MA[self.aux_current_code]

    @property
    def power_state_name(self) -> str:
        return POWER_STATES[self.power_state]

    @property
    def pme_states(self) -> list[str]:
        """The states the Function can raise PME from: PME_Support bit n set -> PME_STATES[n]."""
        return [name for n, name in enumerate(PME_STATES) if bit(self.pme_support, n)]

    @property
    def data_select_name(self) -> str:
        return DATA_SELECT.get(self.data_select, f"reserved ({self.data_select})")

    @property
    def data_scale_name(self) -> str:
        return DATA_SCALE[self.data_scale]


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
