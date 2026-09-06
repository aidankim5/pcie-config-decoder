"""Layer 3: raw configuration-space reads on Windows, through a signed kernel driver.

Windows gives user mode no way to read a device's configuration space byte for
byte. The two hardware paths both need kernel privilege:

- The PCI-compatible path (spec 7.2.1): write the address to I/O port CF8h,
  read the data from CFCh. Port I/O is ring 0 only, and the address register
  has 8 bits of register number, so this path reaches 256 bytes per Function.
- The ECAM path (spec 7.2.2): the firmware maps every Function's 4096 bytes
  into physical memory, and the address is a plain calculation from the
  segment's base plus (bus << 20) + (device << 15) + (function << 12).
  Mapping physical memory is also ring 0 only. This is the path that reaches
  the extended capabilities at 100h and up, which is why `pcicfg decode` wants
  a 4096-byte dump.

So a driver has to do it. The rule for this project is that no unsigned driver
is loaded, test signing stays off and Memory Integrity stays on, so the only
candidate is a driver Microsoft already signed. PawnIO (github.com/namazso/PawnIO)
is one: a signed kernel driver that runs small signed Pawn modules and exposes
natives to them, `pci_config_read_dword(bus, device, function, offset, out)`
among them. That native is exactly what this file wants.

What the spike found on this machine, and why `pcicfg dump` does not read bytes:

1. PawnIO 2.2.0.0 is installed and its service is running, and PawnIOLib.dll
   loads and answers pawnio_version without any privilege.
2. pawnio_open returns 0x80070005, ERROR_ACCESS_DENIED, from a normal user
   process. The driver's device object is only openable by an elevated one.
3. Even elevated, there is nothing to load. A PawnIO module is a compiled Pawn
   program signed with a key the driver trusts, and the official release
   modules are all device-specific (SMBus controllers, MSRs, LPC, embedded
   controllers); none exposes a generic configuration-space read. Writing one
   is a small job, but the driver build that accepts a self-signed module is
   the "unrestricted" one, which is test signed, and enabling test signing is
   exactly what this project will not do.

That is a real answer, not a missing feature: the byte-level read needs either
a signed module from the driver's author or a machine where test signing is
acceptable. Both alternatives below get the same bytes today.
"""

import ctypes
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass

PAWNIO_DLL = r"C:\Program Files\PawnIO\PawnIOLib.dll"

# The two frames a dump can have, and what reaches them (see the module docstring).
FRAME_BY_PATH = {
    "CF8/CFC": 256,  # spec 7.2.1, the PCI-compatible configuration mechanism
    "ECAM": 4096,  # spec 7.2.2, Enhanced Configuration Access Mechanism
}

ALTERNATIVES = """Two ways to get the same bytes today:

1. RW-Everything (rweverything.com), a signed Windows tool with its own signed
   driver. Open it, pick the device in PCI view, and use its per-device save to
   write a .bin or a text dump. `pcicfg decode <file>` reads either: a raw
   256- or 4096-byte image, or lspci-style hex rows.

2. An Ubuntu live USB on the same machine, which needs no install:
       sudo lspci -vvv -xxxx -s 01:00.0 > rtx3060ti_01-00.0.txt
       sudo cat /sys/bus/pci/devices/0000:01:00.0/config > 01-00.0.config
   The first is what the fixtures in this repo are. The second is the raw
   4096-byte ECAM frame. Copy either to Windows and decode it there.

For link speed, width, payload sizes and the AER masks without any dump at all,
`pcicfg list` reads what Windows already knows (see pcicfg/win/enum.py)."""


@dataclass
class PawnIoStatus:
    """What the spike found when it asked the driver, in the order it asked."""
    dll_present: bool
    dll_error: str = ""
    version: str = ""
    opened: bool = False
    open_hresult: int | None = None
    open_meaning: str = ""
    elevated: bool = False

    @property
    def blocker(self) -> str:
        """The first thing that stopped a raw read, in one line."""
        if not self.dll_present:
            return f"PawnIOLib.dll is not loadable ({self.dll_error}); install the official signed release from github.com/namazso/PawnIO"
        if not self.opened:
            hr = f"0x{self.open_hresult & 0xFFFFFFFF:08X}" if self.open_hresult is not None else "?"
            if not self.elevated:
                return f"pawnio_open returned {hr} ({self.open_meaning}); this process is not elevated, and the driver's device object needs an elevated one"
            return f"pawnio_open returned {hr} ({self.open_meaning})"
        return ("PawnIO opened, but no module is loaded that exposes pci_config_read_dword: the official release "
                "modules are device-specific, and the driver build that accepts a self-signed module is test signed")


def hresult_meaning(hr: int) -> str:
    """The Win32 message behind an HRESULT of the form 0x8007xxxx (FACILITY_WIN32)."""
    code = hr & 0xFFFF
    try:
        return ctypes.FormatError(code).strip().rstrip(".")
    except (ValueError, OSError):
        return f"Win32 error {code}"


def is_elevated() -> bool:
    """True when this process runs with the Administrators group enabled."""
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def probe_pawnio(dll_path: str = PAWNIO_DLL) -> PawnIoStatus:
    """Ask PawnIO, in order: does the library load, what version, will it open.

    Nothing here changes any state: pawnio_version reads a number, pawnio_open
    asks for a handle to the driver's device object and the handle is closed
    again at once. No module is loaded and no hardware is touched.
    """
    if sys.platform != "win32":
        return PawnIoStatus(dll_present=False, dll_error=f"PawnIO is a Windows driver; this is {sys.platform}")
    try:
        lib = ctypes.WinDLL(dll_path)
    except OSError as e:
        return PawnIoStatus(dll_present=False, dll_error=str(e))

    status = PawnIoStatus(dll_present=True, elevated=is_elevated())
    version = ctypes.c_ulong()
    if lib.pawnio_version(ctypes.byref(version)) == 0:
        v = version.value  # (major << 16) | (minor << 8) | patch, per PawnIOLib.h
        status.version = f"{(v >> 16) & 0xFFFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"

    handle = wintypes.HANDLE()
    hr = lib.pawnio_open(ctypes.byref(handle))
    status.open_hresult = hr
    if hr == 0:
        status.opened = True
        lib.pawnio_close(handle)
    else:
        status.open_meaning = hresult_meaning(hr)
    return status


def parse_bdf(text: str) -> tuple[int, int, int]:
    """'01:00.0' or '0000:01:00.0' -> (bus, device, function).

    A domain (segment) is accepted and must be 0000: one CF8/CFC address space
    and one ECAM base per segment, and this tool only ever reads segment 0.
    """
    parts = text.strip().split(":")
    if len(parts) == 3:
        domain, parts = parts[0], parts[1:]
        if int(domain, 16) != 0:
            raise ValueError(f"{text}: only segment 0000 is supported")
    elif len(parts) != 2:
        raise ValueError(f"{text}: expected bus:device.function, e.g. 01:00.0")
    bus_text, rest = parts
    if "." not in rest:
        raise ValueError(f"{text}: expected bus:device.function, e.g. 01:00.0")
    device_text, function_text = rest.split(".", 1)
    bus, device, function = int(bus_text, 16), int(device_text, 16), int(function_text, 16)
    if not (0 <= bus <= 0xFF and 0 <= device <= 0x1F and 0 <= function <= 7):
        raise ValueError(f"{text}: bus 00-ff, device 00-1f, function 0-7")
    return bus, device, function


def cf8_address(bus: int, device: int, function: int, offset: int) -> int:
    """The value to write to port CF8h for one DWORD (spec 7.2.1, Figure 7-1).

    Bit 31 Enable, bits 23:16 bus, 15:11 device, 10:8 function, 7:2 register
    number, 1:0 always 00b because the data port returns a whole DWORD. Six
    bits of register number is why this path stops at 256 bytes.
    """
    if offset >= 256:
        raise ValueError(f"offset {offset:X}h is past the 256-byte PCI-compatible frame; that needs ECAM (7.2.2)")
    return 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC)


def ecam_address(base: int, bus: int, device: int, function: int, offset: int = 0) -> int:
    """The physical address of a Function's configuration space under ECAM (spec 7.2.2).

    base + (bus << 20) + (device << 15) + (function << 12) + offset: 12 bits of
    offset is the whole 4096-byte frame, which is what makes the extended
    capabilities at 100h and up reachable.
    """
    if not (0 <= offset < 4096):
        raise ValueError(f"offset {offset:X}h is outside the 4096-byte ECAM frame")
    return base + (bus << 20) + (device << 15) + (function << 12) + offset


def report(status: PawnIoStatus, bdf: str) -> str:
    """What `pcicfg dump` prints instead of bytes: what was tried, what stopped it, what else to do."""
    lines = [
        f"pcicfg dump {bdf}: no bytes read.",
        "",
        "What this tool tried, and what it found:",
    ]
    if status.dll_present:
        lines.append(f"  PawnIOLib.dll   loaded from {PAWNIO_DLL}" + (f", driver library version {status.version}" if status.version else ""))
    else:
        lines.append(f"  PawnIOLib.dll   not loadable: {status.dll_error}")
    if status.dll_present:
        hr = f"0x{status.open_hresult & 0xFFFFFFFF:08X}" if status.open_hresult is not None else "?"
        opened = "opened" if status.opened else f"failed, {hr} ({status.open_meaning})"
        lines.append(f"  pawnio_open     {opened}")
        lines.append(f"  this process    {'elevated' if status.elevated else 'not elevated (run the terminal as Administrator to change this)'}")
    lines += [
        "",
        f"Blocked by: {status.blocker}.",
        "",
        "Why a driver at all: reading configuration space means either port I/O to CF8h/CFCh",
        "(spec 7.2.1, 256 bytes per Function) or mapping the ECAM window in physical memory",
        "(spec 7.2.2, the full 4096 bytes). Both are ring 0. This project does not enable test",
        "signing, does not turn off Memory Integrity and does not load an unsigned driver, so a",
        "signed driver with a signed module is the only route, and no official PawnIO module",
        "exposes a generic configuration-space read.",
        "",
        ALTERNATIVES,
    ]
    return "\n".join(lines)
