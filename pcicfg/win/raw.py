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

ALTERNATIVES = """Ways to get the bytes, best first (verified against Microsoft's docs and
driver-blocklist, and against each tool's own source):

1. An Ubuntu live USB on the same machine. No install, no Windows changes, and
   it works whatever this machine's security settings are:
       sudo lspci -vvv -xxxx -s 01:00.0 > rtx3060ti_01-00.0.txt
       sudo cat /sys/bus/pci/devices/0000:01:00.0/config > 01-00.0.config
   The first is what the fixtures in this repo are; the second is the raw
   4096-byte ECAM frame. Copy either to Windows and `pcicfg decode <file>`.

2. RW-Everything (rweverything.com), only on a machine with Memory Integrity
   off. Its driver RwDrv.sys is on Microsoft's vulnerable-driver blocklist, so
   with Memory Integrity on it is refused at load and neither its GUI nor its
   command line reads a byte. Where it does load, save the device from its PCI
   view and `pcicfg decode <file>`; a PCIe device saves the full 4096 bytes.

Also possible, and why not here: Windows kernel-debug mode (bcdedit /debug on)
lets Microsoft's own signed kldbgdrv.sys read config space with no third-party
driver and Memory Integrity left on, but it is a boot-level change that needs a
reboot. A driver you write yourself and get attestation-signed by Microsoft
loads with Memory Integrity on, but signing needs a registered organization and
an EV certificate (money and weeks). Test signing and loading an unsigned or
blocklisted driver are off the table by design.

For link speed, width, payload sizes and the AER masks with no dump and no
driver at all, `pcicfg list` reads what Windows already knows (see
pcicfg/win/enum.py)."""


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


@dataclass
class EcamRegion:
    """One MCFG allocation: an ECAM window for a range of buses in one segment (spec 7.2.2)."""
    base: int  # physical base address of the window
    segment: int  # PCI segment (domain) number
    start_bus: int
    end_bus: int

    def covers(self, bus: int, segment: int = 0) -> bool:
        return segment == self.segment and self.start_bus <= bus <= self.end_bus

    def physical_address(self, bus: int, device: int, function: int, offset: int = 0) -> int:
        return ecam_address(self.base, bus - self.start_bus, device, function, offset)


def read_ecam_regions() -> list[EcamRegion]:
    """Where every Function's 4096-byte ECAM frame lives in physical memory.

    The firmware publishes the base of each ECAM window in the ACPI MCFG table,
    and `GetSystemFirmwareTable` hands that table to user mode with no
    privilege (it does not read the window itself, only the table that says
    where it is). So a normal process can work out the exact physical address
    of any Function's configuration space. It still cannot read that address:
    mapping physical memory is ring 0. Knowing where the bytes are is not
    reading them, which is the whole reason Layer 3 needs a driver.

    Empty when the table is absent (a pre-ECAM machine, or not Windows).
    """
    if sys.platform != "win32":
        return []
    import struct

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetSystemFirmwareTable.restype = wintypes.UINT
    k.GetSystemFirmwareTable.argtypes = [wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    acpi = int.from_bytes(b"ACPI", "big")  # provider signature, as the FOURCC MSVC would form
    table_id = int.from_bytes(b"MCFG", "little")  # the table's own signature, little-endian DWORD
    size = k.GetSystemFirmwareTable(acpi, table_id, None, 0)
    if not size:
        return []
    buf = (ctypes.c_ubyte * size)()
    got = k.GetSystemFirmwareTable(acpi, table_id, buf, size)
    data = bytes(buf[:got])
    # MCFG: a 36-byte ACPI header, 8 reserved bytes, then 16-byte allocation records
    # (base u64, segment u16, start-bus u8, end-bus u8, 4 reserved).
    regions = []
    for off in range(44, len(data) - 15, 16):
        base, segment, start_bus, end_bus = struct.unpack_from("<QHBB", data, off)
        regions.append(EcamRegion(base=base, segment=segment, start_bus=start_bus, end_bus=end_bus))
    return regions


def ecam_region_for(bus: int, segment: int = 0, regions: list[EcamRegion] | None = None) -> EcamRegion | None:
    """The ECAM window that covers this bus, or None when the table names none."""
    for region in read_ecam_regions() if regions is None else regions:
        if region.covers(bus, segment):
            return region
    return None


# --- can a raw read even happen on this machine? -------------------------------------------
#
# RW-Everything (rweverything.com) is the tool people reach for: it reads the full config
# space through its own kernel driver, RwDrv.sys. Two facts, both verified on this machine,
# decide whether it can work here at all, and this section checks them so `pcicfg dump` can
# say precisely what is true rather than guess:
#
#  1. RwDrv.sys is on Microsoft's vulnerable-driver blocklist (its file rule is in the
#     enforced policy, FileName="RwDrv.sys"). While Memory Integrity (HVCI) is on, a
#     blocklisted driver is refused at load. So on a machine with Memory Integrity on,
#     RW-Everything's driver does not load, and neither its GUI nor its command line can read
#     a byte. It works only where Memory Integrity is off.
#  2. RW-Everything's binaries are not Authenticode-signed (the portable Rw.exe and the
#     installer both read "NotSigned"); the driver is the signed part, and that is the part
#     the blocklist stops.
#
# So this tool does not drive RW-Everything: on a locked-down machine it would fail at the
# driver load, and this project keeps Memory Integrity on. `pcicfg dump` instead reports the
# machine's state and the routes that actually fit it. The reliable way to feed the decoder
# on Windows is `pcicfg decode <file>` on a dump saved where a driver can run (RW-Everything
# on a machine with Memory Integrity off, or a Linux live USB); the Windows-native, no-driver
# facts are in `pcicfg list`.

RW_EXE_NAMES = ("Rw.exe", "Rw64.exe")
RW_SEARCH_DIRS = (
    r"C:\Program Files\RW-Everything",
    r"C:\Program Files (x86)\RW-Everything",
)
DRIVER_POLICY = r"C:\Windows\System32\CodeIntegrity\driversipolicy.p7b"


def find_rw_everything(extra: str | None = None) -> str | None:
    """The path to RW-Everything's Rw.exe if it is installed or on PATH, else None."""
    import shutil

    candidates = list(filter(None, [extra]))
    for d in RW_SEARCH_DIRS:
        candidates += [os.path.join(d, name) for name in RW_EXE_NAMES]
    for path in candidates:
        if os.path.isfile(path):
            return path
    for name in RW_EXE_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def memory_integrity_enabled() -> bool | None:
    """Is HVCI / Memory Integrity running? None when it cannot be read (or not Windows).

    A blocklisted driver such as RwDrv.sys will not load while this is on.
    """
    if sys.platform != "win32":
        return None
    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")
        value, _ = winreg.QueryValueEx(key, "Enabled")
        return bool(value)
    except (OSError, ImportError):
        return None


def driver_blocklisted(driver_name: str = "RwDrv", policy_path: str = DRIVER_POLICY) -> bool | None:
    """Is a driver named in the machine's active vulnerable-driver blocklist?

    The enforced policy at driversipolicy.p7b names blocked drivers as text
    inside the signed blob; a substring test is enough to see whether one is
    listed. None when the policy file cannot be read.
    """
    if sys.platform != "win32":
        return None
    try:
        blob = open(policy_path, "rb").read()
    except OSError:
        return None
    needle = driver_name.lower().encode()
    return needle in blob.lower() or needle in blob.decode("utf-16-le", "ignore").lower().encode()


@dataclass
class DumpResult:
    """The outcome of trying to read bytes: the bytes and how, or None and why not."""
    data: bytes | None
    method: str = ""  # how the bytes were read, when they were
    reason: str = ""  # why not, when they were not


def dump_config_space(bdf: str, size: int = 4096) -> DumpResult:
    """Try to read one Function's configuration space with a driver that works on this machine.

    On a machine with Memory Integrity on there is none: the third-party
    drivers that read config space (RW-Everything's RwDrv.sys and its kin) are
    on the vulnerable-driver blocklist and are refused at load, and this
    project does not turn Memory Integrity off. So this returns None with the
    exact reason, and `pcicfg dump` prints the routes that do fit. It stays a
    function, not a hard-coded "no", so a machine where Memory Integrity is off
    and RW-Everything loads is handled by decoding its saved dump instead.
    """
    parse_bdf(bdf)  # validate the address; raises ValueError on a bad one
    if memory_integrity_enabled() and driver_blocklisted("RwDrv"):
        return DumpResult(None, reason="RwDrv.sys (RW-Everything) is on the active vulnerable-driver blocklist and Memory Integrity is on, so it cannot load here")
    if find_rw_everything() is None:
        return DumpResult(None, reason="no driver that can read config space is usable here; see the routes below")
    return DumpResult(None, reason="RW-Everything is installed; save the device from its GUI and run `pcicfg decode <file>`")


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
    # Show the exact physical address of these bytes, computed from the ACPI MCFG table with no
    # privilege. It proves the tool knows where the bytes are; it still cannot read them.
    try:
        bus, device, function = parse_bdf(bdf)
        region = ecam_region_for(bus)
    except (ValueError, OSError):
        region = None
    if region is not None:
        addr = region.physical_address(bus, device, function)
        lines.append(f"  ECAM address    physical 0x{addr:X} (from the ACPI MCFG table; reading it needs ring 0)")
    # The two facts that decide whether any third-party config-space driver can load here.
    mi = memory_integrity_enabled()
    blocked = driver_blocklisted("RwDrv")
    if mi is not None:
        lines.append(f"  Memory Integrity {'on (HVCI): a blocklisted driver will not load' if mi else 'off: a blocklisted driver could load'}")
    if blocked is not None:
        lines.append(f"  RwDrv.sys        {'on the active vulnerable-driver blocklist' if blocked else 'not on the active blocklist'} (RW-Everything)")
    lines += [
        "",
        f"Blocked by: {status.blocker}.",
        "",
        "Why a driver at all: reading configuration space means either port I/O to CF8h/CFCh",
        "(spec 7.2.1, 256 bytes per Function) or mapping the ECAM window in physical memory",
        "(spec 7.2.2, the full 4096 bytes). Both are ring 0, so a driver has to do it. The",
        "third-party drivers that would (RW-Everything's RwDrv.sys and its kin) are on Microsoft's",
        "vulnerable-driver blocklist and are refused while Memory Integrity is on; PawnIO loads but",
        "runs only modules its author signed, none of which reads generic config space. A driver",
        "you write and get signed, or Microsoft's own debug driver via a reboot, would work; both",
        "are described below.",
        "",
        ALTERNATIVES,
    ]
    return "\n".join(lines)
