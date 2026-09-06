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

1. RW-Everything (rweverything.com), the recommended path. It installs a signed
   driver and keeps Memory Integrity, Secure Boot and signature enforcement on;
   nothing is test-signed. Two ways to use it:
     - `pcicfg dump <BDF>` drives its command-line build (Rw.exe) for you, when
       it is installed and you run the terminal as Administrator.
     - Or open the GUI, pick the device in PCI view, and use its per-device Save
       to write a .bin; then `pcicfg decode <file>`. A PCIe device saves the
       full 4096 bytes.

2. An Ubuntu live USB on the same machine, no install, no Windows changes:
       sudo lspci -vvv -xxxx -s 01:00.0 > rtx3060ti_01-00.0.txt
       sudo cat /sys/bus/pci/devices/0000:01:00.0/config > 01-00.0.config
   The first is what the fixtures in this repo are; the second is the raw
   4096-byte ECAM frame. Copy either to Windows and decode it there.

Deliberately not used, and why: enabling Windows kernel-debug mode (bcdedit
/debug on) lets Microsoft's own signed kldbgdrv.sys read config space, but it
is a boot-level security change and needs a reboot. Drivers like WinRing0,
InpOut32 and the ASUS AsIO family can do it too, but they are on Microsoft's
vulnerable-driver blocklist and are refused while Memory Integrity is on. Test
signing and a self-signed driver are off the table by design.

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


# --- reading the bytes through RW-Everything's command-line build --------------------------
#
# RW-Everything (rweverything.com) ships a signed driver, RwDrv.sys, and a command-line
# program, Rw.exe, that drives it. It is the one route that returns the full 4096-byte ECAM
# frame while Memory Integrity, Secure Boot and driver-signature enforcement all stay on and
# nothing is test-signed: a person installs a signed, purpose-built tool and runs it elevated.
# This is not bringing your own vulnerable driver; it is using RW-Everything for exactly what
# it is for. If Rw.exe is on the machine, `pcicfg dump` drives it; if not, it says how to get it.
#
# Not live-tested here (RW-Everything is not installed on the development machine), so the read
# fails loudly and falls back to the report rather than ever returning bytes it is unsure of.

RW_EXE_NAMES = ("Rw.exe", "Rw64.exe")
RW_SEARCH_DIRS = (
    r"C:\Program Files\RW-Everything",
    r"C:\Program Files (x86)\RW-Everything",
)
# One RPCIE32 read per DWORD: RPCIE32 <bus> <dev> <func> <offset> reads a 32-bit value from
# PCI Express (ECAM) configuration space, so it reaches the whole 4096-byte frame (RW-Everything
# also has RPCI32 for the legacy CF8/CFC path, which stops at 256 bytes).
RW_READ_COMMAND = "RPCIE32"


def find_rw_everything(extra: str | None = None) -> str | None:
    """The path to Rw.exe if it is installed or on PATH, else None."""
    import shutil

    candidates = []
    if extra:
        candidates.append(extra)
    for d in RW_SEARCH_DIRS:
        candidates += [os.path.join(d, name) for name in RW_EXE_NAMES]
    for path in candidates:
        if os.path.isfile(path):
            return path
    for name in RW_EXE_NAMES:  # or anywhere on PATH
        found = shutil.which(name)
        if found:
            return found
    return None


def parse_rw_dwords(text: str) -> list[int]:
    """The 32-bit values RW-Everything printed, in order.

    Rw.exe prints each read result as '... = 0xXXXXXXXX'. Matching the token
    after '=' ignores the address/bus/dev/offset it echoes on the same line,
    which are also hexadecimal. Order is the order the reads were issued.
    """
    import re

    return [int(m, 16) for m in re.findall(r"=\s*0x([0-9A-Fa-f]{1,8})", text)]


def read_via_rw_everything(bus: int, device: int, function: int, size: int, rw_path: str) -> bytes:
    """Read `size` bytes of one Function's configuration space with RW-Everything's Rw.exe.

    One RPCIE32 read per DWORD, issued through a single Rw.exe invocation, then
    assembled little-endian (each DWORD sits in memory low byte first, exactly
    as the decoder expects). Raises if Rw.exe is missing, fails, or returns the
    wrong number of values, so a partial or misread dump is never passed on as
    if it were real.
    """
    import subprocess

    if size % 4:
        raise ValueError(f"size {size} is not a whole number of DWORDs")
    commands = ";".join(f"{RW_READ_COMMAND} 0x{bus:X} 0x{device:X} 0x{function:X} 0x{off:X}"
                        for off in range(0, size, 4))
    result = subprocess.run(
        [rw_path, "/Nologo", "/Stdout", f"/Command={commands}"],
        capture_output=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Rw.exe failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace').strip()}")
    dwords = parse_rw_dwords(result.stdout.decode("utf-8", "replace"))
    if len(dwords) != size // 4:
        raise RuntimeError(f"Rw.exe returned {len(dwords)} values, expected {size // 4}; the command form may differ on this RW-Everything version")
    return b"".join(d.to_bytes(4, "little") for d in dwords)


@dataclass
class DumpResult:
    """The outcome of trying to read bytes: the bytes and how, or None and why not."""
    data: bytes | None
    method: str = ""  # how the bytes were read, when they were
    reason: str = ""  # why not, when they were not


def dump_config_space(bdf: str, size: int = 4096, rw_path: str | None = None) -> DumpResult:
    """Try to read one Function's configuration space with a signed driver already present.

    Today that means RW-Everything's Rw.exe. Elevation is required for the read
    (the driver's device object is opened by an elevated process); Rw.exe itself
    will report that if this process is not elevated. Returns the bytes and the
    method, or None and the reason, so the caller can decode or explain.
    """
    bus, device, function = parse_bdf(bdf)
    rw = find_rw_everything(rw_path)
    if rw is None:
        return DumpResult(None, reason="RW-Everything (Rw.exe) is not installed; it is the signed tool that reads the bytes")
    try:
        data = read_via_rw_everything(bus, device, function, size, rw)
    except (RuntimeError, ValueError, OSError) as e:
        return DumpResult(None, reason=str(e))
    return DumpResult(data, method=f"RW-Everything ({rw})")


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
    lines += [
        "",
        f"Blocked by: {status.blocker}.",
        "",
        "Why a driver at all: reading configuration space means either port I/O to CF8h/CFCh",
        "(spec 7.2.1, 256 bytes per Function) or mapping the ECAM window in physical memory",
        "(spec 7.2.2, the full 4096 bytes). Both are ring 0, so a signed driver has to do it.",
        "PawnIO is signed and loads here, but its release build runs only modules its author",
        "signed, and none of those reads generic configuration space; a self-signed module needs",
        "the test-signed build, which this project will not enable.",
        "",
        ALTERNATIVES,
    ]
    return "\n".join(lines)
