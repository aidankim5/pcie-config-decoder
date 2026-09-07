"""Layer 3, the security-on path: configuration space through Microsoft's own debug driver.

`raw.py` explains why a driver is needed at all: both hardware paths to
configuration space (port CF8h/CFCh in spec 7.2.1, and the ECAM window in spec
7.2.2) are ring 0. It then rules out the third-party drivers, because RwDrv.sys
and its kin are on Microsoft's vulnerable-driver blocklist and are refused while
Memory Integrity is on. This module takes the route that is left: a driver
Microsoft signed and ships itself.

kldbgdrv.sys is the Kernel Local Debugging Driver. It is what `kd -kl` uses to
debug the running kernel from user mode, and it is the driver behind pciutils'
`win32-kldbg` access method. Three things make it the right one here:

- It is Microsoft-signed. The copy embedded in the Windows SDK's kd.exe is
  signed "CN=Microsoft Corporation, OU=MOPR" under "Microsoft Code Signing PCA"
  and verifies Valid, so it loads with Memory Integrity on and the
  vulnerable-driver blocklist enforced. Nothing is renamed, patched or
  self-signed. (Not every copy is: the one inside the Microsoft Store WinDbg
  package is signed by "Windows Internal Build Tools PCA 2020", whose root is
  not trusted on a retail machine, so that copy will not load. See
  docs/security-on-path.md.)
- It is not on the blocklist, which `driver_blocklisted("kldbgdrv")` confirms
  against this machine's own enforced policy blob.
- It is inert unless the machine was booted with kernel debugging enabled
  (`bcdedit /debug on`). That is the cost of this path, and it is a real one:
  see the tradeoff section of docs/security-on-path.md.

How the read works. The driver takes one IOCTL, IOCTL_KLDBG, whose payload is a
KLDBG structure naming a SYSDBG_COMMAND and a command-specific buffer. Two
commands matter:

- SysDbgReadBusData (18) with BusDataType = PCIConfiguration (4). The kernel
  turns this into HalGetBusDataByOffset, the HAL's own configuration-space
  read. Whether that reaches past the first 256 bytes is not documented, so
  this module measures it rather than assuming: see `read_config_space`.
- SysDbgReadPhysical (10). This reads physical memory, and the ECAM window is
  physical memory. `raw.read_ecam_regions` already works out the exact physical
  address of any Function's 4096-byte frame from the ACPI MCFG table with no
  privilege at all; this command is the ring-0 read that address was always
  missing. So when the bus-data path stops at 256 bytes, this one still reaches
  the extended capabilities at 100h and up.

Both need SeDebugPrivilege, which an elevated process has, and both need the
kernel debugger enabled at boot. `probe()` reports each of those conditions
separately so `pcicfg dump` can say exactly which one is missing.
"""

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass, field

from .raw import ecam_region_for, is_elevated, parse_bdf

# CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_NEITHER, FILE_READ_ACCESS | FILE_WRITE_ACCESS).
# CTL_CODE packs (DeviceType << 16) | (Access << 14) | (Function << 2) | Method.
IOCTL_KLDBG = (0x22 << 16) | (3 << 14) | (0x1 << 2) | 3  # 0x0022C007

# SYSDBG_COMMAND values, from the NT debug interface. Only the two reads are used here;
# the matching writes exist and are deliberately not wired up.
SYSDBG_READ_PHYSICAL = 10
SYSDBG_READ_BUS_DATA = 18

PCI_CONFIGURATION = 4  # BUS_DATA_TYPE.PCIConfiguration

KLDBG_DEVICE = r"\\.\kldbgdrv"
KLDBG_SERVICE = "kldbgdrv"

# NtQuerySystemInformation class 35, SystemKernelDebuggerInformation. Readable by a normal
# user, which is how this module reports "debug mode is off" without needing to be elevated.
SYSTEM_KERNEL_DEBUGGER_INFORMATION = 35

COMPATIBLE_FRAME = 256  # spec 7.2.1: the PCI-compatible frame, all CF8/CFC can reach
EXTENDED_FRAME = 4096  # spec 7.2.2: the full ECAM frame, where the extended chain lives


class SYSDBG_BUS_DATA(ctypes.Structure):
    """The SysDbgReadBusData payload: which Function, which offset, where to put the bytes."""

    _fields_ = [
        ("Address", wintypes.ULONG),  # offset into configuration space
        ("Buffer", ctypes.c_void_p),
        ("Request", wintypes.ULONG),  # bytes wanted
        ("BusDataType", ctypes.c_long),
        ("BusNumber", wintypes.ULONG),  # PCI_SEGMENT_BUS_NUMBER: bus 7:0, segment 23:8
        ("SlotNumber", wintypes.ULONG),  # PCI_SLOT_NUMBER: device 4:0, function 7:5
    ]


class SYSDBG_PHYSICAL(ctypes.Structure):
    """The SysDbgReadPhysical payload: a physical address and a length."""

    _fields_ = [
        ("Address", ctypes.c_ulonglong),
        ("Buffer", ctypes.c_void_p),
        ("Request", wintypes.ULONG),
    ]


class KLDBG(ctypes.Structure):
    """The IOCTL_KLDBG envelope: a SYSDBG command and its command-specific buffer."""

    _fields_ = [
        ("Command", wintypes.ULONG),
        ("Buffer", ctypes.c_void_p),
        ("BufferLength", wintypes.DWORD),
    ]


def slot_number(device: int, function: int) -> int:
    """PCI_SLOT_NUMBER: device number in bits 4:0, function number in bits 7:5."""
    return (device & 0x1F) | ((function & 0x7) << 5)


def segment_bus_number(bus: int, segment: int = 0) -> int:
    """PCI_SEGMENT_BUS_NUMBER: bus number in bits 7:0, segment number in bits 23:8."""
    return (bus & 0xFF) | ((segment & 0xFFFF) << 8)


def kernel_debugger_enabled() -> bool | None:
    """Was this machine booted with kernel debugging on? None when it cannot be asked.

    This is the `bcdedit /debug on` state as the running kernel sees it, and it
    needs no privilege, so `pcicfg dump` can tell an unelevated user that the
    reboot has not happened yet instead of failing later with a vaguer error.
    """
    if sys.platform != "win32":
        return None
    try:
        ntdll = ctypes.WinDLL("ntdll")
        buf = (ctypes.c_ubyte * 2)()  # BOOLEAN KernelDebuggerEnabled, BOOLEAN KernelDebuggerNotPresent
        length = wintypes.ULONG()
        status = ntdll.NtQuerySystemInformation(
            SYSTEM_KERNEL_DEBUGGER_INFORMATION, ctypes.byref(buf), ctypes.sizeof(buf), ctypes.byref(length)
        )
        if status != 0:
            return None
        return bool(buf[0])
    except (OSError, AttributeError):
        return None


def secure_boot_enabled() -> bool | None:
    """Is UEFI Secure Boot on? None when it cannot be read.

    This decides whether this whole path is available, so it is worth reading
    before anything else is tried. Secure Boot policy protects the BCD `debug`
    element, so on a Secure Boot machine `bcdedit /debug on` is refused outright:

        The value is protected by Secure Boot policy and cannot be modified or deleted.

    No amount of privilege gets around that; it is settled in firmware. The
    value is readable without elevation, which is what lets `pcicfg dump` say
    "this path is closed here" instead of sending someone to a command that
    cannot work.
    """
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State") as k:
            value, _ = winreg.QueryValueEx(k, "UEFISecureBootEnabled")
            return bool(value)
    except (OSError, ImportError):
        return None


def enable_debug_privilege() -> bool:
    """Turn on SeDebugPrivilege in this process's token. False when it is not held.

    An elevated process holds the privilege but does not have it enabled by
    default; the driver's IOCTL refuses the call until it is.
    """
    if sys.platform != "win32":
        return False

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED = 0x20, 0x8, 0x2

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(
        kernel.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)
    ):
        return False
    try:
        luid = LUID()
        if not advapi.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        privileges = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)))
        ctypes.set_last_error(0)
        ok = advapi.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), ctypes.sizeof(privileges), None, None)
        # AdjustTokenPrivileges reports success even when it changed nothing; the real
        # answer is ERROR_NOT_ALL_ASSIGNED (1300) in the last error.
        return bool(ok) and ctypes.get_last_error() != 1300
    finally:
        kernel.CloseHandle(token)


class KernelDebugReader:
    """An open handle to kldbgdrv.sys, with the two reads this tool needs.

    Used as a context manager so the handle is always closed:

        with KernelDebugReader() as reader:
            data = reader.read_bus_data(1, 0, 0, 0, 256)
    """

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("the Kernel Local Debugging Driver is Windows-only")
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel.CreateFileW.restype = wintypes.HANDLE
        self._kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        enable_debug_privilege()
        GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3
        handle = self._kernel.CreateFileW(KLDBG_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if handle == wintypes.HANDLE(-1).value or handle is None:
            raise ctypes.WinError(ctypes.get_last_error())
        self.handle = handle

    def __enter__(self) -> "KernelDebugReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if getattr(self, "handle", None):
            self._kernel.CloseHandle(self.handle)
            self.handle = None

    def _ioctl(self, command: int, payload: ctypes.Structure) -> bool:
        """One IOCTL_KLDBG. The payload is both the inner command buffer and the output buffer.

        The IOCTL is METHOD_NEITHER, so the driver receives the pointers as
        given and fills the caller's buffer directly; that is why the same
        structure is passed on both sides, exactly as pciutils does it.
        """
        envelope = KLDBG(Command=command, Buffer=ctypes.addressof(payload), BufferLength=ctypes.sizeof(payload))
        returned = wintypes.DWORD()
        ok = self._kernel.DeviceIoControl(
            wintypes.HANDLE(self.handle), wintypes.DWORD(IOCTL_KLDBG),
            ctypes.byref(envelope), ctypes.sizeof(envelope),
            ctypes.byref(payload), ctypes.sizeof(payload),
            ctypes.byref(returned), None,
        )
        return bool(ok)

    def read_bus_data(self, bus: int, device: int, function: int, offset: int, length: int) -> bytes | None:
        """Configuration space through HalGetBusDataByOffset. None when the kernel refuses.

        A refusal is the answer, not an error: it is how the extent of this
        path gets measured in `read_config_space`.
        """
        buf = (ctypes.c_ubyte * length)()
        payload = SYSDBG_BUS_DATA(
            Address=offset, Buffer=ctypes.cast(buf, ctypes.c_void_p), Request=length,
            BusDataType=PCI_CONFIGURATION, BusNumber=segment_bus_number(bus), SlotNumber=slot_number(device, function),
        )
        if not self._ioctl(SYSDBG_READ_BUS_DATA, payload):
            return None
        # The kernel reports how much it actually read back in Request.
        if payload.Request != length:
            return None
        return bytes(buf)

    def read_physical(self, address: int, length: int) -> bytes | None:
        """Physical memory, which is how the ECAM window is reached. None when refused."""
        buf = (ctypes.c_ubyte * length)()
        payload = SYSDBG_PHYSICAL(Address=address, Buffer=ctypes.cast(buf, ctypes.c_void_p), Request=length)
        if not self._ioctl(SYSDBG_READ_PHYSICAL, payload):
            return None
        if payload.Request != length:
            return None
        return bytes(buf)


@dataclass
class KldbgStatus:
    """Why a kldbg read can or cannot happen here, one condition per field."""

    platform_ok: bool
    debug_boot: bool | None = None  # bcdedit /debug on, as the running kernel reports it
    secure_boot: bool | None = None  # when on, the debug boot above cannot be turned on at all
    elevated: bool = False
    service_present: bool | None = None
    opened: bool = False
    open_error: str = ""

    @property
    def usable(self) -> bool:
        return self.opened

    @property
    def blocker(self) -> str:
        """The first condition that is not met, in one line, with the fix."""
        if not self.platform_ok:
            return "kldbgdrv.sys is a Windows driver; this is not Windows"
        if self.debug_boot is False:
            if self.secure_boot:
                # Measured on this machine: bcdedit refuses with "The value is protected by
                # Secure Boot policy and cannot be modified or deleted." Firmware settles it.
                return ("kernel debugging is off and Secure Boot policy protects the BCD debug element, so "
                        "`bcdedit /debug on` is refused outright; this path needs Secure Boot off, which is a "
                        "bigger weakening than the ones this project refuses (see docs/security-on-path.md)")
            return ("this machine was not booted with kernel debugging enabled; run `bcdedit /debug on` "
                    "from an elevated prompt and reboot (see docs/security-on-path.md)")
        if not self.elevated:
            return "this process is not elevated, and the driver's device object needs an elevated one"
        if self.service_present is False:
            return ("the kldbgdrv service is not installed; see docs/security-on-path.md for the two "
                    "elevated commands that install Microsoft's signed driver")
        if not self.opened:
            return f"opening {KLDBG_DEVICE} failed: {self.open_error}"
        return ""


def service_present(name: str = KLDBG_SERVICE) -> bool | None:
    """Is a kernel service of this name registered? None when the registry cannot be read."""
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{name}"):
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return None


def probe() -> KldbgStatus:
    """Ask, in order: right platform, debug boot, elevated, service, and will it open.

    Nothing here changes any state. The device handle, if one is obtained, is
    closed again at once and no read is issued.
    """
    if sys.platform != "win32":
        return KldbgStatus(platform_ok=False)
    status = KldbgStatus(
        platform_ok=True,
        debug_boot=kernel_debugger_enabled(),
        secure_boot=secure_boot_enabled(),
        elevated=is_elevated(),
        service_present=service_present(),
    )
    try:
        reader = KernelDebugReader()
    except OSError as e:
        status.open_error = str(e)
        return status
    reader.close()
    status.opened = True
    return status


@dataclass
class ConfigRead:
    """Bytes read from one Function, and the honest account of how far each path got."""

    data: bytes | None = None
    method: str = ""
    bus_data_bytes: int = 0  # how far SysDbgReadBusData reached
    physical_bytes: int = 0  # how far SysDbgReadPhysical reached, through ECAM
    ecam_address: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data) if self.data else 0

    @property
    def frame(self) -> str:
        if self.size >= EXTENDED_FRAME:
            return "the full 4096-byte extended frame (spec 7.2.2)"
        if self.size >= COMPATIBLE_FRAME:
            return "the 256-byte PCI-compatible frame only (spec 7.2.1)"
        return f"{self.size} bytes"


def _read_whole(read, size: int, chunk: int) -> tuple[bytes, int]:
    """Read `size` bytes with `read(offset, length)`, in `chunk`-sized pieces.

    Stops at the first piece the kernel refuses and returns what came before it,
    which is what makes the reach of each path measurable rather than assumed.
    """
    out = bytearray()
    for offset in range(0, size, chunk):
        piece = read(offset, min(chunk, size - offset))
        if piece is None:
            break
        out += piece
    return bytes(out), len(out)


def read_config_space(bdf: str, size: int = EXTENDED_FRAME, reader: KernelDebugReader | None = None) -> ConfigRead:
    """Read one Function's configuration space, and measure which path reached how far.

    Two paths are tried, in this order:

    1. SysDbgReadBusData, the HAL's own configuration-space read. It certainly
       covers the 256-byte PCI-compatible frame. Whether it covers the extended
       frame is undocumented, so the read simply continues past 256 and stops
       where the kernel first refuses; `bus_data_bytes` is how far it got.
    2. If that stopped short of 4096, SysDbgReadPhysical against the ECAM
       address for this Function, worked out from the ACPI MCFG table. This is
       the same 4096 bytes by the spec 7.2.2 route.

    The result carries whichever read reached further, and says which one it was.
    """
    bus, device, function = parse_bdf(bdf)
    result = ConfigRead()
    own_reader = reader is None
    if own_reader:
        reader = KernelDebugReader()
    try:
        # 1. The bus-data path. 256 bytes at a time first; on refusal, fall back to
        # dword reads so the boundary is found exactly rather than to the nearest block.
        data, got = _read_whole(
            lambda off, ln: reader.read_bus_data(bus, device, function, off, ln), size, COMPATIBLE_FRAME
        )
        if got < size:
            tail, extra = _read_whole(
                lambda off, ln: reader.read_bus_data(bus, device, function, got + off, ln), size - got, 4
            )
            data, got = data + tail, got + extra
        result.bus_data_bytes = got
        if got:
            result.data, result.method = data, "kldbgdrv SysDbgReadBusData (HalGetBusDataByOffset)"

        if got >= size:
            return result

        # 2. The ECAM path, for the extended frame the bus-data path did not reach.
        region = ecam_region_for(bus)
        if region is None:
            result.notes.append("no ACPI MCFG entry covers this bus, so there is no ECAM address to read")
            return result
        address = region.physical_address(bus, device, function)
        result.ecam_address = address
        ecam, ecam_got = _read_whole(lambda off, ln: reader.read_physical(address + off, ln), size, COMPATIBLE_FRAME)
        result.physical_bytes = ecam_got
        if ecam_got > got:
            result.data = ecam
            result.method = f"kldbgdrv SysDbgReadPhysical at ECAM 0x{address:X} (spec 7.2.2)"
        elif ecam_got:
            result.notes.append(f"the ECAM read reached {ecam_got} bytes, no further than the bus-data read")
        return result
    finally:
        if own_reader:
            reader.close()


def report(status: KldbgStatus) -> list[str]:
    """The lines `pcicfg dump` prints about this path when it could not be used."""
    lines = ["  kldbgdrv.sys    Microsoft's Kernel Local Debugging Driver (the security-on path)"]
    if status.debug_boot is not None:
        if status.debug_boot:
            lines.append("  debug boot      on")
        elif status.secure_boot:
            lines.append("  debug boot      off, and cannot be turned on: Secure Boot policy protects it")
        else:
            lines.append("  debug boot      off (bcdedit /debug on, then reboot)")
    if status.secure_boot is not None:
        lines.append(f"  Secure Boot     {'on' if status.secure_boot else 'off'}")
    lines.append(f"  this process    {'elevated' if status.elevated else 'not elevated'}")
    if status.service_present is not None:
        lines.append(f"  kldbgdrv svc    {'installed' if status.service_present else 'not installed'}")
    if status.open_error:
        lines.append(f"  device open     {status.open_error}")
    return lines
