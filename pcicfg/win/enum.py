"""Layer 2: list every PCI function Windows knows about, with no driver.

Windows keeps, for each PCI device node, a set of PnP device properties
(DEVPKEY_*); Device Manager > Details shows them. The PCI bus driver fills the
DEVPKEY_PciDevice_* ones from the same configuration-space registers this
tool decodes: current and max link speed and width come from Link Status and
Link Capabilities of the PCI Express capability (7.5.3.8, 7.5.3.6); the
payload sizes from Device Control and Device Capabilities (7.5.3.4, 7.5.3.3).
So `pcicfg list` is the Windows-native cross-check of the by-hand decode,
without touching a raw byte.

How, and why (a choice): one PowerShell process is started and prints one
JSON document with the wanted properties of every present PCI\\* device
(Get-PnpDevice, Get-PnpDeviceProperty, ConvertTo-Json); Python parses it.
That works on a stock Windows install and takes about five seconds. The
same data is reachable without a process start through ctypes into
CfgMgr32.dll (CM_Get_Device_ID_ListW with the "PCI" enumerator,
CM_Locate_DevNodeW, CM_Get_DevNode_PropertyW), which is the API PowerShell
itself calls; that is the natural next step and is not done here.

Encodings, from the Windows SDK header pciprop.h. The header is not installed
on this machine, so each value was confirmed against the running system
where a device of that kind exists (noted below); the rest are quoted from
the header as documented and were not observed:
- DEVPKEY_Device_Address: device number in bits 31:16, function in bits 15:0
  (confirmed: 00:15.2 reads 00150002h).
- DEVPKEY_PciDevice_DeviceType: 0 PCI conventional, 1 PCI-X, 2 PCI Express
  endpoint, 3 PCI Express legacy endpoint, 4 Root Complex integrated
  endpoint, 5 PCI Express treated as PCI, 6 conventional PCI bridge, 7 PCI-X
  bridge, 8 PCI Express Root Port, 9 upstream switch port, 10 downstream
  switch port, 11 PCI Express to PCI-X bridge, 12 PCI-X to PCI Express
  bridge, 13 PCI Express bridge treated as PCI, 14 Root Complex Event
  Collector (confirmed: 0, 2, 3, 4, 8; the GPU reads 3, matching lspci's
  "Legacy Endpoint").
- Link speed: 1 = 2.5, 2 = 5.0, 3 = 8.0, 4 = 16.0, 5 = 32.0 GT/s, the
  same encoding as the spec's Link Status / Link Capabilities fields
  (confirmed: the GPU reads max 4, and its dump's Link Capabilities says 16
  GT/s). Link width: the lane count.
- Payload sizes: 0 = 128 ... 5 = 4096 bytes, the same codes as Device
  Control (confirmed: the GPU reads 1/1/2 = 256/256/512, matching its dump).
Devices with no PCI Express capability (conventional PCI, integrated
platform devices) report null for the link properties.
"""

import base64
import json
import re
import subprocess
import sys
from dataclasses import dataclass

from .. import ids
from ..pcie_cap import PAYLOAD_BYTES, SPEED_GTS

# The property keys we read, all verified to exist on this machine with
#   Get-PnpDevice -PresentOnly | Where-Object InstanceId -like 'PCI\*' | Select -First 1 | Get-PnpDeviceProperty
PROPERTY_KEYS = [
    "DEVPKEY_Device_BusNumber",
    "DEVPKEY_Device_Address",
    "DEVPKEY_Device_HardwareIds",
    "DEVPKEY_Device_DeviceDesc",
    "DEVPKEY_Device_LocationInfo",
    "DEVPKEY_Device_Parent",
    "DEVPKEY_PciDevice_DeviceType",
    "DEVPKEY_PciDevice_BaseClass",
    "DEVPKEY_PciDevice_SubClass",
    "DEVPKEY_PciDevice_ProgIf",
    "DEVPKEY_PciDevice_CurrentLinkSpeed",
    "DEVPKEY_PciDevice_CurrentLinkWidth",
    "DEVPKEY_PciDevice_MaxLinkSpeed",
    "DEVPKEY_PciDevice_MaxLinkWidth",
    "DEVPKEY_PciDevice_CurrentPayloadSize",
    "DEVPKEY_PciDevice_MaxPayloadSize",
    "DEVPKEY_PciDevice_MaxReadRequestSize",
    "DEVPKEY_PciDevice_ExpressSpecVersion",
    "DEVPKEY_PciDevice_InterruptSupport",
    "DEVPKEY_PciDevice_InterruptMessageMaximum",
    "DEVPKEY_PciDevice_BarTypes",
    "DEVPKEY_PciDevice_AERCapabilityPresent",
    "DEVPKEY_PciDevice_Uncorrectable_Error_Mask",
    "DEVPKEY_PciDevice_Uncorrectable_Error_Severity",
    "DEVPKEY_PciDevice_Correctable_Error_Mask",
    "DEVPKEY_PciDevice_Error_Reporting",
]

# The PowerShell that does the work. It emits one JSON list; each element is one PCI function
# with the properties above as fields. $keys is filled in from PROPERTY_KEYS at run time.
POWERSHELL_SCRIPT = r"""
$keys = @(KEYS)
$out = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'PCI\*' } | ForEach-Object {
  $o = [ordered]@{ InstanceId = $_.InstanceId }
  foreach ($p in (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName $keys)) { $o[$p.KeyName] = $p.Data }
  [pscustomobject]$o
}
@($out) | ConvertTo-Json -Depth 3
"""

DEVICE_TYPES = {
    0: "PCI conventional",
    1: "PCI-X",
    2: "PCI Express endpoint",
    3: "PCI Express legacy endpoint",
    4: "Root Complex integrated endpoint",
    5: "PCI Express treated as PCI",
    6: "PCI conventional bridge",
    7: "PCI-X bridge",
    8: "PCI Express Root Port",
    9: "PCI Express upstream switch port",
    10: "PCI Express downstream switch port",
    11: "PCI Express to PCI-X bridge",
    12: "PCI-X to PCI Express bridge",
    13: "PCI Express bridge treated as PCI",
    14: "Root Complex Event Collector",
}

# 'PCI\VEN_10DE&DEV_2489&SUBSYS_40771458&REV_A1': vendor, device, subsystem (ID then vendor), revision.
_HARDWARE_ID = re.compile(r"VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})(?:&SUBSYS_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4}))?(?:&REV_([0-9A-Fa-f]{2}))?")


@dataclass
class PciFunction:
    instance_id: str
    bus: int
    device: int
    function: int
    vendor_id: int
    device_id: int
    subsystem_id: int | None
    subsystem_vendor_id: int | None
    revision: int | None
    base_class: int | None
    sub_class: int | None
    prog_if: int | None
    description: str
    location: str
    parent: str
    device_type: int | None
    current_link_speed: int | None  # spec speed code, or None when the device has no link
    current_link_width: int | None
    max_link_speed: int | None
    max_link_width: int | None
    current_payload: int | None  # payload code, as in Device Control
    max_payload: int | None  # as in Device Capabilities
    max_read_request: int | None
    express_version: int | None
    interrupt_support: int | None
    interrupt_message_maximum: int | None
    bar_types: int | None
    aer_present: bool | None
    ue_mask: int | None
    ue_severity: int | None
    ce_mask: int | None
    error_reporting: int | None

    @property
    def bdf(self) -> str:
        return f"{self.bus:02x}:{self.device:02x}.{self.function}"

    @property
    def bdf_key(self) -> tuple[int, int, int]:
        return (self.bus, self.device, self.function)

    @property
    def vid_did(self) -> str:
        return f"{self.vendor_id:04x}:{self.device_id:04x}"

    @property
    def class_code(self) -> int | None:
        if self.base_class is None:
            return None
        return (self.base_class << 16) | ((self.sub_class or 0) << 8) | (self.prog_if or 0)

    @property
    def class_name(self) -> str:
        if self.base_class is None:
            return "class unknown"
        return ids.class_name(self.base_class, self.sub_class or 0, self.prog_if or 0)

    @property
    def device_type_name(self) -> str:
        if self.device_type is None:
            return "unknown"
        return DEVICE_TYPES.get(self.device_type, f"type {self.device_type}")

    @property
    def has_link(self) -> bool:
        return self.current_link_speed is not None and self.max_link_speed is not None

    @property
    def speed_downgraded(self) -> bool:
        return self.has_link and 0 < self.current_link_speed < self.max_link_speed

    @property
    def width_downgraded(self) -> bool:
        return self.has_link and 0 < (self.current_link_width or 0) < (self.max_link_width or 0)

    @property
    def link_text(self) -> str:
        """lspci-style: 'LnkSta 2.5GT/s x16 (max 16GT/s x16)' or a reason there is no link."""
        if not self.has_link:
            # Observed on this machine: Windows fills the link properties for endpoints only. Root Ports
            # (DeviceType 8) have a Link Status register too, but the property reads null for them.
            if self.device_type == 8:
                return "Root Port (Windows reports no link properties for ports)"
            if self.device_type is None:
                return "no PCI Express properties (host bridge)"
            return "no PCI Express link (conventional or integrated device)"
        cur = f"{speed_short(self.current_link_speed)} x{self.current_link_width}"
        mx = f"{speed_short(self.max_link_speed)} x{self.max_link_width}"
        flag = " downgraded" if self.speed_downgraded or self.width_downgraded else ""
        return f"LnkSta {cur} (max {mx}){flag}"

    @property
    def payload_text(self) -> str:
        if self.current_payload is None:
            return ""
        return f"MPS {payload_short(self.current_payload)}/{payload_short(self.max_payload)} MRRS {payload_short(self.max_read_request)}"


def speed_short(code: int | None) -> str:
    return f"{SPEED_GTS[code]:g}GT/s" if code in SPEED_GTS else f"code {code}"


def payload_short(code: int | None) -> str:
    return f"{PAYLOAD_BYTES[code]}" if code in PAYLOAD_BYTES else f"code {code}"


def _int_or_none(value):
    return None if value is None else int(value)


def parse_hardware_ids(hardware_ids) -> tuple[int, int, int | None, int | None, int | None]:
    """The first hardware ID carries vendor, device, subsystem and revision."""
    first = hardware_ids[0] if isinstance(hardware_ids, list) and hardware_ids else str(hardware_ids or "")
    m = _HARDWARE_ID.search(first)
    if not m:
        raise ValueError(f"cannot read VEN/DEV from hardware ID {first!r}")
    vendor, device, subsystem, subsystem_vendor, revision = m.groups()
    return (
        int(vendor, 16),
        int(device, 16),
        int(subsystem, 16) if subsystem else None,
        int(subsystem_vendor, 16) if subsystem_vendor else None,
        int(revision, 16) if revision else None,
    )


def parse_pnp_json(text: str) -> list[PciFunction]:
    """The PowerShell JSON (a list, or one object when only one device) -> PciFunction rows."""
    data = json.loads(text)
    if isinstance(data, dict):  # ConvertTo-Json drops the list around a single element
        data = [data]
    rows = []
    for e in data:
        address = int(e.get("DEVPKEY_Device_Address") or 0)
        vendor, device, subsystem, subsystem_vendor, revision = parse_hardware_ids(e.get("DEVPKEY_Device_HardwareIds"))
        rows.append(
            PciFunction(
                instance_id=e.get("InstanceId", ""),
                bus=int(e.get("DEVPKEY_Device_BusNumber") or 0),
                device=address >> 16,  # device number: the upper 16 bits
                function=address & 0xFFFF,  # function number: the lower 16 bits
                vendor_id=vendor,
                device_id=device,
                subsystem_id=subsystem,
                subsystem_vendor_id=subsystem_vendor,
                revision=revision,
                base_class=_int_or_none(e.get("DEVPKEY_PciDevice_BaseClass")),
                sub_class=_int_or_none(e.get("DEVPKEY_PciDevice_SubClass")),
                prog_if=_int_or_none(e.get("DEVPKEY_PciDevice_ProgIf")),
                description=e.get("DEVPKEY_Device_DeviceDesc") or "",
                location=e.get("DEVPKEY_Device_LocationInfo") or "",
                parent=e.get("DEVPKEY_Device_Parent") or "",
                device_type=_int_or_none(e.get("DEVPKEY_PciDevice_DeviceType")),
                current_link_speed=_int_or_none(e.get("DEVPKEY_PciDevice_CurrentLinkSpeed")),
                current_link_width=_int_or_none(e.get("DEVPKEY_PciDevice_CurrentLinkWidth")),
                max_link_speed=_int_or_none(e.get("DEVPKEY_PciDevice_MaxLinkSpeed")),
                max_link_width=_int_or_none(e.get("DEVPKEY_PciDevice_MaxLinkWidth")),
                current_payload=_int_or_none(e.get("DEVPKEY_PciDevice_CurrentPayloadSize")),
                max_payload=_int_or_none(e.get("DEVPKEY_PciDevice_MaxPayloadSize")),
                max_read_request=_int_or_none(e.get("DEVPKEY_PciDevice_MaxReadRequestSize")),
                express_version=_int_or_none(e.get("DEVPKEY_PciDevice_ExpressSpecVersion")),
                interrupt_support=_int_or_none(e.get("DEVPKEY_PciDevice_InterruptSupport")),
                interrupt_message_maximum=_int_or_none(e.get("DEVPKEY_PciDevice_InterruptMessageMaximum")),
                bar_types=_int_or_none(e.get("DEVPKEY_PciDevice_BarTypes")),
                aer_present=e.get("DEVPKEY_PciDevice_AERCapabilityPresent"),
                ue_mask=_int_or_none(e.get("DEVPKEY_PciDevice_Uncorrectable_Error_Mask")),
                ue_severity=_int_or_none(e.get("DEVPKEY_PciDevice_Uncorrectable_Error_Severity")),
                ce_mask=_int_or_none(e.get("DEVPKEY_PciDevice_Correctable_Error_Mask")),
                error_reporting=_int_or_none(e.get("DEVPKEY_PciDevice_Error_Reporting")),
            )
        )
    return sorted(rows, key=lambda r: r.bdf_key)


def powershell_script() -> str:
    keys = ",".join(f"'{k}'" for k in PROPERTY_KEYS)
    return POWERSHELL_SCRIPT.replace("KEYS", keys)


def run_powershell(script: str) -> str:
    """Run a PowerShell script and return its stdout.

    -EncodedCommand takes the script base64-encoded as UTF-16LE, so no shell
    quoting rule can mangle it. -NoProfile keeps the user's profile out of the
    way; the output is read as UTF-8 with a possible byte order mark.
    """
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"PowerShell failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout.decode("utf-8-sig", "replace")


def list_pci_functions() -> list[PciFunction]:
    """Every present PCI function, sorted by bus, device, function. Windows only."""
    if sys.platform != "win32":
        raise RuntimeError("pcicfg list reads Windows PnP device properties; not available on this platform")
    return parse_pnp_json(run_powershell(powershell_script()))


def render_list(functions: list[PciFunction]) -> str:
    """One row per function, lspci -nn style: BDF, VID:DID, class, name, link, payload sizes."""
    lines = [
        "# Windows PnP view, no driver: link speed/width are DEVPKEY_PciDevice_* properties the PCI",
        "# bus driver fills from Link Status / Link Capabilities (spec 7.5.3.8 / 7.5.3.6)",
    ]
    for f in functions:
        # base and sub class as four hex digits, what lspci -nn shows in brackets ([0300] for VGA)
        cls = f"{f.class_code >> 8:04x}" if f.class_code is not None else "----"
        lines.append(f"{f.bdf}  {f.vid_did}  {cls}  {f.description:<44} {f.link_text}  {f.payload_text}".rstrip())
    return "\n".join(lines)


def functions_as_json(functions: list[PciFunction]) -> list[dict]:
    out = []
    for f in functions:
        d = dict(vars(f))
        d.update(bdf=f.bdf, vid_did=f.vid_did, class_code=f.class_code, class_name=f.class_name,
                 device_type_name=f.device_type_name, link=f.link_text, speed_downgraded=f.speed_downgraded,
                 width_downgraded=f.width_downgraded)
        out.append(d)
    return out
