# Reading real configuration space on Windows with Memory Integrity left on

This is the route `pcicfg dump` tries first. It reads a device's configuration
space byte for byte on Windows with **Memory Integrity (HVCI) on**, the
**vulnerable-driver blocklist enforced** and **test signing off**, using a driver
Microsoft signed and ships itself.

> ## ⚠ Precondition: it requires Secure Boot to be **off**
>
> This was measured, not assumed. The path needs `bcdedit /debug on`, and Secure
> Boot policy protects that BCD element:
>
> ```
> C:\> bcdedit /debug on
> An error occurred while attempting to modify the debugger settings.
> The value is protected by Secure Boot policy and cannot be modified or deleted.
> ```
>
> No amount of privilege gets around this; it is settled in firmware. On a
> Secure Boot machine — which is the default, and was the case here — **this
> path is closed**, and `pcicfg dump` says so without needing admin rights.
>
> **I do not recommend turning Secure Boot off to open it.** Secure Boot is the
> root of trust that Memory Integrity's own guarantees rest on, so disabling it
> is a broader weakening than either thing this project set out to avoid. If you
> are on a Secure Boot machine, use the Linux live USB in
> [the last section](#if-you-cannot-do-any-of-this) instead: same bytes, no
> Windows changes at all.

The rest of this document is what to do on a machine where Secure Boot is
already off, and it is still not free: it costs one boot-level change and a
reboot, with a security cost of its own spelled out under
[The tradeoff](#the-tradeoff).

## Why a driver is needed at all

Configuration space has exactly two hardware access paths, and both are ring 0:

| Path | Spec | Reaches | Why user mode cannot |
|---|---|---|---|
| Write CF8h, read CFCh | 7.2.1 | 256 bytes per Function | Port I/O is ring 0 |
| ECAM window in physical memory | 7.2.2 | the full 4096 bytes | Mapping physical memory is ring 0 |

The extended capability chain — AER, L1 PM Substates, Latency Tolerance
Reporting and the rest — starts at offset 100h, so anything that stops at 256
bytes cannot see it. That is why the frame size matters and why this document
keeps insisting on the number.

`pcicfg list` already reports link speed, width, payload sizes and the AER masks
with no driver at all, by reading the `DEVPKEY_PciDevice_*` properties Windows
fills in from these same registers. What it cannot give you is the bytes.

## Why kldbgdrv.sys

The drivers people normally reach for — RW-Everything's `RwDrv.sys` and its kin —
are on Microsoft's vulnerable-driver blocklist and are refused at load while
Memory Integrity is on. This project does not turn that off, so they are out.

`kldbgdrv.sys` is the Kernel Local Debugging Driver: what `kd -kl` uses to
inspect the running kernel, and the driver behind pciutils' `win32-kldbg` access
method. It qualifies where the others do not:

- **Microsoft-signed.** The copy in the Windows SDK verifies `Valid`, signed
  `CN=Microsoft Corporation, OU=MOPR` under `Microsoft Code Signing PCA`.
- **Not blocklisted.** Checked against this machine's own enforced policy blob:
  `driver_blocklisted("kldbgdrv")` returns `False`, where `RwDrv` returns `True`.
- **Inert by default.** It does nothing unless the machine was booted with
  kernel debugging enabled.

Nothing is renamed, patched, self-signed or test-signed at any point.

### One trap worth knowing

`kldbgdrv.sys` is not shipped as a file. It is embedded as a resource
(type `0x4444`, name `0x7777`) inside `kd.exe` and `windbg.exe`, and **the two
copies in circulation are not equally usable**:

| Source of `kd.exe` | Embedded driver signed by | Loads? |
|---|---|---|
| Windows SDK Debugging Tools | `Microsoft Corporation` / `Microsoft Code Signing PCA` — **Valid** | yes |
| Microsoft Store WinDbg (`Microsoft.WinDbg`) | `Windows Internal Build Tools PCA 2020` — root not trusted on retail Windows | **no** |

The Store package's own `kd.exe` is validly signed; the driver *inside* it is
not, so a driver unpacked from it fails code integrity at load. pciutils will
happily unpack from whichever `kd.exe` it finds on `PATH`, so if the Store
WinDbg is first you get an install that cannot work. `tools/kldbg-setup.ps1`
verifies the signature before installing and refuses the bad copy.

## Setup

### 1. Get the SDK debugging tools

Only the payload is needed, not an installed SDK. `/layout` downloads without
installing and without admin:

```powershell
# winsdksetup.exe from https://go.microsoft.com/fwlink/?linkid=2286561
.\winsdksetup.exe /layout C:\sdklayout /features OptionId.WindowsDesktopDebuggers /quiet
msiexec /a "C:\sdklayout\Installers\X64 Debuggers And Tools-x64_en-us.msi" /qn TARGETDIR=C:\dbgtools
# kd.exe lands in C:\dbgtools\Windows Kits\10\Debuggers\x64\
```

Installing the SDK's Debugging Tools normally also works; then `kd.exe` is in
`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\`, where the setup script
looks by default.

### 2. Install the driver and enable debug boot

**If BitLocker is on, suspend it first** — see the warning below — then, from an
**elevated** prompt:

```powershell
.\tools\kldbg-setup.ps1 -Install -EnableDebugBoot -KdPath "C:\dbgtools\Windows Kits\10\Debuggers\x64\kd.exe"
```

The script verifies the signature, copies the driver to `System32`, registers a
demand-start kernel service, and runs `bcdedit /debug on`. It changes nothing
else. Run it with no arguments at any time to see the current state.

### 3. Reboot

`bcdedit /debug on` only takes effect at the next boot.

### 4. Read

From an **elevated** prompt, because the driver's device object requires it:

```powershell
python -m pcicfg dump 01:00.0 -o rtx3060ti.bin
python -m pcicfg dump 02:00.0 -o samsung990pro.bin
```

`pcicfg dump` prints which access method read the bytes and how far each of its
two reads reached, so the 256-vs-4096 question is answered from measurement
rather than assumption:

```
# read by kldbgdrv ...
# got NNNN bytes: ...
#   SysDbgReadBusData reached NNN bytes (HalGetBusDataByOffset)
#   SysDbgReadPhysical at ECAM 0xC0100000 ...
```

## How the read works

The driver exposes one IOCTL, `IOCTL_KLDBG` (`0x0022C007`), carrying a `KLDBG`
envelope that names a `SYSDBG_COMMAND`. `pcicfg` uses two, in this order:

1. **`SysDbgReadBusData` (18)** with `BusDataType = PCIConfiguration (4)`. The
   kernel turns this into `HalGetBusDataByOffset`, the HAL's own
   configuration-space read. Whether it reaches past the first 256 bytes is
   **not documented**, so `kldbg.read_config_space` reads upward until the
   kernel refuses and records how far it got. (pciutils documents its
   `win32-sysdbg` backend — the same command by a different route — as reaching
   "only first 256 bytes", and as unavailable on 64-bit Windows at all.)
2. **`SysDbgReadPhysical` (10)**, used when the first stops short of 4096. The
   ECAM window *is* physical memory, and `raw.read_ecam_regions` already works
   out any Function's exact physical address from the ACPI MCFG table with no
   privilege at all. This command is the ring-0 read that address was always
   missing, and it reaches the extended capabilities at 100h and up.

Both need `SeDebugPrivilege` (an elevated process holds it; `pcicfg` enables it)
and both need the debug boot.

## The tradeoff

Be clear about what this does and does not change.

**Unchanged.** Memory Integrity stays on. The vulnerable-driver blocklist stays
enforced. Test signing stays off. No unsigned, renamed or blocklisted driver is
loaded. `RwDrv.sys` still cannot load.

**Already off, or this would not have got here.** Secure Boot — see the
precondition at the top. That is the largest single cost of this route, and on a
machine where Secure Boot is on it is the reason the route is unavailable.

**Changed.** `bcdedit /debug on` arms the local kernel debugging interface from
the next boot. Concretely:

- An **administrator** can then read and write kernel memory through
  `kldbgdrv.sys` — which is exactly the capability `pcicfg dump` uses. It does
  not grant a normal user anything, and it is not remotely reachable, but it
  does mean local admin becomes a shorter path to kernel read/write than it was.
- Kernel Patch Protection is not enforced against an attached kernel debugger,
  so a machine in this state is a weaker platform for detecting kernel tampering.
- Some DRM and a few anti-cheat systems refuse to run on a debug-boot machine.

**BitLocker.** Turning kernel debugging on changes the measured boot
configuration, so the next boot demands your recovery key unless you suspend
protection first:

```powershell
manage-bde -protectors -get C:          # write the recovery key down first
manage-bde -protectors -disable C: -RebootCount 2
```

The honest summary: this is a smaller and much better-scoped change than turning
Memory Integrity off, because it does not re-open the door to the blocklisted
drivers that BYOVD attacks actually use — but it is not nothing, and it is worth
undoing when you are done.

## Undo

From an elevated prompt, then reboot:

```powershell
.\tools\kldbg-setup.ps1 -Uninstall -DisableDebugBoot
```

That deletes the service, removes `System32\kldbgdrv.sys` and runs
`bcdedit /debug off`, returning the machine to its previous state.

## Cross-checking with lspci

pciutils' `win32-kldbg` backend uses the same driver and the same
`SysDbgReadBusData` command, so it is a useful independent check of the
`pcicfg` reader. Built from the official source with MinGW:

```sh
make CC=gcc ZLIB=no DNS=no IDSDIR="" HOST=x86_64-windows
lspci.exe -A win32-kldbg -s 01:00.0 -vvv -xxxx
```

Run it elevated and with debug boot on; `lspci` prints 4096 bytes only if the
backend actually returns them, and falls back to 256 otherwise, which makes it a
second opinion on the same question.

## If you cannot do any of this

`docs/security-off-path.md` documents the route that needs Memory Integrity
off, and what that costs. A Linux live USB gets the same bytes with no Windows
changes at all and is usually the better answer.
