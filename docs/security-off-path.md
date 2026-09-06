# The security-off path: RW-Everything with Memory Integrity disabled

**This is the fallback, and it is documented rather than used.** Nothing in this
repository turns these protections off, and `pcicfg` will not do it for you.
`docs/security-on-path.md` gets the same bytes with Memory Integrity left on and
should be tried first; a Linux live USB gets them with no Windows changes at all.

Read [What this actually costs](#what-this-actually-costs) before deciding.

## Why this path exists

RW-Everything reads configuration space through its own kernel driver,
`RwDrv.sys`. On a current Windows 11 machine that driver does not load, for a
specific and checkable reason: it is named in Microsoft's vulnerable-driver
blocklist, and while Memory Integrity (HVCI) is on, a blocklisted driver is
refused at load. You can confirm both facts on your own machine:

```powershell
python -c "from pcicfg.win.raw import driver_blocklisted, memory_integrity_enabled; print('RwDrv blocklisted:', driver_blocklisted('RwDrv')); print('Memory Integrity:', memory_integrity_enabled())"
```

On the machine this project was built on that prints `True` and `True`, which is
why neither RW-Everything's GUI nor its command line reads a single byte here.
Making it work means turning both of those off.

## The steps

Every one of these needs an elevated prompt, and steps 1–3 together need one
reboot before RW-Everything will load.

### 1. Turn Memory Integrity off

Windows Security → Device security → Core isolation → **Memory integrity** →
Off. Or, equivalently:

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
```

### 2. Turn the vulnerable-driver blocklist off

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
```

Memory Integrity off is not by itself enough on a current build: the blocklist is
enforced separately, and `RwDrv.sys` is on it. Both have to go.

### 3. Reboot

Then check that it took, before blaming the tool:

```powershell
python -c "from pcicfg.win.raw import memory_integrity_enabled; print('Memory Integrity:', memory_integrity_enabled())"
```

### 4. Read the device with RW-Everything

Install it from <https://rweverything.com> and run `Rw.exe` **as
Administrator**. (Its own binaries are not Authenticode-signed; the driver is
the signed part, and the blocklist is what stops that.)

1. Toolbar → **PCI** to open the PCI device list.
2. Pick the Function you want — `01:00.0` for the RTX 3060 Ti, `02:00.0` for the
   Samsung 990 PRO.
3. **File → Save** the configuration space to a text file. A PCI Express device
   saves the full 4096 bytes, which is what the extended capability chain at
   offset 100h and up needs.

### 5. Decode it

```powershell
python -m pcicfg decode rtx3060ti_01-00.0.txt
python -m pcicfg decode rtx3060ti_01-00.0.txt --annotate
python -m pcicfg decode rtx3060ti_01-00.0.txt --json
```

`pcicfg decode` takes an RW-Everything save, an `lspci -xxxx` text dump or a raw
binary image, and works out which it is. If the file has only 256 bytes,
`decode` says so and skips the extended chain rather than inventing it.

### 6. Put the machine back

This is the step people forget. Re-enable both, and reboot:

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
```

Memory Integrity is better re-enabled through the Windows Security UI, which
will tell you if an incompatible driver is now blocking it.

## What this actually costs

The blocklist is not arbitrary. It exists because "bring your own vulnerable
driver" is a standard, actively used technique: an attacker who already has
administrator rights loads a *legitimately signed* driver with a known flaw and
uses it as a ready-made kernel read/write primitive, to disable security
software, steal credentials from LSASS, or install a rootkit. Ransomware crews do
this routinely. `RwDrv.sys` is on the list precisely because it is a good tool
for it — the same generality that makes it useful for reading configuration
space makes it useful for writing anywhere.

So while these two settings are off:

- Any code that reaches administrator on the machine can load one of those
  drivers and get kernel read/write, which is effectively game over for that
  install.
- Hypervisor-enforced code integrity is not validating kernel code at all, so
  the usual protection against a malicious or tampered driver is gone.
- Anything else on the machine that depends on VBS is weakened at the same time.

Compare that with the security-on path, which needs `bcdedit /debug on` — also a
real change, and also worth undoing, but one that leaves the blocklist enforced
and HVCI validating every driver, so the BYOVD door stays shut.

If the machine holds anything you care about, prefer either of these instead:

- **`docs/security-on-path.md`** — Microsoft's own signed debug driver, all
  protections left on.
- **A Linux live USB** — no Windows changes whatsoever, and the same bytes:

  ```sh
  sudo lspci -vvv -xxxx -s 01:00.0 > rtx3060ti_01-00.0.txt
  sudo cat /sys/bus/pci/devices/0000:01:00.0/config > 01-00.0.config
  ```

  Copy either file to Windows and `pcicfg decode` it. The fixtures in
  `tests/fixtures/` were made this way.
