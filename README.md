# pcie-config-decoder

`pcicfg` reads PCI Express configuration space and decodes it: the Type 0
header, the standard and extended capability chains, the PCI Express
capability (link speed and width, payload sizes, error reporting enables), and
Advanced Error Reporting. It is built in three layers:

1. **Decoder core** (pure Python, stdlib only): decodes a 256- or 4096-byte
   dump from a file. Works on any OS.
2. **Windows enumeration, no driver**: `pcicfg list` prints every PCI function
   with the link properties Windows already exposes through PnP properties.
3. **Raw reads on Windows** through a signed kernel driver (PawnIO): optional.
   If it is not available, `pcicfg dump` says exactly why and how else to get
   the bytes.

Status: being built one module at a time. This README grows with each module.
Done so far:

1. **parse**: `lspci -xxxx` text or raw binary -> bytes, `pcicfg decode <file> --hex`.
2. **header and ids**: the Type 0 header, every register with its absolute
   offset, raw value and meaning; `pcicfg decode <file>` prints it. Type 1
   (bridge) headers: bus numbers only, tagged ahead.

Taught vs ahead (expanded in the final README): taught = Type 0 header,
standard and extended capability chains, PCI Express capability, AER, MSI
basics, CF8/CFC vs ECAM. Ahead = Type 1 bridge headers, Power Management and
MSI-X registers, Virtual Channel, Resizable BAR, L1 PM Substates, SR-IOV.

## How to get a dump

Linux (the reference path):

```
sudo lspci -vvv -xxxx -s 01:00.0 > rtx3060ti_01-00.0.txt
# or the raw bytes straight from sysfs:
sudo cat /sys/bus/pci/devices/0000:01:00.0/config > 01-00.0.config
```

Windows: Layer 3 status will be recorded here after the spike. Fallback:
RW-Everything's per-device save, or an Ubuntu live USB and the commands above.

## Run

```
py -m pcicfg decode tests/fixtures/rtx3060ti_01-00.0.txt --hex
py -m pytest
```

## Fixtures

`tests/fixtures/` holds two real dumps taken with `sudo lspci -vvv -xxxx`:
an NVIDIA RTX 3060 Ti (`10de:2489`, 01:00.0) and a Samsung 990 PRO NVMe
(`144d:a80c`, 02:00.0), plus `lspci -tv` and `lspci -nn` of the same machine.
lspci's own decoded text sits above the hex rows in each file and is the answer
key the tests check against.
Line endings were normalized to LF, which is what lspci wrote on Linux; the
vault copies are CRLF. The parser accepts either, and UTF-16 files as written by
Windows PowerShell redirection.
