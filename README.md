# pcie-config-decoder

`pcicfg` reads PCI Express configuration space and decodes it: the Type 0
header, the standard and extended capability chains, every register of the PCI
Express capability, and Advanced Error Reporting. The decoder is pure Python
with nothing but the standard library, so the same code runs on Windows and
Linux and reads a dump taken on either.

I built it to learn the spec by hand, one register at a time. Everything below
that says `[taught]` is something I decoded on paper first and then wrote code
for. Everything that says `[ahead]` is something the tool decodes correctly but
that I have not worked through myself yet, and the output says so on the line
where it appears.

---

## 1. What it is: three layers

| Layer | What it does | Where |
|---|---|---|
| 1. Decoder core | Decodes a 256- or 4096-byte dump from a file. Standard library only, no OS calls. | `pcicfg/*.py` |
| 2. Windows enumeration, no driver | `pcicfg list`: every PCI function with link speed, width and payload sizes, from the PnP properties Windows already publishes. | `pcicfg/win/enum.py` |
| 3. Raw reads on Windows | `pcicfg dump <BDF>`: needs a signed kernel driver. It does not work on this machine, and says exactly why. | `pcicfg/win/raw.py` |

Layer 1 is the part that matters and it ships. Layers 2 and 3 are about the
Windows side of the same question: what can you learn about a link without
touching a byte, and what does it take to touch the bytes.

```
pcicfg decode <file> [--json] [--hex] [--annotate]   one device
pcicfg all <full-lspci-file> [--json]                every device in a listing
pcicfg list [--json]                                 Windows: what the OS already knows
pcicfg dump <BDF> [-o file]                          Windows: raw bytes (see layer 3)
```

Exit codes: 0 done, 1 bad input, 2 usage error, 3 that part is not available.

---

## 2. How to get a dump

Linux is the reference path. Both forms decode:

```
sudo lspci -vvv -xxxx -s 01:00.0 > rtx3060ti_01-00.0.txt      # text, with lspci's own decode above the hex
sudo cat /sys/bus/pci/devices/0000:01:00.0/config > 01-00.0.config   # the raw 4096 bytes
```

`-xxxx` needs root; without it lspci prints no hex rows at all. On Windows,
`pcicfg dump` explains why it cannot read the bytes itself and points at
RW-Everything's per-device save or an Ubuntu live USB. The parser takes a raw
image of exactly 64, 256 or 4096 bytes, or lspci text in UTF-8 or UTF-16.

The two fixtures in `tests/fixtures/` are real dumps from my own machine: an
NVIDIA RTX 3060 Ti at 01:00.0 and a Samsung 990 PRO NVMe at 02:00.0. lspci's
decoded text sits above the hex rows in each file, and the tests check my
decode against it line by line. Line endings are normalized to LF.

---

## 3. Real output

`py -m pcicfg decode tests/fixtures/rtx3060ti_01-00.0.txt`, abridged. The full
389 lines are in [`docs/decode-rtx3060ti.txt`](docs/decode-rtx3060ti.txt); the
NVMe SSD is in [`docs/decode-samsung990pro.txt`](docs/decode-samsung990pro.txt).

```
Type 0 header (spec 7.5.1.1, 7.5.1.2)  [taught]
  00h Vendor ID          10de                 NVIDIA Corporation
  02h Device ID          2489                 GA104 [GeForce RTX 3060 Ti Lite Hash Rate]
  04h Command            0407                 set: I/O Space Enable, Memory Space Enable, Bus Master Enable, Interrupt Disable
  06h Status             0010                 set: Capabilities List
  09h Class Code         030000               VGA compatible controller (base 03, sub 00, prog-if 00)
  0Eh Header Type        80                   Type 0, multi-function
  10h BAR0               84000000             Memory at 84000000 (32-bit, non-prefetchable); size: not determinable from a dump (needs the write-all-ones probe)
  14h BAR1               0000000c 18h:00000040 Memory at 4000000000 (64-bit, prefetchable); size: not determinable from a dump (needs the write-all-ones probe)
  34h Capabilities Ptr   60

Standard capability chain (spec 7.5.1.1.11; Capabilities Pointer 34h = 60h)  [taught]
  60h  ID 01  Power Management                 next 68h     8 bytes to the next start at 68h; structure 8 bytes (spec)  [ahead: ...]
  68h  ID 05  MSI                              next 78h     16 bytes to the next start at 78h; structure 16 bytes (DWORDs of Figures 7-44 to 7-47 per Message Control; a count, the spec gives no byte size)
  78h  ID 10  PCI Express                      next B4h     60 bytes to the next start at B4h; structure 60 bytes (by Capability Version and port type; a choice of this tool, see pcie_cap.py)
  B4h  ID 09  Vendor Specific (length 14h)     end of list  76 bytes to 100h, the end of the PCI-compatible space; structure 20 bytes (declared, Table 7-160)  [ahead: ...]

-- 78h PCI Express (ID 10, spec 7.5.3, 60 bytes: version 2, Legacy PCI Express Endpoint)
  Link: Speed 2.5 GT/s (downgraded), Width x16   (lspci's LnkSta line; 'downgraded' = below Link Capabilities, not said for Downstream Ports)
  +12h (8Ah) Link Status              1101       spec 7.5.3.8
        3:0    Current Link Speed                                 1     2.5 GT/s  (index into the Supported Link Speeds Vector)
        9:4    Negotiated Link Width                              16    x16
        12     Slot Clock Configuration                           1     +
        13     Data Link Layer Link Active                        0     -  (valid only if Link Capabilities bit 20)

-- 420h AER (Advanced Error Reporting) (ID 0001 v2, header 60020001, 44 bytes)
  summary: uncorrectable errors logged: none; correctable errors logged: Advisory Non-Fatal Error
  +10h (430h) Correctable Error Status                00002000   spec 7.8.4.5
        13     Advisory Non-Fatal Error                           1     + error occurred (write 1 to clear)  (RW1CS)
```

Every register line gives the offset inside the capability first, the absolute
offset in the dump second, then the raw value as it sits in memory and the
decode. `--hex` adds the raw rows, `--annotate` marks where each capability
starts in those rows and reprints each structure from its own offset 00, and
`--json` gives the same information as a document with every field.

Two more real captures: [`docs/pcicfg-list-capture.txt`](docs/pcicfg-list-capture.txt)
(the Windows enumeration) and [`docs/pcicfg-dump-capture.txt`](docs/pcicfg-dump-capture.txt)
(the layer 3 refusal).

---

## 4. Verification: my decode against lspci's

Every row below is checked by a test. The raw column is the bytes as they sit
in the dump; the tool flips the little-endian ones before decoding.

| Register | Offset | Raw | My decode | lspci says |
|---|---|---|---|---|
| Vendor ID | 00h | `de 10` | `10de` NVIDIA Corporation | `NVIDIA Corporation` |
| Device ID | 02h | `89 24` | `2489` GA104 [GeForce RTX 3060 Ti] | `GA104 [GeForce RTX 3060 Ti Lite Hash Rate]` |
| Command | 04h | `07 04` | `0407` I/O+ Mem+ BusMaster+ IntDisable+ | `Control: I/O+ Mem+ BusMaster+ ... DisINTx+` |
| Class Code | 09h | `00 00 03` | `030000` VGA compatible controller | `VGA compatible controller` |
| Capabilities Ptr | 34h | `60` | chain starts at 60h | `Capabilities: [60] Power Management` |
| Link Capabilities | 84h | `04 3d 45 00` | `00453d04` max 16 GT/s, x16, Port #0 | `LnkCap: Port #0, Speed 16GT/s, Width x16` |
| Link Status | 8Ah | `01 11` | `1101` 2.5 GT/s (downgraded), x16 | `LnkSta: Speed 2.5GT/s (downgraded), Width x16` |
| Link Capabilities 2 | A4h | `1e 00 80 01` | `0180001e` supported 2.5, 5, 8, 16 GT/s; Retimer+ 2Retimers+ | `LnkCap2: Supported Link Speeds: 2.5-16GT/s, Crosslink- Retimer+ 2Retimers+ DRS-` |
| AER UE Status | 424h | all zero | none logged | `UESta: DLP- SDES- TLP- ... MalfTLP-` |
| AER CE Status | 430h | `00 20 00 00` | `00002000` bit 13 Advisory Non-Fatal Error | `CESta: ... AdvNonFatalErr+ ...` |
| AER CE Mask | 434h | `00 a0 00 00` | bits 13 and 15 masked | `CEMsk: ... AdvNonFatalErr+ ... HeaderOF+` |
| AER UE Severity | 42Ch | `30 20 46 00` | `00462030`, the spec 5.0 default | (lspci prints the bits, same set) |

The Windows side agrees too. `pcicfg list` reads the same numbers out of the
PnP properties, and a test asserts they match the dump: max link speed code 4
(16 GT/s), max width 16, Max_Payload_Size 256 bytes, Max_Read_Request_Size 512,
and Uncorrectable Error Severity `0x462030`, which Windows reports as the
decimal 4595760.

---

## 5. Two things the dump actually told me

**The GPU link was running at 2.5 GT/s, and that is not a fault.**

Link Status at 8Ah reads `0x1101`. Bits 3:0 are 1, which indexes the Supported
Link Speeds Vector to 2.5 GT/s; bits 9:4 are 16, so x16. Link Capabilities at
84h says the maximum is 16 GT/s, so lspci prints `(downgraded)` and so do I. A
card running a sixth of its rated speed looks like a problem, and it is not: the
lanes are all there (x16, not x8 or x4), and only the speed dropped. That is
dynamic link speed management. An idle GPU drops its link to the lowest speed
both ends support and trains back up when traffic arrives, and the width is what
would show a real electrical or seating fault.

I have both states on the same card. The Linux dump above was taken with the GPU
idle and reads 2.5 GT/s. Reading the same link live on Windows, with a display
attached and the NVIDIA driver holding it up, gives 16 GT/s:

```
01:00.0  10de:2489  0300  NVIDIA GeForce RTX 3060 Ti   LnkSta 16GT/s x16 (max 16GT/s x16)  MPS 256/256 MRRS 512
```

Six samples four seconds apart all read 16 GT/s
([`docs/gpu-link-samples-windows.txt`](docs/gpu-link-samples-windows.txt)). Same
register, same card, two power states. The width never moved.

The one link on this machine that really is downgraded is the Wi-Fi card:

```
05:00.0  8086:272b  0280  Intel(R) Wi-Fi 7 BE202 160MHz   LnkSta 8GT/s x1 (max 16GT/s x1) downgraded
```

**The GPU has one correctable error logged, and it was recorded on purpose.**

AER Correctable Error Status at 430h reads `0x00002000`: bit 13, Advisory
Non-Fatal Error. One correctable event happened at some point and the hardware
recorded it. Correctable means the link fixed it itself; nothing was lost.

The interesting part is the mask next to it. Correctable Error Mask at 434h
reads `0x0000a000`, so bit 13 is masked. I first wrote that a masked error is
"not logged, not reported", and this dump proves that wrong: the status bit is
set while the mask bit is set. The two mask registers do not mean the same
thing, and the spec says so in two different subsections. 7.8.4.3, uncorrectable:
a masked error "is not recorded or reported in the Header Log, TLP Prefix Log,
or First Error Pointer, and is not reported to the ... Root Complex". 7.8.4.6,
correctable: a masked error "is not reported to the ... Root Complex" and that
is the whole sentence. So a masked correctable error still sets its status bit;
it just does not send an error message. Masking bit 13 is the normal default,
because Advisory Non-Fatal is informational.

Uncorrectable Error Status is all zero, and Uncorrectable Error Severity is
`0x00462030`, exactly the spec 5.0 default from Table 7-102. Nothing on this
card needs attention.

---

## 6. Why 256 bytes and why 4096

There are two ways to reach configuration space, and they reach different
amounts of it. This is the single fact that decides whether a dump can have
extended capabilities at all.

**The PCI-compatible mechanism (spec 7.2.1)** is the original one, inherited
from PCI. You write an address to I/O port CF8h and read or write the data at
CFCh. The address register has bit 31 as an enable, then 8 bits of bus, 5 of
device, 3 of function, and only **6 bits of register number** (bits 7:2, with
1:0 always zero because the data port hands back a whole DWORD). Six bits of
DWORD number is 64 DWORDs is **256 bytes**. That is the ceiling, and it is why
the PCI-compatible frame stops at FFh and the standard capability chain, whose
pointers are single bytes, lives inside it.

**ECAM, the Enhanced Configuration Access Mechanism (spec 7.2.2)**, is the
PCI Express one. Firmware maps configuration space into physical memory, and
the address of a register is just arithmetic:

```
base + (bus << 20) + (device << 15) + (function << 12) + offset
```

Twelve bits of offset is **4096 bytes** per function. Everything from 100h up
exists only here: the extended capability chain, whose headers are DWORDs with
12-bit next-offset fields, and with it AER, L1 PM Substates, Secondary PCIe,
Lane Margining and the rest.

So the frame size tells you which mechanism produced the dump, and the tool says
which one it got. Hand it 256 bytes and it decodes the header and the standard
chain and then says plainly:

```
note: extended space not present in dump (256 bytes; the extended chain needs the 4096-byte ECAM frame, spec 7.2.2)
```

Both address calculations are implemented and tested in `pcicfg/win/raw.py`
(`cf8_address`, `ecam_address`), including the check that refuses an offset past
256 bytes on the CF8/CFC path.

---

## 7. Layer 3: what raw reads would take, and why they do not happen here

Both hardware paths above are ring 0. Port I/O to CF8h is a privileged
instruction, and mapping the ECAM window means mapping physical memory. User
mode cannot do either, so `pcicfg dump` needs a kernel driver.

The rule I set for this project is that no unsigned driver gets loaded, test
signing stays off, and Memory Integrity stays on. Memory Integrity is on here
(`SecurityServicesRunning` includes 2, HVCI), and I am not turning it off for a
side project. That leaves drivers Microsoft already signed. PawnIO
(github.com/namazso/PawnIO) is one: a signed kernel driver that runs small
signed Pawn modules, and it exposes exactly the native this needs,
`pci_config_read_dword(bus, device, function, offset, out)`.

`pcicfg dump` asks that driver three questions and reports what it finds,
changing nothing:

```
  PawnIOLib.dll   loaded from C:\Program Files\PawnIO\PawnIOLib.dll, driver library version 2.0.0
  pawnio_open     failed, 0x80070005 (Access is denied)
  this process    not elevated (run the terminal as Administrator to change this)
```

Elevation alone would not finish it. A PawnIO module is a compiled Pawn program
signed with a key the driver trusts, and every module in the official release is
device-specific: SMBus controllers, MSRs, LPC, embedded controllers. None
exposes a general configuration-space read. The driver build that accepts a
module you signed yourself is the unrestricted one, which is test signed, and
enabling test signing is the thing I said I would not do.

That is the honest answer: the byte-level read needs a signed module from the
driver's author, or a machine where test signing is acceptable. So `pcicfg dump`
exits 3, writes nothing, and prints the two ways to get the same bytes today,
which is how the fixtures in this repo were made:

1. RW-Everything's per-device save, on Windows, with its own signed driver.
2. An Ubuntu live USB and `sudo lspci -vvv -xxxx -s <bdf>` or
   `sudo cat /sys/bus/pci/devices/0000:<bdf>/config`.

And for link speed, width, payload sizes and the AER masks with no dump and no
driver at all, layer 2 already works: `pcicfg list` reads the
`DEVPKEY_PciDevice_*` properties the Windows PCI bus driver fills in from Link
Status, Link Capabilities, Device Control and Device Capabilities. That is one
PowerShell query and about five seconds for the whole machine.

---

## 8. Taught and ahead

I will not claim a register I cannot explain. The code and the output carry
these tags, so you can ask me about anything marked taught.

**Taught.** I decoded these by hand before writing the code, from the bit tables
in the spec's own subsections:

- The Type 0 header (7.5.1.1, 7.5.1.2): every register, little-endian, the BAR
  encodings, why a 64-bit BAR eats the next slot.
- The standard capability chain from 34h (7.5.1.1.11): ID and next-pointer as
  two separate bytes, never one number.
- The extended capability chain from 100h (7.6.1, 7.6.3): a DWORD header with
  ID in 15:0, version in 19:16, and the next offset in 31:20 as an absolute
  address with two reserved low bits.
- The PCI Express capability (7.5.3), especially Link Capabilities at +0Ch and
  Link Status at +12h, which is where the 2.5 GT/s finding came from.
- AER (7.8.4): the uncorrectable and correctable status, mask and severity
  registers, and the Header Log byte order in 7.8.4.8.
- MSI basics (7.7.1): Message Control, and how the 64-bit address bit moves
  Message Data from +08h to +0Ch.
- CF8/CFC versus ECAM (7.2.1, 7.2.2), as in section 6 above.

**Ahead.** The tool decodes these correctly and the tests check them against
lspci, but I have not worked through them by hand. Every line the tool prints
for them carries `[ahead: decoded by the tool, not yet worked through by hand]`:

- Type 1 (bridge) headers: bus numbers only.
- Power Management (7.5.2) and MSI-X (7.7.2) registers.
- Virtual Channel, Resizable BAR, Device Serial Number.
- Power Budgeting, LTR, L1 PM Substates, Secondary PCIe, Data Link Feature,
  Physical Layer 16 GT/s, Lane Margining, Vendor-Specific extended.
- SR-IOV.

---

## 9. Spec references

Everything is from the **PCI Express Base Specification, Revision 5.0
Version 1.0**. Bit positions were read from each register's own subsection, not
from memory, and cross-checked against Linux `include/uapi/linux/pci_regs.h`
and against lspci's decoded text in the fixtures.

| Topic | Section |
|---|---|
| PCI-compatible configuration mechanism (CF8/CFC) | 7.2.1 |
| Enhanced Configuration Access Mechanism (ECAM) | 7.2.2 |
| Type 0 header | 7.5.1.1, 7.5.1.2 |
| Type 1 header (bridges) | 7.5.1.3 |
| Capabilities Pointer and the standard chain | 7.5.1.1.11 |
| Power Management capability | 7.5.2 |
| PCI Express capability, all 22 registers | 7.5.3.1 - 7.5.3.23 |
| Extended capability headers and the chain | 7.6.1, 7.6.3 |
| MSI / MSI-X | 7.7.1, 7.7.2 |
| Secondary PCI Express, Data Link Feature | 7.7.3, 7.7.4 |
| Physical Layer 16.0 GT/s, Lane Margining | 7.7.5, 7.7.7 |
| Advanced Error Reporting | 7.8.4 |
| Power Budgeting, LTR, L1 PM Substates | 7.8.1, 7.8.2, 7.8.3 |
| Vendor-Specific (standard and extended) | 7.9.4, 7.9.5 |

Where the spec fixes nothing and I had to choose, the code and the output say
"a choice" and say what the choice was. The structure size of the PCI Express
capability is one: the spec draws one figure for every function and hardwires to
zero what a function does not implement, so "how many bytes is this structure"
is a decision, not a lookup.

---

## Run it

```
py -m pcicfg decode tests/fixtures/rtx3060ti_01-00.0.txt
py -m pcicfg decode tests/fixtures/rtx3060ti_01-00.0.txt --hex --annotate
py -m pcicfg all my-lspci-listing.txt --json
py -m pcicfg list
py -m pytest -q
```

162 tests, no dependencies beyond pytest for the tests themselves. Python 3.10
or newer.

---

Built by Aidan Kim with an AI coding agent. The spec reading, the by-hand
decodes and the findings are mine; the agent wrote code to match them and
argued with me about the parts I had wrong.
