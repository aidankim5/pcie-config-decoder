"""Turn a dump of PCI configuration space into bytes.

[Taught] This is the step Aidan did by eye: find the hex rows, read the row
label as the absolute offset of the row's first byte, count across to the byte
you want, and flip multi-byte fields little-endian.

Three inputs are accepted:

1. The text that `sudo lspci -vvv -xxxx -s <bdf>` prints on Linux. lspci prints
   its own decoded view first, then the raw bytes, 16 per row, each row labeled
   with the absolute offset of its first byte in hex: "00:", "10:", ... "ff0:".
   Only the labeled rows become bytes. The decoded text above them is kept as
   `ConfigSpace.lspci_text` because it is the answer key the tests check
   against, but nothing in this package decodes from it.
2. A raw binary file: the bytes themselves, for example
   `/sys/bus/pci/devices/0000:01:00.0/config` copied off a Linux machine.
3. A full `lspci -vvv -xxxx` listing with many devices (see parse_lspci_all).

Dump sizes and what each one means (spec = PCI Express Base 5.0):

- 64 bytes:   the header only (`lspci -x`). Spec 7.5.1.
- 256 bytes:  everything the PCI-compatible configuration mechanism can reach
              (CF8/CFC, an 8-bit register field). Spec 7.2.1. The standard
              capability chain lives here.
- 4096 bytes: everything ECAM can reach (memory-mapped, 12-bit offset).
              Spec 7.2.2. Extended capabilities start at offset 100h and exist
              only in this frame.

This module does not decode anything. It only produces bytes and the three
little-endian readers every later module uses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# One hex row as lspci prints it:
#   "70: 00 00 00 00 00 00 00 00 10 b4 12 00 e1 8d 2c 11"
# group 1 = the label (absolute offset of the first byte, 2 or 3 hex digits),
# group 2 = the byte pairs. Rows start at column 0 in lspci output; leading
# whitespace is tolerated for hand-pasted files.
_HEX_ROW = re.compile(r"^\s*([0-9A-Fa-f]{2,3}):((?:\s+[0-9A-Fa-f]{2})+)\s*$")

# The first line of an lspci device block:
#   "01:00.0 VGA compatible controller: NVIDIA Corporation ..."
# With `lspci -D` the PCI domain is prefixed: "0000:01:00.0 ...".
_BDF_LINE = re.compile(
    r"^(?P<bdf>(?:[0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7])\s+(?P<desc>.*)$"
)

# Choice, not spec: the dump sizes this tool expects and the name of each frame.
FRAME_NAMES = {
    64: "header only (lspci -x)",
    256: "PCI-compatible space, 256 bytes (CF8/CFC reach, spec 7.2.1)",
    4096: "full ECAM space, 4096 bytes (spec 7.2.2)",
}


class ParseError(ValueError):
    """The dump file is not in a shape this module understands."""


@dataclass
class ConfigSpace:
    """The bytes of one function's configuration space plus where they came from.

    `data[off]` is the byte at absolute offset `off`. The readers below do the
    little-endian flip so callers never do it by hand.
    """

    data: bytes
    source: str = ""
    bdf: str | None = None
    description: str = ""  # lspci's first line after the BDF, if any
    lspci_text: str = ""  # lspci's decoded lines (the answer key), if any

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def frame(self) -> str:
        """Which configuration-space frame this dump covers (see module docstring)."""
        return FRAME_NAMES.get(self.size, f"nonstandard size, {self.size} bytes")

    @property
    def has_extended_space(self) -> bool:
        """True when the dump reaches past offset FFh.

        Extended capabilities start at 100h (spec 7.6.3), so a 256-byte dump
        cannot contain any. Only ECAM (spec 7.2.2) reaches them.
        """
        return self.size > 0x100

    def _check(self, off: int, width: int) -> None:
        if off < 0 or off + width > self.size:
            raise IndexError(
                f"offset {off:#x} width {width} is outside this {self.size}-byte dump"
            )

    def u8(self, off: int) -> int:
        """The byte at absolute offset `off`."""
        self._check(off, 1)
        return self.data[off]

    def u16(self, off: int) -> int:
        """Two bytes at `off`, little-endian: bytes `de 10` at 00h read as 0x10DE."""
        self._check(off, 2)
        return int.from_bytes(self.data[off : off + 2], "little")

    def u32(self, off: int) -> int:
        """Four bytes at `off`, little-endian: bytes `04 3d 45 00` read as 0x00453D04."""
        self._check(off, 4)
        return int.from_bytes(self.data[off : off + 4], "little")

    def bytes_at(self, off: int, length: int) -> bytes:
        """`length` raw bytes starting at `off`, in dump order (no flip)."""
        self._check(off, length)
        return self.data[off : off + length]


def parse_lspci_hex(text: str) -> bytes:
    """Collect the labeled hex rows of one lspci block into bytes.

    Rows must start at 00: and be contiguous: each row's label must equal the
    number of bytes collected so far. Lines that are not hex rows (lspci's
    decoded text) are skipped.
    """
    out = bytearray()
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _HEX_ROW.match(line)
        if not m:
            continue
        label = int(m.group(1), 16)
        if label != len(out):
            raise ParseError(
                f"line {lineno}: row label {label:#x} but {len(out):#x} bytes "
                "collected so far; rows must be contiguous from 00:"
            )
        out += bytes.fromhex(m.group(2))  # fromhex ignores the spaces between pairs
    if not out:
        raise ParseError("no hex rows found (expected lines like '00: de 10 89 24 ...')")
    return bytes(out)


def split_lspci_blocks(text: str) -> list[str]:
    """Split a multi-device lspci listing into one text block per function.

    A block starts at a line that begins with a BDF ("01:00.0 ...") and runs
    until the next such line. Text before the first BDF line is dropped. A file
    with no BDF line at all is one block.
    """
    blocks: list[list[str]] = []
    for line in text.splitlines():
        if _BDF_LINE.match(line):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    if not blocks:
        return [text]
    return ["\n".join(b) for b in blocks]


def parse_lspci_block(block: str, source: str = "") -> ConfigSpace:
    """One device's lspci text (decoded lines + hex rows) -> ConfigSpace."""
    lines = block.splitlines()
    bdf = None
    description = ""
    if lines:
        m = _BDF_LINE.match(lines[0])
        if m:
            bdf = m.group("bdf")
            description = m.group("desc").strip()
    decoded = [ln for ln in lines if not _HEX_ROW.match(ln)]
    return ConfigSpace(
        data=parse_lspci_hex(block),
        source=source,
        bdf=bdf,
        description=description,
        lspci_text="\n".join(decoded),
    )


def parse_lspci_all(text: str, source: str = "") -> list[ConfigSpace]:
    """Every device in a full `lspci -vvv -xxxx` listing, in file order.

    Blocks with no hex rows (for example a device lspci could not read) are
    skipped rather than aborting the whole file.
    """
    devices = []
    for block in split_lspci_blocks(text):
        try:
            devices.append(parse_lspci_block(block, source))
        except ParseError as e:
            if "no hex rows" in str(e):
                continue
            raise
    return devices


def looks_like_lspci_text(text: str) -> bool:
    return any(_HEX_ROW.match(line) for line in text.splitlines())


def load_config_space(path: str | Path) -> ConfigSpace:
    """Read one dump file, whichever of the accepted formats it is in.

    Detection order: if the file decodes as text and contains hex rows it is an
    lspci dump; otherwise it must be a raw binary image of exactly 64, 256, or
    4096 bytes (the three frames in FRAME_NAMES). Any other length is rejected
    rather than guessed at: a 20-byte file is not a configuration space.
    """
    p = Path(path)
    raw = p.read_bytes()
    text: str | None
    try:
        text = raw.decode("utf-8-sig")  # -sig strips a Notepad BOM if present
    except UnicodeDecodeError:
        text = None

    if text is not None and looks_like_lspci_text(text):
        blocks = split_lspci_blocks(text)
        with_rows = [b for b in blocks if looks_like_lspci_text(b)]
        if len(with_rows) > 1:
            raise ParseError(
                f"{p}: contains {len(with_rows)} devices; use `pcicfg all` for a full listing"
            )
        return parse_lspci_block(with_rows[0], source=str(p))

    if len(raw) in FRAME_NAMES:
        return ConfigSpace(data=raw, source=str(p))

    raise ParseError(
        f"{p}: not an lspci text dump (no hex rows) and not a raw image "
        f"({len(raw)} bytes; expected 64, 256, or 4096)"
    )
