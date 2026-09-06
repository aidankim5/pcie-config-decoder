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

- 64 bytes:   the header only. `lspci -x` prints this much on purpose; lspci
              -xxx/-xxxx and sysfs reads also stop at 64 when run without root.
- 256 bytes:  everything the PCI-compatible configuration mechanism can reach
              (CF8/CFC, an 8-bit register field). Spec 7.2.1. The standard
              capability chain lives here.
- 4096 bytes: everything ECAM can reach (memory-mapped, 12-bit offset).
              Spec 7.2.2. Extended capabilities start at offset 100h and exist
              only in this frame.

Spec vs choice: the 256 and 4096 sizes are spec (7.2.1, 7.2.2). Accepting a
64-byte file is a choice, made so a dump taken without sudo still shows its
header. Any other size is refused rather than guessed at.

This module does not decode anything. It only produces bytes and the three
little-endian readers every later module uses.
"""

import re
from dataclasses import dataclass
from pathlib import Path

# One hex row as lspci prints it:
#   "70: 00 00 00 00 00 00 00 00 10 b4 12 00 e1 8d 2c 11"
# The regex, piece by piece:
#   ^\s*                      optional leading spaces (hand-pasted files; lspci itself
#                             starts at column 0)
#   ([0-9A-Fa-f]{2,3}):       the label, 2 or 3 hex digits, then a colon  -> group 1
#   ((?:\s+[0-9A-Fa-f]{2})+)  one or more "spaces + two hex digits"       -> group 2
#   \s*$                      optional trailing spaces, then end of line
_HEX_ROW = re.compile(r"^\s*([0-9A-Fa-f]{2,3}):((?:\s+[0-9A-Fa-f]{2})+)\s*$")

BYTES_PER_ROW = 16  # lspci always prints 16 per row; any other count is a damaged file

# The first line of an lspci device block:
#   "01:00.0 VGA compatible controller: NVIDIA Corporation ..."
# (?P<name>...) names a group so the code can say m.group("bdf") instead of m.group(1).
#   domain    optional, 4 or more hex digits then a colon. lspci prints it only with -D
#             or when some device is outside domain 0 ("0000:01:00.0"; Intel VMD uses
#             5-digit domains like "10000:e1:00.0")
#   bus       2 hex digits (an 8-bit number)
#   device    2 hex digits (really 5 bits, so 00-1f)
#   function  one digit 0-7: a device has at most 8 functions (3 bits, spec 7.3.2)
#   \s+(?P<desc>.*)$   at least one space, then the rest of the line is the description
_BDF_LINE = re.compile(
    r"^\s*(?P<bdf>(?:[0-9A-Fa-f]{4,}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7])\s+(?P<desc>.*)$"
)

# Choice, not spec: the three dump sizes this tool accepts and the name of each frame.
FRAME_NAMES = {
    64: "header only, 64 bytes (lspci -x, or lspci/sysfs run without root)",
    256: "PCI-compatible space, 256 bytes (CF8/CFC reach, spec 7.2.1)",
    4096: "full ECAM space, 4096 bytes (spec 7.2.2)",
}


class ParseError(ValueError):
    """The dump file is not in a shape this module understands."""


@dataclass  # writes __init__ and a readable repr for us from the field list below
class ConfigSpace:
    """The bytes of one function's configuration space plus where they came from.

    `data[off]` is the byte at absolute offset `off`. The readers below do the
    little-endian flip so callers never do it by hand.
    """

    data: bytes
    source: str = ""  # file path
    origin: str = ""  # "lspci text" or "raw image": which branch of load_config_space ran
    bdf: str | None = None  # "01:00.0" when the file had an lspci device line, else None
    description: str = ""  # lspci's first line after the BDF, if any
    lspci_text: str = ""  # lspci's decoded lines (the answer key), if any

    # @property: call it like an attribute, cs.size, not cs.size().
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

        Extended capabilities begin at offset 100h (spec 7.6.1; their header
        format is 7.6.3), so a 256-byte dump cannot contain any. Only ECAM
        (spec 7.2.2) reaches them.
        """
        return self.size > 0x100

    def _check(self, off: int, width: int) -> None:
        """Refuse a read that starts before 0, runs past the end, or has a negative width."""
        if width < 0:
            raise ValueError(f"negative width {width}")
        if off < 0 or off + width > self.size:
            raise IndexError(
                f"offset {off:#x} width {width} is outside this {self.size}-byte dump"
            )  # {off:#x} prints the offset as 0x-prefixed hex

    # u8/u16/u32 = unsigned 8-, 16-, 32-bit: one, two, or four bytes as one number.
    def u8(self, off: int) -> int:
        """The byte at absolute offset `off`."""
        self._check(off, 1)
        return self.data[off]  # indexing one position gives an int, 0-255

    def u16(self, off: int) -> int:
        """Two bytes at `off`, little-endian: bytes `de 10` at 00h read as 0x10DE."""
        self._check(off, 2)
        # data[off : off + 2] is a 2-byte slice (end is exclusive); "little" = first byte is low
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

    Rules, all of them checks on the file rather than guesses:
    - rows must start at 00: and be contiguous: each row's label must equal
      the number of bytes collected so far;
    - every row carries exactly 16 bytes, as lspci prints them;
    - the total must be one of the three frame sizes (64, 256, 4096).
    Lines that are not hex rows (lspci's decoded text) are skipped.
    """
    out = bytearray()  # a growable bytes object; bytes(out) freezes it at the end
    for lineno, line in enumerate(text.splitlines(), 1):  # line numbers from 1 for messages
        m = _HEX_ROW.match(line)
        if not m:
            continue
        label = int(m.group(1), 16)  # the label text is hex: "70" -> 112
        if label != len(out):
            raise ParseError(
                f"line {lineno}: row label {label:#x} but {len(out):#x} bytes "
                "collected so far; rows must be contiguous from 00:"
            )
        pairs = m.group(2).split()
        if len(pairs) != BYTES_PER_ROW:
            raise ParseError(
                f"line {lineno}: {len(pairs)} bytes on the row; lspci prints {BYTES_PER_ROW}"
            )
        out += bytes.fromhex(" ".join(pairs))  # "de 10 89 24" -> b"\xde\x10\x89\x24"
    if not out:
        raise ParseError("no hex rows found (expected lines like '00: de 10 89 24 ...')")
    if len(out) not in FRAME_NAMES:
        raise ParseError(
            f"{len(out)} bytes of hex rows; a dump is exactly 64, 256, or 4096 bytes"
        )
    return bytes(out)


def looks_like_lspci_text(text: str) -> bool:
    """True if at least one line is a labeled hex row."""
    return any(_HEX_ROW.match(line) for line in text.splitlines())


def split_lspci_blocks(text: str) -> list[str]:
    """Split a multi-device lspci listing into one text block per function.

    A block starts at a line that begins with a BDF ("01:00.0 ...") and runs
    until the next such line. Text before the first BDF line is dropped. A file
    with no BDF line at all is one block.
    """
    blocks: list[list[str]] = []  # one list of lines per device
    for line in text.splitlines():
        if _BDF_LINE.match(line):
            blocks.append([line])  # a new device begins
        elif blocks:
            blocks[-1].append(line)  # -1 = the most recent block
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
    decoded = [ln for ln in lines if not _HEX_ROW.match(ln)]  # everything but the hex rows
    return ConfigSpace(
        data=parse_lspci_hex(block),
        source=source,
        origin="lspci text",
        bdf=bdf,
        description=description,
        lspci_text="\n".join(decoded),
    )


def parse_lspci_all(text: str, source: str = "") -> list[ConfigSpace]:
    """Every device in a full `lspci -vvv -xxxx` listing, in file order.

    A block with no hex rows (a device lspci could not read, because -xxxx
    without root prints none) has nothing to parse and is skipped rather than
    aborting the whole file. Use skipped_lspci_blocks to name what was skipped:
    a silent skip would read as "that device is not in the file".
    """
    devices = []
    for block in split_lspci_blocks(text):
        if not looks_like_lspci_text(block):
            continue
        devices.append(parse_lspci_block(block, source))
    return devices


def skipped_lspci_blocks(text: str) -> list[str]:
    """The first line of every block parse_lspci_all had to skip, for an honest report."""
    return [block.splitlines()[0].strip() for block in split_lspci_blocks(text)
            if not looks_like_lspci_text(block) and block.strip()]


def decode_text(raw: bytes) -> str | None:
    """File bytes -> text, or None when the file is not text at all.

    UTF-8 is what Linux writes. A file that begins with the bytes FF FE or
    FE FF is UTF-16, which is what Windows PowerShell 5.1 writes for
    `ssh box "sudo lspci ..." > dump.txt`; the "utf-16" codec reads that
    marker and picks the byte order. "utf-8-sig" also strips the marker
    EF BB BF (a "byte order mark", BOM) that Notepad puts at the start of a
    UTF-8 file.
    """
    try:
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def load_config_space(path: str | Path) -> ConfigSpace:
    """Read one dump file, whichever of the accepted formats it is in.

    Detection order: if the file decodes as text and contains hex rows it is an
    lspci dump; otherwise it must be a raw binary image of exactly 64, 256, or
    4096 bytes (the three frames in FRAME_NAMES). The result records which
    branch ran in `origin`, and the CLI prints it, so nothing is silent.
    """
    p = Path(path)
    raw = p.read_bytes()
    text = decode_text(raw)

    if text is not None and looks_like_lspci_text(text):
        blocks = [b for b in split_lspci_blocks(text) if looks_like_lspci_text(b)]
        if len(blocks) > 1:
            raise ParseError(
                f"{p}: contains {len(blocks)} devices; use `pcicfg all` for a full listing"
            )
        return parse_lspci_block(blocks[0], source=str(p))

    if len(raw) in FRAME_NAMES:  # `in` on a dict checks its keys: 64, 256, 4096
        return ConfigSpace(data=raw, source=str(p), origin="raw image")

    if text is None:
        why = "not UTF-8 or UTF-16 text"
    else:
        why = "text with no hex rows (expected lines like '00: de 10 89 24 ...')"
    raise ParseError(
        f"{p}: {why}, and not a raw image either "
        f"({len(raw)} bytes; a raw image is exactly 64, 256, or 4096 bytes)"
    )
