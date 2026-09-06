"""Text output. Module 1 ships only the hex view; the decoded views come later."""

from __future__ import annotations


def render_hex(data: bytes, base: int = 0) -> str:
    """Bytes, 16 per row, labeled the way `lspci -xxxx` labels them.

    `base` is the absolute offset of data[0]. With base=0 on a whole dump this
    reproduces lspci's hex block byte for byte ("00:" ... "ff0:"). `--annotate`
    will reuse it with base=0 on a capability's own bytes so that capability
    reads from 00 again (relative offsets), the way it was taught.
    """
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        rows.append(f"{base + i:02x}: " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(rows)
