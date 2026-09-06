"""Text output. Module 1 ships only the hex view; the decoded views come later."""


def render_hex(data: bytes, base: int = 0) -> str:
    """Bytes, 16 per row, labeled the way `lspci -xxxx` labels them.

    `base` is the absolute offset of data[0]. With base=0 on a whole dump this
    reproduces lspci's hex block byte for byte ("00:" ... "ff0:"). `--annotate`
    will reuse it with base=0 on a capability's own bytes so that capability
    reads from 00 again (relative offsets), the way it was taught.
    """
    rows = []
    for i in range(0, len(data), 16):  # i = index of each row's first byte: 0, 16, 32, ...
        chunk = data[i : i + 16]
        # :02x = lowercase hex, at least 2 digits, zero-padded ("0a" not "a").
        # Labels 0x100 and up grow to 3 digits by themselves, matching lspci's "100:" ... "ff0:".
        label = f"{base + i:02x}:"
        rows.append(label + " " + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(rows)
