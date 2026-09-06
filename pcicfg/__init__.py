"""pcicfg: read and decode PCI Express configuration space.

Layer 1 (this package, stdlib only): decode a 256- or 4096-byte dump.
Layer 2 (pcicfg.win.enum): list PCI functions on Windows with no driver.
Layer 3 (pcicfg.win.raw): raw reads on Windows through a signed driver, optional.
"""

__version__ = "0.1.0"
