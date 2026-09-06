"""Lets `py -m pcicfg ...` work without installing the package."""

from .cli import main

raise SystemExit(main())
