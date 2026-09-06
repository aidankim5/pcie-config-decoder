"""Lets `py -m pcicfg ...` work without installing the package."""

from .cli import main

# SystemExit(n) ends the program with n as the exit code the shell sees.
raise SystemExit(main())
