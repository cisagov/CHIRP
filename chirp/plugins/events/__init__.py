"""Event plugin initializer."""

from . import scan

REQUIRED_OS = "Windows"
REQUIRED_ADMIN = True
entrypoint = scan.run
