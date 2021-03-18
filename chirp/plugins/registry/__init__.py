"""Registry plugin initializer."""

from . import scan

REQUIRED_OS = "Windows"
REQUIRED_ADMIN = False
entrypoint = scan.run
