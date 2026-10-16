"""CLI subcommand implementations, one module per Tekton Task.

Ecosystem-specific commands live in their ecosystem packages
(``slan_cuan.java``, ``slan_cuan.python``); this package holds the
ecosystem-agnostic commands.
"""

from slan_cuan.java import extract, publish, sign
from slan_cuan.tasks.generate_security_metadata import (
    generate_security_metadata,
    generate_security_metadata_from_snapshot,
)
from slan_cuan.tasks.register import register

__all__ = [
    "extract",
    "generate_security_metadata",
    "generate_security_metadata_from_snapshot",
    "publish",
    "register",
    "sign",
]
