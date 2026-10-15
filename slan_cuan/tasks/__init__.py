"""CLI subcommand implementations, one module per Tekton Task."""

from slan_cuan.tasks.build_index import build_index_filter
from slan_cuan.tasks.extract import extract
from slan_cuan.tasks.generate_security_metadata import (
    generate_security_metadata,
    generate_security_metadata_from_snapshot,
)
from slan_cuan.tasks.publish import publish
from slan_cuan.tasks.register import register
from slan_cuan.tasks.sign import sign

__all__ = [
    "build_index_filter",
    "extract",
    "generate_security_metadata",
    "generate_security_metadata_from_snapshot",
    "publish",
    "register",
    "sign",
]
