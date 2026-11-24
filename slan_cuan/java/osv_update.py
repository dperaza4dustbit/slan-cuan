"""Re-publication of OSV advisories: bump ``modified`` only when content changes.

A re-release produces the same advisory IDs (derived from the module and its
version), and fath-cuan sets ``modified`` to the build time, like
``published``. Publishing such a record over an existing one must therefore:

- keep the published record when nothing but ``modified`` differs (no churn),
- set ``modified`` to the publication time when the content changed, so
  osv.dev and other consumers pick the update up (OSV requires ``modified``
  to move with every change).

Each sink (GitHub, Pulp) compares against its own current copy. Withdrawals
of advisories a release no longer produces stay a manual step.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Pulp label carrying the content hash of an OSV record without ``modified``;
# the Pulp content API returns labels but not file contents.
OSV_CONTENT_LABEL = "osv_content_sha256"


def publication_time() -> str:
    """Return the current UTC time in OSV timestamp form."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def osv_content_sha256(record: dict[str, Any]) -> str:
    """Hash an OSV record's content, ignoring ``modified`` and key order."""
    content = {k: v for k, v in record.items() if k != "modified"}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def same_osv_content(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Return True when two OSV records differ at most in ``modified``."""
    return osv_content_sha256(a) == osv_content_sha256(b)


def write_with_modified(
    record: dict[str, Any], modified: str, dest: Path
) -> None:
    """Write *record* to *dest* with ``modified`` set to *modified*."""
    updated = {**record, "modified": modified}
    dest.write_text(json.dumps(updated, indent=2))
