"""Tests for OSV re-publication helpers (slan_cuan/java/osv_update.py)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from slan_cuan.java.osv_update import (
    osv_content_sha256,
    publication_time,
    same_osv_content,
    write_with_modified,
)

_RECORD = {
    "id": "RHLW-2026-33400e52ea4f277c",
    "published": "2026-11-13T18:59:33Z",
    "modified": "2026-11-13T18:59:33Z",
    "upstream": ["CVE-2026-19880"],
}


def test_content_hash_ignores_modified_and_key_order() -> None:
    """Only a content change, not modified or key order, changes the hash."""
    reordered = dict(
        reversed(list({**_RECORD, "modified": "2027-01-01T00:00:00Z"}.items()))
    )
    assert osv_content_sha256(reordered) == osv_content_sha256(_RECORD)
    assert same_osv_content(reordered, _RECORD)
    changed = {**_RECORD, "upstream": ["CVE-2026-19880", "CVE-2024-12798"]}
    assert not same_osv_content(changed, _RECORD)


def test_write_with_modified_keeps_everything_else(tmp_path: Path) -> None:
    """Only modified changes; published and key order stay."""
    dest = tmp_path / "r.json"
    write_with_modified(_RECORD, "2026-11-20T12:00:00Z", dest)

    written = json.loads(dest.read_text())
    assert list(written) == list(_RECORD)
    assert written == {**_RECORD, "modified": "2026-11-20T12:00:00Z"}


def test_publication_time_is_an_osv_timestamp() -> None:
    """The publication time uses the OSV timestamp form."""
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", publication_time())
