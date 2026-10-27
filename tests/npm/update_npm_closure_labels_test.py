"""Unit tests for Pulp label digest-lock in update-npm-closure."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "npm" / "update-npm-closure"
)


def _load_closure_module() -> Any:
    """Load the standalone update-npm-closure script as a module."""
    name = "update_npm_closure_under_test"
    # Script has no .py suffix; SourceFileLoader still executes it.
    loader = importlib.machinery.SourceFileLoader(name, str(_SCRIPT))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def closure() -> Any:
    """Provide a freshly loaded update-npm-closure module."""
    return _load_closure_module()


def _content(labels: dict[str, str]) -> dict[str, Any]:
    return {
        "pulp_href": "/api/pulp/test/api/v3/content/npm/packages/abc/",
        "pulp_labels": dict(labels),
        "name": "express",
        "version": "4.22.0",
    }


def test_monotone_target_level_never_downgrades(closure: Any) -> None:
    """Sticky levels keep the higher of current vs desired."""
    assert closure._monotone_target_level("L3", "L1") == "L3"
    assert closure._monotone_target_level("L1", "L2") == "L2"
    assert closure._monotone_target_level("", "L2") == "L2"


def test_sync_labels_noop_when_already_matching(closure: Any) -> None:
    """Skip set_label when digest and level already match."""
    digest = "sha256:" + ("a" * 64)
    row = _content(
        {
            "tl.compliance_oci_digest": digest,
            "tl.compliance_level": "L2",
        }
    )
    with (
        patch.object(closure, "find_content_in_repo", return_value=row) as find,
        patch.object(closure, "set_pulp_label") as set_label,
    ):
        closure.sync_content_pulp_labels(
            row["pulp_href"],
            "/repo/versions/1/",
            "express",
            "4.22.0",
            "L2",
            digest,
        )
    set_label.assert_not_called()
    assert find.call_count == 1


def test_sync_labels_writes_digest_before_level(closure: Any) -> None:
    """Claim digest, verify, then write level; digest precedes level."""
    digest = "sha256:" + ("b" * 64)
    href = "/api/pulp/test/api/v3/content/npm/packages/abc/"
    empty = _content({})
    digest_only = _content({"tl.compliance_oci_digest": digest})
    both = _content(
        {
            "tl.compliance_oci_digest": digest,
            "tl.compliance_level": "L1",
        }
    )
    with (
        patch.object(
            closure,
            "find_content_in_repo",
            # initial → after digest write → before level → final
            side_effect=[empty, digest_only, digest_only, both],
        ),
        patch.object(closure, "set_pulp_label") as set_label,
    ):
        closure.sync_content_pulp_labels(
            href, "/repo/versions/1/", "express", "4.22.0", "L1", digest
        )
    assert set_label.call_count == 2
    keys = [c.args[1] for c in set_label.call_args_list]
    assert keys == ["tl.compliance_oci_digest", "tl.compliance_level"]


def test_sync_labels_fails_closed_on_digest_race_after_digest_write(
    closure: Any,
) -> None:
    """If post-digest verify sees another digest, exit before writing level."""
    wanted = "sha256:" + ("c" * 64)
    other = "sha256:" + ("d" * 64)
    href = "/api/pulp/test/api/v3/content/npm/packages/abc/"
    before = _content({})
    raced = _content(
        {
            "tl.compliance_oci_digest": other,
            "tl.compliance_level": "L2",
        }
    )
    with (
        patch.object(
            closure, "find_content_in_repo", side_effect=[before, raced]
        ),
        patch.object(closure, "set_pulp_label") as set_label,
        pytest.raises(SystemExit, match="Pulp label digest race") as exc,
    ):
        closure.sync_content_pulp_labels(
            href, "/repo/versions/1/", "express", "4.22.0", "L1", wanted
        )
    assert wanted in str(exc.value)
    assert other in str(exc.value)
    # Digest write attempted once; level must not be written.
    assert set_label.call_count == 1
    assert set_label.call_args.args[1] == "tl.compliance_oci_digest"


def test_sync_labels_refuses_level_downgrade(closure: Any) -> None:
    """When digest already matches, do not write a lower compliance level."""
    digest = "sha256:" + ("e" * 64)
    row = _content(
        {
            "tl.compliance_oci_digest": digest,
            "tl.compliance_level": "L3",
        }
    )
    with (
        patch.object(closure, "find_content_in_repo", return_value=row),
        patch.object(closure, "set_pulp_label") as set_label,
    ):
        closure.sync_content_pulp_labels(
            row["pulp_href"],
            "/repo/versions/1/",
            "express",
            "4.22.0",
            "L1",
            digest,
        )
    set_label.assert_not_called()


def test_sync_labels_preserves_higher_level_seen_before_level_write(
    closure: Any,
) -> None:
    """Bruno race: after claiming digest, re-read sees L3 → do not write L2."""
    digest = "sha256:" + ("f" * 64)
    href = "/api/pulp/test/api/v3/content/npm/packages/abc/"
    empty = _content({})
    digest_only = _content({"tl.compliance_oci_digest": digest})
    # Concurrent writer raised level to L3 while we held the digest.
    digest_and_l3 = _content(
        {
            "tl.compliance_oci_digest": digest,
            "tl.compliance_level": "L3",
        }
    )
    with (
        patch.object(
            closure,
            "find_content_in_repo",
            side_effect=[empty, digest_only, digest_and_l3, digest_and_l3],
        ),
        patch.object(closure, "set_pulp_label") as set_label,
    ):
        closure.sync_content_pulp_labels(
            href, "/repo/versions/1/", "express", "4.22.0", "L2", digest
        )
    keys = [c.args[1] for c in set_label.call_args_list]
    assert keys == ["tl.compliance_oci_digest"]
    assert "tl.compliance_level" not in keys


def test_sync_labels_aborts_level_if_digest_lost_before_level_write(
    closure: Any,
) -> None:
    """If digest changes before level write, fail closed without setting level."""
    wanted = "sha256:" + ("1" * 64)
    other = "sha256:" + ("2" * 64)
    href = "/api/pulp/test/api/v3/content/npm/packages/abc/"
    empty = _content({})
    ours = _content({"tl.compliance_oci_digest": wanted})
    stolen = _content(
        {
            "tl.compliance_oci_digest": other,
            "tl.compliance_level": "L3",
        }
    )
    with (
        patch.object(
            closure,
            "find_content_in_repo",
            side_effect=[empty, ours, stolen],
        ),
        patch.object(closure, "set_pulp_label") as set_label,
        pytest.raises(SystemExit, match="Pulp label digest race"),
    ):
        closure.sync_content_pulp_labels(
            href, "/repo/versions/1/", "express", "4.22.0", "L2", wanted
        )
    keys = [c.args[1] for c in set_label.call_args_list]
    assert keys == ["tl.compliance_oci_digest"]
