"""Unit tests for the build-index filter stage functions.

The stages (:func:`load_build_index`, :func:`purls_from_index`,
:func:`apply_release_scope_filter`) are consumed by the merged
``python extract-filter`` command; end-to-end coverage of the command
itself lives in ``tests/python/extract_filter_test.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import click
import pytest

from slan_cuan.models import (
    BUILD_INDEX_MEDIA_TYPE,
    FILTER_REPORT_FILENAME,
    parse_image_ref,
)
from slan_cuan.oci import OrasError
from slan_cuan.tasks.build_index import (
    apply_release_scope_filter,
    load_build_index,
    purls_from_index,
)

DIGEST_REF = "quay.io/repo@sha256:1111"


@pytest.fixture
def payload_dir(tmp_path: Path) -> Path:
    """Sample payload directory with wheels, sdists, and sidecars."""
    p = tmp_path / "payload"
    p.mkdir()
    (p / "flask-2.0.1-py3-none-any.whl").write_bytes(b"flask wheel")
    (p / "flask-2.0.1-py3-none-any.whl.sha256").write_text("dummy sha")
    (p / "extra_pkg-0.1.0-py3-none-any.whl").write_bytes(b"extra wheel")
    (p / "companion-1.0.0.tar.gz").write_bytes(b"companion sdist")
    (p / "other-9.9.9.tar.gz").write_bytes(b"other sdist")
    # Metadata written by extract-py-artifacts: must survive filtering
    # because rh-sign-python-wheels consumes it for PEP 740 attestations.
    prov = p / "chains-provenance"
    prov.mkdir()
    (prov / "sha256:abc123.json").write_text('{"predicate": {}}')
    return p


def _wire_index(
    mock_discover: MagicMock,
    mock_pull: MagicMock,
    index_body: str,
) -> None:
    """Wire discover/pull mocks for a single-referrer build-index."""
    mock_discover.return_value = [
        {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
    ]
    mock_pull.side_effect = lambda ref, dest, **kwargs: (
        dest / "build-index.json"
    ).write_text(index_body)


class TestParseImageRef:
    """Invalid image references surface as clean CLI errors."""

    def test_invalid_ref_raises_click_exception(self) -> None:
        """An unparsable reference fails as a single-line CLI error."""
        with pytest.raises(click.ClickException, match="Invalid image reference"):
            parse_image_ref("not a valid ref")

    def test_valid_ref_parses(self) -> None:
        """A digest-pinned reference parses normally."""
        ref = parse_image_ref(DIGEST_REF)
        assert ref.digest == "sha256:1111"
        assert ref.repository == "repo"


class TestLoadBuildIndex:
    """Discovery, dedup, and pull of the build-index."""

    def test_missing_digest_in_image_ref(self) -> None:
        """Fail closed when image reference lacks a digest."""
        with pytest.raises(click.ClickException, match="must include a digest"):
            load_build_index("quay.io/repo:tag", None)

    def test_invalid_image_ref_fails_cleanly(self) -> None:
        """Fail closed with a clean error, not a raw traceback."""
        with pytest.raises(click.ClickException, match="Invalid image reference"):
            load_build_index("not a valid ref", None)

    @patch("slan_cuan.tasks.build_index.discover")
    def test_no_referrers_fails_closed(self, mock_discover: MagicMock) -> None:
        """Fail closed when no build-index referrer is discovered."""
        mock_discover.return_value = []
        with pytest.raises(
            click.ClickException, match="No build-index referrer found"
        ):
            load_build_index(DIGEST_REF, None)

    @patch("slan_cuan.tasks.build_index.manifest_fetch")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_ambiguous_referrers_fails_closed(
        self, mock_discover: MagicMock, mock_fetch: MagicMock
    ) -> None:
        """Fail closed when referrers have distinct artifact blobs."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"},
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:bbb"},
        ]
        mock_fetch.side_effect = [
            {"layers": [{"digest": "sha256:l1"}]},
            {"layers": [{"digest": "sha256:l2"}]},
        ]
        with pytest.raises(
            click.ClickException, match="found 2 distinct blob sets"
        ):
            load_build_index(DIGEST_REF, None)

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.manifest_fetch")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_duplicate_referrers_deduplicate(
        self,
        mock_discover: MagicMock,
        mock_fetch: MagicMock,
        mock_pull: MagicMock,
        payload_dir: Path,
    ) -> None:
        """Referrers sharing identical layer blob digests deduplicate."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"},
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:bbb"},
        ]
        mock_fetch.return_value = {"layers": [{"digest": "sha256:same_blob"}]}
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(json.dumps({"purls": ["pkg:pypi/Flask@2.0.1"]}))

        index_data, _ = load_build_index(DIGEST_REF, None)
        kept, removed = apply_release_scope_filter(
            payload_dir, purls_from_index(index_data), publish_all=False
        )
        assert (kept, removed) == (3, 3)
        # Chains provenance metadata must survive filtering (LWLP-3276:
        # rh-sign-python-wheels consumes it for PEP 740 attestations).
        assert (payload_dir / "chains-provenance" / "sha256:abc123.json").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_identical_manifest_digest_referrers_deduplicate(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        payload_dir: Path,
    ) -> None:
        """Referrers with identical manifest digests deduplicate."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"},
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"},
        ]
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(json.dumps({"purls": ["pkg:pypi/Flask@2.0.1"]}))

        index_data, _ = load_build_index(DIGEST_REF, None)
        kept, removed = apply_release_scope_filter(
            payload_dir, purls_from_index(index_data), publish_all=False
        )
        assert (kept, removed) == (3, 3)
        assert (payload_dir / "chains-provenance" / "sha256:abc123.json").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_missing_build_index_json_fails_closed(
        self, mock_discover: MagicMock, mock_pull: MagicMock
    ) -> None:
        """Fail closed when build-index.json is missing in pulled referrer."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        # Pull creates an arbitrary json file instead of build-index.json
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "arbitrary.json"
        ).write_text(json.dumps({"purls": []}))

        with pytest.raises(
            click.ClickException,
            match="No build-index.json found after pulling referrer",
        ):
            load_build_index(DIGEST_REF, None)

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_malformed_build_index_fails_closed(
        self, mock_discover: MagicMock, mock_pull: MagicMock
    ) -> None:
        """Fail closed when build-index.json is not valid JSON."""
        _wire_index(mock_discover, mock_pull, "not json{")

        with pytest.raises(
            click.ClickException, match="Failed to parse build-index.json"
        ):
            load_build_index(DIGEST_REF, None)

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_non_object_build_index_fails_closed(
        self, mock_discover: MagicMock, mock_pull: MagicMock
    ) -> None:
        """Fail closed when build-index.json is not a JSON object."""
        _wire_index(mock_discover, mock_pull, json.dumps(["not", "a", "dict"]))

        with pytest.raises(
            click.ClickException, match="Expected JSON object in build-index.json"
        ):
            load_build_index(DIGEST_REF, None)

    @patch("slan_cuan.tasks.build_index.deduplicate_referrers")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_deduplicate_referrers_oras_error_handling(
        self, mock_discover: MagicMock, mock_dedup: MagicMock
    ) -> None:
        """Wrap OrasError from deduplicate_referrers into ClickException."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        mock_dedup.side_effect = OrasError(
            "failed to inspect manifest", "raw error", 1
        )

        with pytest.raises(
            click.ClickException, match="OCI error: failed to inspect manifest"
        ):
            load_build_index(DIGEST_REF, None)


class TestPurlsFromIndex:
    """Extraction and validation of the purls allow-list."""

    def test_extracts_purls(self) -> None:
        """The purls list is returned as-is."""
        assert purls_from_index({"purls": ["pkg:pypi/a@1"]}) == ["pkg:pypi/a@1"]

    def test_missing_purls_defaults_to_empty(self) -> None:
        """An index without purls yields an empty allow-list."""
        assert purls_from_index({}) == []

    def test_non_list_purls_fails_closed(self) -> None:
        """Fail closed when purls is not a list."""
        with pytest.raises(click.ClickException, match="'purls' to be a list"):
            purls_from_index({"purls": "nope"})

    def test_non_string_entry_fails_closed(self) -> None:
        """Fail closed when a purls entry is not a string."""
        with pytest.raises(click.ClickException, match="must be strings"):
            purls_from_index({"purls": [42]})


class TestApplyReleaseScopeFilter:
    """The payload filtering engine."""

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_filtering_keeps_purls_removes_extras(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        payload_dir: Path,
    ) -> None:
        """Filter keeps purls artifacts and removes extras and non-matches."""
        index_content = {
            "purls": [
                "pkg:pypi/Flask@2.0.1",
                "pkg:pypi/companion@1.0.0",
            ],
            "extraPurls": [
                "pkg:pypi/extra-pkg@0.1.0",
            ],
        }
        _wire_index(mock_discover, mock_pull, json.dumps(index_content))

        index_data, digest = load_build_index(DIGEST_REF, None)
        kept, removed = apply_release_scope_filter(
            payload_dir,
            purls_from_index(index_data),
            publish_all=False,
            build_index_digest=digest,
        )
        assert (kept, removed) == (4, 2)

        # Verify kept files
        assert (payload_dir / "flask-2.0.1-py3-none-any.whl").exists()
        assert (payload_dir / "flask-2.0.1-py3-none-any.whl.sha256").exists()
        assert (payload_dir / "companion-1.0.0.tar.gz").exists()
        assert not (payload_dir / "extra_pkg-0.1.0-py3-none-any.whl").exists()
        assert not (payload_dir / "other-9.9.9.tar.gz").exists()
        # Metadata passes through untouched (signing consumes it downstream)
        assert (payload_dir / "chains-provenance" / "sha256:abc123.json").exists()

        # Verify removed sibling dir
        filtered_dir = payload_dir.parent / f"{payload_dir.name}-filtered"
        assert (filtered_dir / "extra_pkg-0.1.0-py3-none-any.whl").exists()
        assert (filtered_dir / "other-9.9.9.tar.gz").exists()

        # Verify filter-report.json
        report_file = payload_dir.parent / FILTER_REPORT_FILENAME
        assert report_file.exists()
        report = json.loads(report_file.read_text())
        assert report["kept_count"] == 4
        assert report["removed_count"] == 2
        assert "consumed_build_index_digest" in report

    def test_unmappable_purl_fails_closed(self, payload_dir: Path) -> None:
        """A purl that yields no filename candidates is a hard error.

        If we cannot map a purl to filename candidates, its artifacts would
        be treated as out-of-scope and removed -- wrong for in-scope content.
        Wrong-ecosystem purls (e.g. maven) and versionless purls land here.
        """
        with pytest.raises(click.ClickException) as excinfo:
            apply_release_scope_filter(
                payload_dir,
                ["pkg:pypi/Flask@2.0.1", "pkg:maven/org.apache/x@1.0"],
                publish_all=False,
            )
        assert "no filename candidates" in str(excinfo.value)
        assert "pkg:maven/org.apache/x@1.0" in str(excinfo.value)
        # Nothing was touched on disk
        assert (payload_dir / "flask-2.0.1-py3-none-any.whl").exists()

    def test_non_distribution_files_pass_through(self, payload_dir: Path) -> None:
        """Only distribution-shaped files are removed; metadata survives.

        extract-py-artifacts writes chains-provenance/ into the payload dir
        and rh-sign-python-wheels (running after this filter in calunga)
        consumes it to build PEP 740 attestations. Removing it would
        silently downgrade attestations to the minimal predicate fallback.
        """
        kept, removed = apply_release_scope_filter(
            payload_dir, ["pkg:pypi/Flask@2.0.1"], publish_all=False
        )
        assert (kept, removed) == (3, 3)
        prov = payload_dir / "chains-provenance" / "sha256:abc123.json"
        assert prov.exists()
        assert prov.read_text() == '{"predicate": {}}'
        filtered_dir = payload_dir.parent / f"{payload_dir.name}-filtered"
        assert not (filtered_dir / "chains-provenance").exists()

    def test_publish_all_keeps_everything(self, payload_dir: Path) -> None:
        """Publish-all keeps all artifacts regardless of index purls."""
        kept, removed = apply_release_scope_filter(
            payload_dir, [], publish_all=True
        )
        assert (kept, removed) == (6, 0)
        assert (payload_dir / "extra_pkg-0.1.0-py3-none-any.whl").exists()

    def test_dry_run_leaves_files_untouched(
        self, payload_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Dry-run reports file decisions without modifying the filesystem."""
        kept, removed = apply_release_scope_filter(
            payload_dir, ["pkg:pypi/flask@2.0.1"], publish_all=False, dry_run=True
        )
        assert (kept, removed) == (3, 3)
        assert "dry-run: would keep" in capsys.readouterr().out
        # Everything still in payload_dir
        assert (payload_dir / "extra_pkg-0.1.0-py3-none-any.whl").exists()
        assert not (payload_dir.parent / f"{payload_dir.name}-filtered").exists()
        assert not (payload_dir.parent / FILTER_REPORT_FILENAME).exists()
