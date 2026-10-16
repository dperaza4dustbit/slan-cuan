"""Unit tests for the build-index-filter task and helper functions."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.models import (
    BUILD_INDEX_MEDIA_TYPE,
    FILTER_REPORT_FILENAME,
)
from slan_cuan.tasks.build_index import (
    canonicalize_name,
    get_base_artifact_filename,
    get_purl_candidate_patterns,
    matches_any_candidate,
    parse_pypi_purl,
)


class TestHelpers:
    """Tests for coordinate and purl parsing helper functions."""

    def test_canonicalize_name(self) -> None:
        """Canonicalize package names per PEP 503."""
        assert canonicalize_name("Foo_Bar.Baz") == "foo-bar-baz"
        assert canonicalize_name("my--package..name") == "my-package-name"
        assert canonicalize_name("simple") == "simple"

    def test_parse_pypi_purl(self) -> None:
        """Parse PyPI PURLs into canonical name and version."""
        assert parse_pypi_purl("pkg:pypi/Flask@2.0.1") == ("flask", "2.0.1")
        assert parse_pypi_purl("pkg:pypi/my_pkg@1.0.0?extension=whl") == (
            "my-pkg",
            "1.0.0",
        )
        assert parse_pypi_purl("pkg:maven/org.example/artifact@1.0.0") is None
        assert parse_pypi_purl("invalid-purl") is None

    def test_get_base_artifact_filename(self) -> None:
        """Strip checksum and signature sidecar extensions."""
        assert (
            get_base_artifact_filename("foo-1.0-py3-none-any.whl.sha256")
            == "foo-1.0-py3-none-any.whl"
        )
        assert (
            get_base_artifact_filename("foo-1.0.tar.gz.asc") == "foo-1.0.tar.gz"
        )
        assert (
            get_base_artifact_filename("foo-1.0-py3-none-any.whl")
            == "foo-1.0-py3-none-any.whl"
        )

    def test_get_purl_candidate_patterns_and_matching(self) -> None:
        """Test candidate generation and matching across PEP 427/440 variants."""
        # Standard purl
        pats = get_purl_candidate_patterns("pkg:pypi/foo-bar@1.2.3")
        assert "foo_bar-1.2.3-py3-none-any.whl" in pats
        assert "foo_bar-1.2.3-*.whl" in pats
        assert "foo-bar-1.2.3.tar.gz" in pats
        assert "foo_bar-1.2.3.tar.gz" in pats
        assert matches_any_candidate("foo_bar-1.2.3-py3-none-any.whl", pats)
        assert matches_any_candidate(
            "foo_bar-1.2.3-py3-none-any.whl.sha512", pats
        )
        assert matches_any_candidate("foo-bar-1.2.3.tar.gz", pats)
        assert matches_any_candidate("foo_bar-1.2.3.tar.gz.sig", pats)

        # Hyphenated version sdist
        pats_hyphen = get_purl_candidate_patterns("pkg:pypi/my-pkg@1.0.0-beta")
        assert "my_pkg-1.0.0_beta-*.whl" in pats_hyphen
        assert "my-pkg-1.0.0-beta.tar.gz" in pats_hyphen
        assert "my_pkg-1.0.0-beta.tar.gz" in pats_hyphen
        assert matches_any_candidate("my-pkg-1.0.0-beta.tar.gz", pats_hyphen)
        assert matches_any_candidate("my_pkg-1.0.0-beta.tar.gz", pats_hyphen)

        # Local version wheel: '+' and '.' in local versions escaped to '_'
        pats_local = get_purl_candidate_patterns("pkg:pypi/my-pkg@1.0.0+rhlw.1")
        assert "my_pkg-1.0.0_rhlw.1-py3-none-any.whl" in pats_local
        assert "my_pkg-1.0.0_rhlw.1-*.whl" in pats_local
        assert matches_any_candidate(
            "my_pkg-1.0.0_rhlw.1-py3-none-any.whl", pats_local
        )
        assert matches_any_candidate(
            "my_pkg-1.0.0_rhlw.1-cp39-cp39-linux_x86_64.whl",
            pats_local,
        )

        # Case variants
        assert matches_any_candidate("Foo_Bar-1.2.3-py3-none-any.whl", pats)
        assert matches_any_candidate("FOO-BAR-1.2.3.TAR.GZ", pats)

        # Multi-glob wheel tags
        assert matches_any_candidate(
            "foo_bar-1.2.3-cp311-cp311-manylinux_2_17_x86_64.whl",
            pats,
        )

        # Unmatched / unknown files
        assert not matches_any_candidate("random-file.txt", pats)
        assert not matches_any_candidate("invalid.whl", pats)
        assert not matches_any_candidate("other-1.2.3.tar.gz", pats)


class TestBuildIndexFilterCommand:
    """Tests for the build-index-filter CLI subcommand."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Return CLI runner fixture."""
        return CliRunner()

    @pytest.fixture
    def payload_dir(self, tmp_path: Path) -> Path:
        """Create sample payload directory with wheels, sdists, and sidecars."""
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

    def test_missing_digest_in_image_ref(
        self, runner: CliRunner, payload_dir: Path
    ) -> None:
        """Fail closed when image reference lacks a digest."""
        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo:tag",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code != 0
        assert "must include a digest" in res.output

    def test_payload_dir_not_found(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Fail closed when payload directory does not exist."""
        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(tmp_path / "missing"),
            ],
        )
        assert res.exit_code != 0
        assert "does not exist" in res.output

    @patch("slan_cuan.tasks.build_index.discover")
    def test_no_referrers_fails_closed(
        self, mock_discover: MagicMock, runner: CliRunner, payload_dir: Path
    ) -> None:
        """Fail closed when no build-index referrer is discovered."""
        mock_discover.return_value = []
        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code != 0
        assert "No build-index referrer found" in res.output

    @patch("slan_cuan.tasks.build_index.manifest_fetch")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_ambiguous_referrers_fails_closed(
        self,
        mock_discover: MagicMock,
        mock_fetch: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
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
        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code != 0
        assert "found 2 distinct blob sets" in res.output

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.manifest_fetch")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_duplicate_referrers_deduplicate(
        self,
        mock_discover: MagicMock,
        mock_fetch: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """Deduplicate referrers sharing identical layer blob digests."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"},
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:bbb"},
        ]
        mock_fetch.return_value = {"layers": [{"digest": "sha256:same_blob"}]}
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(json.dumps({"purls": ["pkg:pypi/Flask@2.0.1"]}))

        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "Filtered payload: 3 kept, 3 removed." in res.output

        # Chains provenance metadata must survive filtering (LWLP-3276:
        # rh-sign-python-wheels consumes it for PEP 740 attestations).
        assert (payload_dir / "chains-provenance" / "sha256:abc123.json").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_identical_manifest_digest_referrers_deduplicate(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """Deduplicate referrers with identical manifest digests."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"},
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"},
        ]
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(json.dumps({"purls": ["pkg:pypi/Flask@2.0.1"]}))

        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "Filtered payload: 3 kept, 3 removed." in res.output

        # Chains provenance metadata must survive filtering (LWLP-3276:
        # rh-sign-python-wheels consumes it for PEP 740 attestations).
        assert (payload_dir / "chains-provenance" / "sha256:abc123.json").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.manifest_fetch")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_filtering_keeps_purls_removes_extras(
        self,
        mock_discover: MagicMock,
        mock_fetch: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Filter keeps purls artifacts and removes extras and non-matches."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]

        index_content = {
            "purls": [
                "pkg:pypi/Flask@2.0.1",
                "pkg:pypi/companion@1.0.0",
            ],
            "extraPurls": [
                "pkg:pypi/extra-pkg@0.1.0",
            ],
        }

        def fake_pull(ref_image, dest_path, **kwargs):
            (dest_path / "build-index.json").write_text(json.dumps(index_content))

        mock_pull.side_effect = fake_pull

        results_dir = tmp_path / "tekton-results"
        results_dir.mkdir()

        res = runner.invoke(
            main,
            [
                "--tekton-results-dir",
                str(results_dir),
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "Filtered payload: 4 kept, 2 removed." in res.output

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

        # Verify Tekton results
        assert (results_dir / "KEPT_COUNT").read_text() == "4"
        assert (results_dir / "REMOVED_COUNT").read_text() == "2"
        assert (results_dir / "CONSUMED_BUILD_INDEX_DIGEST").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_unmappable_purl_fails_closed(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """A purl that yields no filename candidates is a hard error.

        If we cannot map a purl to filename candidates, its artifacts would
        be treated as out-of-scope and removed -- wrong for in-scope content.
        Wrong-ecosystem purls (e.g. maven) and versionless purls land here.
        """
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(
            json.dumps(
                {"purls": ["pkg:pypi/Flask@2.0.1", "pkg:maven/org.apache/x@1.0"]}
            )
        )

        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code != 0
        assert "no filename candidates" in res.output
        assert "pkg:maven/org.apache/x@1.0" in res.output
        # Nothing was touched on disk
        assert (payload_dir / "flask-2.0.1-py3-none-any.whl").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_non_distribution_files_pass_through(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """Only distribution-shaped files are removed; metadata survives.

        extract-py-artifacts writes chains-provenance/ into the payload dir
        and rh-sign-python-wheels (running after this filter in calunga)
        consumes it to build PEP 740 attestations. Removing it would
        silently downgrade attestations to the minimal predicate fallback.
        """
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(json.dumps({"purls": ["pkg:pypi/Flask@2.0.1"]}))

        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code == 0, res.output
        prov = payload_dir / "chains-provenance" / "sha256:abc123.json"
        assert prov.exists()
        assert prov.read_text() == '{"predicate": {}}'
        filtered_dir = payload_dir.parent / f"{payload_dir.name}-filtered"
        assert not (filtered_dir / "chains-provenance").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_publish_all_keeps_everything(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """Publish-all keeps all artifacts regardless of index purls."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(json.dumps({"purls": []}))

        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
                "--publish-all",
            ],
        )
        assert res.exit_code == 0, res.output
        assert "Filtered payload: 6 kept, 0 removed." in res.output
        assert (payload_dir / "extra_pkg-0.1.0-py3-none-any.whl").exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_dry_run_leaves_files_untouched(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """Dry-run reports file decisions without modifying the filesystem."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "build-index.json"
        ).write_text(json.dumps({"purls": ["pkg:pypi/flask@2.0.1"]}))

        res = runner.invoke(
            main,
            [
                "--dry-run",
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "dry-run: would keep" in res.output
        # Everything still in payload_dir
        assert (payload_dir / "extra_pkg-0.1.0-py3-none-any.whl").exists()
        assert not (payload_dir.parent / f"{payload_dir.name}-filtered").exists()
        assert not (payload_dir.parent / FILTER_REPORT_FILENAME).exists()

    @patch("slan_cuan.tasks.build_index.pull")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_missing_build_index_json_fails_closed(
        self,
        mock_discover: MagicMock,
        mock_pull: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """Fail closed when build-index.json is missing in pulled referrer."""
        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        # Pull creates an arbitrary json file instead of build-index.json
        mock_pull.side_effect = lambda ref, dest, **kwargs: (
            dest / "arbitrary.json"
        ).write_text(json.dumps({"purls": []}))

        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code != 0
        assert "No build-index.json found after pulling referrer" in res.output

    @patch("slan_cuan.tasks.build_index.deduplicate_referrers")
    @patch("slan_cuan.tasks.build_index.discover")
    def test_deduplicate_referrers_oras_error_handling(
        self,
        mock_discover: MagicMock,
        mock_dedup: MagicMock,
        runner: CliRunner,
        payload_dir: Path,
    ) -> None:
        """Wrap OrasError from deduplicate_referrers into ClickException."""
        from slan_cuan.oci import OrasError

        mock_discover.return_value = [
            {"artifactType": BUILD_INDEX_MEDIA_TYPE, "digest": "sha256:aaa"}
        ]
        mock_dedup.side_effect = OrasError(
            "failed to inspect manifest", "raw error", 1
        )

        res = runner.invoke(
            main,
            [
                "build-index-filter",
                "--image-ref",
                "quay.io/repo@sha256:1111",
                "--payload-dir",
                str(payload_dir),
            ],
        )
        assert res.exit_code != 0
        assert "OCI error: failed to inspect manifest" in res.output
