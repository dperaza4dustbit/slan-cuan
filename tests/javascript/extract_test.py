"""Tests for the javascript extract command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.javascript.provenance import NPM_PREDICATE_TYPES
from slan_cuan.oci import OrasError

IMAGE_A = "quay.io/repo/npm-a@sha256:" + "11" * 32
IMAGE_B = "quay.io/repo/npm-b@sha256:" + "22" * 32

_PULL = "slan_cuan.javascript.extract.pull"
_FETCH = "slan_cuan.javascript.extract.fetch_chains_provenance"


def _make_snapshot(tmp_path: Path, images: list[str]) -> Path:
    snapshot = tmp_path / "snapshot_spec.json"
    snapshot.write_text(
        json.dumps({"components": [{"containerImage": i} for i in images]})
    )
    return snapshot


@pytest.fixture
def runner() -> CliRunner:
    """Return CLI runner fixture."""
    return CliRunner()


class TestJavascriptExtractCommand:
    """CLI-level tests with mocked pull/provenance fetch."""

    @patch(_FETCH)
    @patch(_PULL)
    def test_extract_pulls_each_image_into_digest_namespaced_dir(
        self,
        mock_pull: MagicMock,
        mock_fetch: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Each image is pulled into files_dir/<digest_safe>."""
        snapshot = _make_snapshot(tmp_path, [IMAGE_A, IMAGE_B])
        files_dir = tmp_path / "files"

        res = runner.invoke(
            main,
            [
                "javascript",
                "extract",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(files_dir),
            ],
        )

        assert res.exit_code == 0, res.output
        assert mock_pull.call_count == 2
        called_dirs = {call.args[1] for call in mock_pull.call_args_list}
        assert called_dirs == {
            files_dir / ("sha256_" + "11" * 32),
            files_dir / ("sha256_" + "22" * 32),
        }

    @patch(_FETCH)
    @patch(_PULL)
    def test_extract_rejects_tag_only_image_reference(
        self,
        mock_pull: MagicMock,
        mock_fetch: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """A tag-only image reference (no digest) is rejected before pull."""
        snapshot = _make_snapshot(tmp_path, ["quay.io/repo/npm-a:latest"])
        files_dir = tmp_path / "files"

        res = runner.invoke(
            main,
            [
                "javascript",
                "extract",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(files_dir),
            ],
        )

        assert res.exit_code != 0
        mock_pull.assert_not_called()
        mock_fetch.assert_not_called()

    @patch(_FETCH)
    @patch(_PULL)
    def test_extract_fetches_provenance_per_image_with_npm_predicate_types(
        self,
        mock_pull: MagicMock,
        mock_fetch: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Provenance is fetched per image with npm predicate types/selector."""
        snapshot = _make_snapshot(tmp_path, [IMAGE_A, IMAGE_B])
        files_dir = tmp_path / "files"

        res = runner.invoke(
            main,
            [
                "javascript",
                "extract",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(files_dir),
            ],
        )

        assert res.exit_code == 0, res.output
        assert mock_fetch.call_count == 2
        for call in mock_fetch.call_args_list:
            assert call.kwargs["predicate_types"] == NPM_PREDICATE_TYPES
            select = call.kwargs["select"]
            assert callable(select)

        # The selector for IMAGE_A should accept a matching candidate and
        # return it unchanged.
        first_call = mock_fetch.call_args_list[0]
        select_a = first_call.kwargs["select"]
        matching_candidate = {
            "predicate": {
                "builder": {"id": "https://tekton.dev/chains/v2"},
                "buildType": "tekton.dev/v1/PipelineRun",
                "invocation": {
                    "environment": {
                        "labels": {
                            "pipelines.openshift.io/runtime": "build-npm",
                        },
                        "annotations": {
                            "pipelinesascode.tekton.dev/log-url": (
                                "https://console.example/ns/calunga-tenant/runs/1"
                            ),
                        },
                    }
                },
            },
            "subject": [{"name": "image", "digest": {"sha256": "11" * 32}}],
        }
        assert select_a([matching_candidate]) is matching_candidate

    @patch(_FETCH)
    @patch(_PULL)
    def test_extract_dry_run_skips_pull_and_provenance(
        self,
        mock_pull: MagicMock,
        mock_fetch: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Dry-run previews the plan without touching network/filesystem."""
        snapshot = _make_snapshot(tmp_path, [IMAGE_A])
        files_dir = tmp_path / "files"

        res = runner.invoke(
            main,
            [
                "--dry-run",
                "javascript",
                "extract",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(files_dir),
            ],
        )

        assert res.exit_code == 0, res.output
        assert f"Would extract {IMAGE_A}" in res.output
        mock_pull.assert_not_called()
        mock_fetch.assert_not_called()
        assert not files_dir.exists()

    @patch(_FETCH)
    @patch(_PULL)
    def test_extract_oras_error_becomes_click_exception(
        self,
        mock_pull: MagicMock,
        mock_fetch: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """An OrasError from pull() surfaces as a ClickException."""
        mock_pull.side_effect = OrasError("boom", stderr="boom", returncode=1)
        snapshot = _make_snapshot(tmp_path, [IMAGE_A])
        files_dir = tmp_path / "files"

        res = runner.invoke(
            main,
            [
                "javascript",
                "extract",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(files_dir),
            ],
        )

        assert res.exit_code != 0
        assert "OCI error" in res.output
        mock_fetch.assert_not_called()
