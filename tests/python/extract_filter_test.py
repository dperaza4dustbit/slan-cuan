"""Tests for the merged python extract-filter command."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.models import FILTER_REPORT_FILENAME

IMAGE = "quay.io/repo/wheels@sha256:1111"

_PULL = "slan_cuan.python.extract_filter.pull"
_RUN = "slan_cuan.provenance.subprocess.run"
_LOAD = "slan_cuan.python.extract_filter.load_build_index"


def _envelope_stdout(payload: dict) -> str:
    """Build cosign verify-attestation stdout for one DSSE envelope."""
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return json.dumps({"payload": encoded}) + "\n"


def _make_snapshot(tmp_path: Path, images: list[str]) -> Path:
    snapshot = tmp_path / "snapshot_spec.json"
    snapshot.write_text(
        json.dumps({"components": [{"containerImage": i} for i in images]})
    )
    return snapshot


class TestExtractFilterCommand:
    """End-to-end command tests with mocked OCI and cosign calls."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Return CLI runner fixture."""
        return CliRunner()

    def _wire(
        self,
        mock_pull: MagicMock,
        mock_run: MagicMock,
        mock_load: MagicMock,
        payload_files: dict[str, bytes],
    ) -> None:
        """Wire pull/cosign/load_build_index side effects."""

        def fake_pull(img_ref, output_dir, **kwargs):
            for name, content in payload_files.items():
                (output_dir / name).write_bytes(content)

        mock_pull.side_effect = fake_pull
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_envelope_stdout({"predicate": {}}), stderr=""
        )
        mock_load.return_value = (
            {"purls": ["pkg:pypi/Flask@2.0.1"]},
            "sha256:cafe",
        )

    @patch(_LOAD)
    @patch(_RUN)
    @patch(_PULL)
    def test_extracts_fetches_provenance_and_filters(
        self,
        mock_pull: MagicMock,
        mock_run: MagicMock,
        mock_load: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Extract, fetch provenance, and filter in one command."""
        self._wire(
            mock_pull,
            mock_run,
            mock_load,
            {
                "flask-2.0.1-py3-none-any.whl": b"flask",
                "other-9.9.9.tar.gz": b"other",
            },
        )
        snapshot = _make_snapshot(tmp_path, [IMAGE])
        files_dir = tmp_path / "files"
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        res = runner.invoke(
            main,
            [
                "--tekton-results-dir",
                str(results_dir),
                "python",
                "extract-filter",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(files_dir),
            ],
        )
        assert res.exit_code == 0, res.output
        assert "Filtered payload: 2 kept, 1 removed." in res.output

        # In-scope wheel kept, out-of-scope sdist moved, provenance saved
        assert (files_dir / "flask-2.0.1-py3-none-any.whl").exists()
        assert not (files_dir / "other-9.9.9.tar.gz").exists()
        filtered_dir = tmp_path / "files-filtered"
        assert (filtered_dir / "other-9.9.9.tar.gz").exists()
        provenance = files_dir / "chains-provenance" / "sha256:1111.json"
        assert json.loads(provenance.read_text()) == {"predicate": {}}

        # Results and report
        assert (results_dir / "CONSUMED_BUILD_INDEX_DIGEST").read_text() == (
            "sha256:cafe"
        )
        assert (results_dir / "KEPT_COUNT").read_text() == "2"
        assert (results_dir / "REMOVED_COUNT").read_text() == "1"
        report = json.loads((tmp_path / FILTER_REPORT_FILENAME).read_text())
        assert report["kept_count"] == 2

        mock_load.assert_called_once_with(IMAGE, None, verbose=False)

    @patch(_LOAD)
    @patch(_RUN)
    @patch(_PULL)
    def test_publish_all_keeps_everything(
        self,
        mock_pull: MagicMock,
        mock_run: MagicMock,
        mock_load: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Publish-all keeps all extracted artifacts."""
        self._wire(
            mock_pull,
            mock_run,
            mock_load,
            {"flask-2.0.1-py3-none-any.whl": b"f", "other-9.9.9.tar.gz": b"o"},
        )
        snapshot = _make_snapshot(tmp_path, [IMAGE])

        res = runner.invoke(
            main,
            [
                "python",
                "extract-filter",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(tmp_path / "files"),
                "--publish-all",
            ],
        )
        assert res.exit_code == 0, res.output
        assert "Filtered payload: 3 kept, 0 removed." in res.output
        assert (tmp_path / "files" / "other-9.9.9.tar.gz").exists()

    @patch(_LOAD)
    @patch(_RUN)
    @patch(_PULL)
    def test_multiple_component_images_fail_closed(
        self,
        mock_pull: MagicMock,
        mock_run: MagicMock,
        mock_load: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        """Fail closed on multi-component snapshots."""
        self._wire(mock_pull, mock_run, mock_load, {})
        second = "quay.io/repo/other@sha256:2222"
        snapshot = _make_snapshot(tmp_path, [IMAGE, second])

        res = runner.invoke(
            main,
            [
                "python",
                "extract-filter",
                "--snapshot-path",
                str(snapshot),
                "--files-dir",
                str(tmp_path / "files"),
            ],
        )
        assert res.exit_code != 0
        assert "exactly one component image" in res.output
        assert "2" in res.output
