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
from slan_cuan.python.extract_filter import (
    fetch_chains_provenance,
    snapshot_component_images,
)

IMAGE = "quay.io/repo/wheels@sha256:1111"

_PULL = "slan_cuan.python.extract_filter.pull"
_RUN = "slan_cuan.python.extract_filter.subprocess.run"
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


class TestSnapshotComponentImages:
    """Tests for snapshot spec parsing."""

    def test_reads_component_images(self, tmp_path: Path) -> None:
        """Read component images from a snapshot."""
        snapshot = _make_snapshot(tmp_path, [IMAGE])
        assert snapshot_component_images(snapshot) == [IMAGE]

    def test_no_components_fails_closed(self, tmp_path: Path) -> None:
        """Fail closed when the snapshot has no components."""
        snapshot = tmp_path / "empty.json"
        snapshot.write_text(json.dumps({"components": []}))
        with pytest.raises(Exception, match="No component containerImage"):
            snapshot_component_images(snapshot)

    def test_missing_file_fails_closed(self, tmp_path: Path) -> None:
        """Fail closed when the snapshot file is missing."""
        with pytest.raises(Exception, match="Failed to parse snapshot"):
            snapshot_component_images(tmp_path / "nope.json")

    def test_bad_json_fails_closed(self, tmp_path: Path) -> None:
        """Fail closed when the snapshot is not valid JSON."""
        snapshot = tmp_path / "bad.json"
        snapshot.write_text("{not json")
        with pytest.raises(Exception, match="Failed to parse snapshot"):
            snapshot_component_images(snapshot)


class TestFetchChainsProvenance:
    """Tests for the cosign provenance fetch."""

    @patch(_RUN)
    def test_saves_decoded_payload_named_by_digest(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Save the decoded DSSE payload named by image digest."""
        predicate = {"builder": {"id": "tekton-chains"}}
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_envelope_stdout(predicate), stderr=""
        )
        prov_dir = tmp_path / "chains-provenance"

        out = fetch_chains_provenance(IMAGE, prov_dir, "k8s://ns/key")

        assert out == prov_dir / "sha256:1111.json"
        assert json.loads(out.read_text()) == predicate
        cmd = mock_run.call_args.args[0]
        assert cmd[:2] == ["cosign", "verify-attestation"]
        assert "--insecure-ignore-tlog=true" in cmd
        assert IMAGE in cmd

    @patch(_RUN)
    def test_registry_auth_file_sets_docker_config(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Cosign runs with the auth file staged as DOCKER_CONFIG."""
        # Capture the config content at cosign-invocation time: the
        # temporary DOCKER_CONFIG dir is removed before the call returns.
        seen: dict[str, str] = {}

        def fake_run(cmd, **kwargs):
            config = Path(kwargs["env"]["DOCKER_CONFIG"]) / "config.json"
            seen["config"] = config.read_text()
            return MagicMock(returncode=0, stdout=_envelope_stdout({}), stderr="")

        mock_run.side_effect = fake_run
        auth = tmp_path / "auth.json"
        auth.write_text('{"auths": {}}')

        fetch_chains_provenance(
            IMAGE, tmp_path / "prov", "k8s://ns/key", registry_auth_file=auth
        )

        assert seen["config"] == '{"auths": {}}'
        # The temporary DOCKER_CONFIG dir is cleaned up afterwards.
        env_dirs = [
            Path(c.kwargs["env"]["DOCKER_CONFIG"])
            for c in mock_run.call_args_list
        ]
        assert all(not (d / "config.json").exists() for d in env_dirs)

    @patch(_RUN)
    def test_cosign_failure_fails_closed(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Fail closed when cosign exits non-zero."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="verification failed"
        )
        with pytest.raises(Exception, match="cosign verify-attestation failed"):
            fetch_chains_provenance(IMAGE, tmp_path / "prov", "k8s://ns/key")

    @patch(_RUN)
    def test_empty_attestation_output_fails_closed(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Fail closed when cosign prints no attestations."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with pytest.raises(Exception, match="no attestations"):
            fetch_chains_provenance(IMAGE, tmp_path / "prov", "k8s://ns/key")

    def test_undigested_reference_fails_closed(self, tmp_path: Path) -> None:
        """Fail closed for non-digest-pinned image references."""
        with pytest.raises(Exception, match="must include a digest"):
            fetch_chains_provenance(
                "quay.io/repo/wheels:latest", tmp_path / "prov", "k8s://ns/key"
            )


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
        report = json.loads(
            (tmp_path / FILTER_REPORT_FILENAME).read_text()
        )
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
