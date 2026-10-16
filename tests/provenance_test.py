"""Tests for Tekton Chains provenance fetching."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from slan_cuan.provenance import fetch_chains_provenance

IMAGE = "quay.io/repo/wheels@sha256:1111"

_RUN = "slan_cuan.provenance.subprocess.run"


def _envelope_stdout(payload: dict) -> str:
    """Build cosign verify-attestation stdout for one DSSE envelope."""
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return json.dumps({"payload": encoded}) + "\n"


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
