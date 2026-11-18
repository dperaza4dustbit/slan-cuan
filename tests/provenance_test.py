"""Tests for Tekton Chains provenance fetching."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import click
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


class TestFetchChainsProvenanceExtension:
    """Tests for the predicate_types/select extension."""

    @patch(_RUN)
    def test_default_predicate_types_preserves_existing_single_type_behavior(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Default args make exactly one cosign call, as before."""
        predicate = {"builder": {"id": "tekton-chains"}}
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_envelope_stdout(predicate), stderr=""
        )

        out = fetch_chains_provenance(IMAGE, tmp_path / "prov", "k8s://ns/key")

        assert mock_run.call_count == 1
        cmd = mock_run.call_args.args[0]
        assert "--type=slsaprovenance" in cmd
        assert json.loads(out.read_text()) == predicate

    @patch(_RUN)
    def test_multiple_predicate_types_invokes_cosign_once_per_type(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Each predicate type gets its own cosign invocation."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_envelope_stdout({}), stderr=""
        )

        fetch_chains_provenance(
            IMAGE,
            tmp_path / "prov",
            "k8s://ns/key",
            predicate_types=("slsaprovenance", "slsaprovenance1"),
        )

        assert mock_run.call_count == 2
        types_seen = [
            next(a for a in c.args[0] if a.startswith("--type="))
            for c in mock_run.call_args_list
        ]
        assert types_seen == [
            "--type=slsaprovenance",
            "--type=slsaprovenance1",
        ]

    @patch(_RUN)
    def test_select_receives_all_candidates_across_types(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """select() sees every decoded candidate, in invocation order."""
        payload_a = {"source": "slsaprovenance"}
        payload_b = {"source": "slsaprovenance1"}
        mock_run.side_effect = [
            MagicMock(
                returncode=0, stdout=_envelope_stdout(payload_a), stderr=""
            ),
            MagicMock(
                returncode=0, stdout=_envelope_stdout(payload_b), stderr=""
            ),
        ]
        select = MagicMock(return_value=payload_a)

        fetch_chains_provenance(
            IMAGE,
            tmp_path / "prov",
            "k8s://ns/key",
            predicate_types=("slsaprovenance", "slsaprovenance1"),
            select=select,
        )

        select.assert_called_once_with([payload_a, payload_b])

    @patch(_RUN)
    def test_select_return_value_is_what_gets_written(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Whatever select() returns is what's written to disk."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout=_envelope_stdout({"irrelevant": True}), stderr=""
        )
        chosen = {"chosen": "candidate"}
        select = MagicMock(return_value=chosen)

        out = fetch_chains_provenance(
            IMAGE,
            tmp_path / "prov",
            "k8s://ns/key",
            select=select,
        )

        assert json.loads(out.read_text()) == chosen

    @patch(_RUN)
    def test_malformed_envelope_line_is_skipped_not_raised(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """A malformed line among multiple envelopes is skipped, not fatal."""
        good_payload = {"source": "well-formed"}
        stdout = (
            _envelope_stdout(good_payload)
            + "not-even-json\n"
            + json.dumps({"payload": "not-base64!!"})
            + "\n"
            + json.dumps({"nope": "no payload key"})
            + "\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
        select = MagicMock(return_value=good_payload)

        fetch_chains_provenance(
            IMAGE,
            tmp_path / "prov",
            "k8s://ns/key",
            select=select,
        )

        select.assert_called_once_with([good_payload])

    @patch(_RUN)
    def test_all_predicate_types_fail_raises_click_exception(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Every type failing (non-zero) still fails closed."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="verification failed"
        )

        with pytest.raises(Exception, match="cosign verify-attestation failed"):
            fetch_chains_provenance(
                IMAGE,
                tmp_path / "prov",
                "k8s://ns/key",
                predicate_types=("slsaprovenance", "slsaprovenance1"),
            )

    @patch(_RUN)
    def test_no_select_and_no_candidates_raises(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """All types succeed but yield no envelopes, and no select given."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with pytest.raises(Exception, match="no attestations"):
            fetch_chains_provenance(
                IMAGE,
                tmp_path / "prov",
                "k8s://ns/key",
                predicate_types=("slsaprovenance", "slsaprovenance1"),
            )


class TestFetchChainsProvenanceCosignFailureVsPolicyRejection:
    """Cosign infra failures must stay distinguishable from policy rejection."""

    _TYPES = ("slsaprovenance", "slsaprovenance1")

    @staticmethod
    def _rejecting_select(candidates: list[dict]) -> dict:
        raise click.ClickException(
            f"No trusted Chains SLSA provenance found ({len(candidates)})"
        )

    @patch(_RUN)
    def test_all_types_fail_with_select_surfaces_real_cosign_stderr(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Every cosign call failing reports cosign's stderr, not select's."""
        mock_run.side_effect = [
            MagicMock(
                returncode=1, stdout="", stderr="error: reading key: no such file"
            ),
            MagicMock(returncode=1, stdout="", stderr="dial tcp: refused"),
        ]
        select = MagicMock(side_effect=self._rejecting_select)

        with pytest.raises(click.ClickException) as excinfo:
            fetch_chains_provenance(
                IMAGE,
                tmp_path / "prov",
                "k8s://ns/key",
                predicate_types=self._TYPES,
                select=select,
            )

        message = excinfo.value.message
        assert "cosign verify-attestation failed" in message
        assert "error: reading key: no such file" in message
        assert "dial tcp: refused" in message
        assert "No trusted" not in message
        select.assert_not_called()

    @patch(_RUN)
    def test_select_rejecting_real_candidates_raises_select_message(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """A genuine trust-policy rejection still surfaces select's error."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="no matching attestations"),
            MagicMock(
                returncode=0,
                stdout=_envelope_stdout({"untrusted": True}),
                stderr="",
            ),
        ]
        select = MagicMock(side_effect=self._rejecting_select)

        with pytest.raises(click.ClickException, match="No trusted") as excinfo:
            fetch_chains_provenance(
                IMAGE,
                tmp_path / "prov",
                "k8s://ns/key",
                predicate_types=self._TYPES,
                select=select,
            )

        assert "cosign verify-attestation failed" not in excinfo.value.message
        select.assert_called_once_with([{"untrusted": True}])

    @patch(_RUN)
    def test_single_type_failure_message_unchanged(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Default single-type failure keeps its exact original message."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="  verification failed \n"
        )

        with pytest.raises(click.ClickException) as excinfo:
            fetch_chains_provenance(IMAGE, tmp_path / "prov", "k8s://ns/key")

        assert excinfo.value.message == (
            f"cosign verify-attestation failed for {IMAGE}: verification failed"
        )

    @patch(_RUN)
    def test_select_not_called_when_cosign_succeeds_with_no_envelopes(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Cosign succeeding with zero envelopes reports no attestations."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        select = MagicMock(side_effect=self._rejecting_select)

        with pytest.raises(click.ClickException, match="no attestations"):
            fetch_chains_provenance(
                IMAGE,
                tmp_path / "prov",
                "k8s://ns/key",
                predicate_types=self._TYPES,
                select=select,
            )

        select.assert_not_called()
