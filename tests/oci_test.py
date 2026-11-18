"""Tests for OCI registry operations using oras CLI."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from slan_cuan.models import ImageReference
from slan_cuan.oci import (
    OrasError,
    blob_fetch,
    deduplicate_referrers,
    discover,
    manifest_fetch,
    pull,
    push,
)


class TestPull:
    """Tests for the pull() function."""

    @pytest.fixture
    def image_ref(self) -> ImageReference:
        """Create a sample image reference."""
        return ImageReference(
            registry="quay.io",
            repository="light-castle/tmp-pnc",
            tag=None,
            digest="sha256:abc123",
        )

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_success(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Successful oras pull completes without error."""
        mock_run.return_value = Mock(returncode=0, stderr="", stdout="")
        pull(image_ref, tmp_path)
        mock_run.assert_called_once()

        # Verify command structure
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "oras"
        assert cmd[1] == "pull"
        assert str(image_ref) in cmd
        assert "--output" in cmd
        assert str(tmp_path) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_auth_failure(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError with auth failure message."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 401 Unauthorized",
            stdout="",
        )
        with pytest.raises(OrasError, match="Authentication failed for quay.io"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_auth_required(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for authentication required."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: authentication required",
            stdout="",
        )
        with pytest.raises(OrasError, match="Authentication failed for quay.io"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_not_found(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError with not found message."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: manifest unknown",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_not_found_uppercase_error_code(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """A bare uppercase MANIFEST_UNKNOWN error code is not-found too."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: GET https://quay.io/v2/x: MANIFEST_UNKNOWN",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_not_found_404(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for 404 Not Found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 404 Not Found",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_not_found_404_case_insensitive(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull classifies a lowercase '404 not found' as not-found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="error: 404 not found",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_network_error_connection(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for connection errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: connection refused",
            stdout="",
        )
        with pytest.raises(OrasError, match="Network error pulling"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_network_error_timeout(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for timeout errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: timeout waiting for response",
            stdout="",
        )
        with pytest.raises(OrasError, match="Network error pulling"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_generic_error(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull raises OrasError for unrecognized errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: something went wrong",
            stdout="",
        )
        with pytest.raises(OrasError, match="oras pull failed"):
            pull(image_ref, tmp_path)

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_with_auth_file(
        self, mock_run: Mock, image_ref: ImageReference, tmp_path: Path
    ) -> None:
        """Oras pull includes --registry-config when auth_file provided."""
        mock_run.return_value = Mock(returncode=0, stderr="", stdout="")
        auth_file = Path("/path/to/auth.json")
        pull(image_ref, tmp_path, auth_file=auth_file)

        cmd = mock_run.call_args[0][0]
        assert "--registry-config" in cmd
        assert str(auth_file) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_pull_verbose_prints_command(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Oras pull with verbose=True prints the command."""
        mock_run.return_value = Mock(returncode=0, stderr="", stdout="")
        pull(image_ref, tmp_path, verbose=True)

        captured = capsys.readouterr()
        assert "Running: oras pull" in captured.out


class TestManifestFetch:
    """Tests for the manifest_fetch() function."""

    @pytest.fixture
    def image_ref(self) -> ImageReference:
        """Create a sample image reference."""
        return ImageReference(
            registry="quay.io",
            repository="light-castle/tmp-pnc",
            tag=None,
            digest="sha256:abc123",
        )

    @pytest.fixture
    def sample_manifest(self) -> dict:
        """Create a sample OCI manifest."""
        return {
            "layers": [
                {
                    "digest": "sha256:layer1",
                    "mediaType": (
                        "application/vnd.lightwell.build-output.layer.v1+tar"
                    ),
                    "size": 1000,
                }
            ],
            "annotations": {
                "org.opencontainers.image.title": "TEST-build-output",
                "deliverable.name": "TEST-build-output",
                "deliverable.type": "lightwell-build-output",
            },
        }

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_success(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        sample_manifest: dict,
    ) -> None:
        """Successful manifest fetch returns parsed JSON."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps(sample_manifest),
        )
        result = manifest_fetch(image_ref)

        assert result == sample_manifest
        mock_run.assert_called_once()

        # Verify command structure
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "oras"
        assert cmd[1] == "manifest"
        assert cmd[2] == "fetch"
        assert str(image_ref) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_auth_failure(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for auth failure."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 401 Unauthorized",
            stdout="",
        )
        with pytest.raises(OrasError, match="Authentication failed for quay.io"):
            manifest_fetch(image_ref)

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_not_found(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for not found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: manifest unknown",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            manifest_fetch(image_ref)

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_network_error(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for network errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: connection timeout",
            stdout="",
        )
        with pytest.raises(OrasError, match="Network error fetching manifest"):
            manifest_fetch(image_ref)

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_invalid_json(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """manifest_fetch raises OrasError for invalid JSON response.

        Regression test: the oras process succeeded (returncode=0), but the
        raised OrasError must still report a synthetic failure returncode
        of 1 rather than propagating the process's successful returncode.
        """
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout="not valid json",
        )
        with pytest.raises(
            OrasError, match="Invalid JSON in manifest response"
        ) as exc_info:
            manifest_fetch(image_ref)
        assert exc_info.value.returncode == 1

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_with_auth_file(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        sample_manifest: dict,
    ) -> None:
        """manifest_fetch includes --registry-config when auth_file provided."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps(sample_manifest),
        )
        auth_file = Path("/path/to/auth.json")
        manifest_fetch(image_ref, auth_file=auth_file)

        cmd = mock_run.call_args[0][0]
        assert "--registry-config" in cmd
        assert str(auth_file) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_manifest_fetch_verbose_prints_command(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        sample_manifest: dict,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """manifest_fetch with verbose=True prints the command."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps(sample_manifest),
        )
        manifest_fetch(image_ref, verbose=True)

        captured = capsys.readouterr()
        assert "Running: oras manifest fetch" in captured.out


class TestDiscover:
    """Tests for the discover() function."""

    @pytest.fixture
    def image_ref(self) -> ImageReference:
        """Create a sample image reference."""
        return ImageReference(
            registry="quay.io",
            repository="light-castle/tmp-pnc",
            tag=None,
            digest="sha256:abc123",
        )

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_success(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Successful discover returns referrer list."""
        referrers = [
            {
                "digest": "sha256:ref1",
                "artifactType": "application/vnd.example.sbom",
            },
            {
                "digest": "sha256:ref2",
                "artifactType": "application/vnd.example.sbom",
            },
        ]
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps({"referrers": referrers}),
        )
        result = discover(image_ref, "application/vnd.example.sbom")

        assert result == referrers
        mock_run.assert_called_once()

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "oras"
        assert cmd[1] == "discover"
        assert "--artifact-type" in cmd
        assert "application/vnd.example.sbom" in cmd
        assert "--format" in cmd
        assert "json" in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_no_referrers(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Discover returns empty list when no referrers found."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps({"referrers": []}),
        )
        result = discover(image_ref, "application/vnd.example.sbom")
        assert result == []

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_auth_failure(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Discover raises OrasError for auth failure."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 401 Unauthorized",
            stdout="",
        )
        with pytest.raises(OrasError, match="Authentication failed"):
            discover(image_ref, "application/vnd.example.sbom")

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_not_found(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Discover raises OrasError for not found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 404 Not Found",
            stdout="",
        )
        with pytest.raises(OrasError, match="Image not found"):
            discover(image_ref, "application/vnd.example.sbom")

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_network_error(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Discover raises OrasError for network errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: connection refused",
            stdout="",
        )
        with pytest.raises(OrasError, match="Network error discovering"):
            discover(image_ref, "application/vnd.example.sbom")

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_generic_error(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Discover raises OrasError for unrecognized errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: something went wrong",
            stdout="",
        )
        with pytest.raises(OrasError, match="oras discover failed"):
            discover(image_ref, "application/vnd.example.sbom")

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_invalid_json(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Discover raises OrasError for invalid JSON response.

        Regression test: the oras process succeeded (returncode=0), but the
        raised OrasError must still report a synthetic failure returncode
        of 1 rather than propagating the process's successful returncode.
        """
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout="not valid json",
        )
        with pytest.raises(
            OrasError, match="Invalid JSON in discover response"
        ) as exc_info:
            discover(image_ref, "application/vnd.example.sbom")
        assert exc_info.value.returncode == 1

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_with_auth_file(
        self, mock_run: Mock, image_ref: ImageReference
    ) -> None:
        """Discover includes --registry-config when auth_file provided."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps({"referrers": []}),
        )
        auth_file = Path("/path/to/auth.json")
        discover(image_ref, "application/vnd.example.sbom", auth_file=auth_file)

        cmd = mock_run.call_args[0][0]
        assert "--registry-config" in cmd
        assert str(auth_file) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_discover_verbose_prints_command(
        self,
        mock_run: Mock,
        image_ref: ImageReference,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Discover with verbose=True prints the command."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=json.dumps({"referrers": []}),
        )
        discover(image_ref, "application/vnd.example.sbom", verbose=True)

        captured = capsys.readouterr()
        assert "Running: oras discover" in captured.out


class TestOrasError:
    """Tests for the OrasError exception class."""

    def test_oras_error_attributes(self) -> None:
        """OrasError preserves message, stderr, and returncode."""
        error = OrasError(
            message="Test error",
            stderr="stderr content",
            returncode=1,
        )
        assert error.message == "Test error"
        assert error.stderr == "stderr content"
        assert error.returncode == 1
        assert str(error) == "Test error"


class TestDeduplicateReferrers:
    """Tests for deduplicate_referrers()."""

    @pytest.fixture
    def image_ref(self) -> ImageReference:
        """Return sample image reference fixture."""
        return ImageReference(
            registry="quay.io",
            repository="example/repo",
            tag=None,
            digest="sha256:rootimage",
        )

    def test_empty_referrers_returns_none(
        self, image_ref: ImageReference
    ) -> None:
        """Empty or invalid referrers list returns None."""
        assert deduplicate_referrers([], "type", image_ref) is None
        assert deduplicate_referrers([{"foo": "bar"}], "type", image_ref) is None

    def test_single_referrer_returns_it(self, image_ref: ImageReference) -> None:
        """Single referrer is returned directly without fetching manifest."""
        ref = {"digest": "sha256:abc"}
        assert deduplicate_referrers([ref], "type", image_ref) == ref

    def test_identical_manifest_digests_deduplicates(
        self, image_ref: ImageReference
    ) -> None:
        """Referrers sharing identical manifest digests deduplicate."""
        ref1 = {"digest": "sha256:abc"}
        ref2 = {"digest": "sha256:abc"}
        result = deduplicate_referrers([ref1, ref2], "type", image_ref)
        assert result == ref1

    def test_identical_layers_deduplicates(
        self, image_ref: ImageReference
    ) -> None:
        """Referrers sharing identical layers deduplicate."""
        ref1 = {"digest": "sha256:manifest1"}
        ref2 = {"digest": "sha256:manifest2"}

        def mock_fetch(img, **kwargs):
            return {
                "layers": [{"digest": "sha256:same_blob"}],
            }

        result = deduplicate_referrers(
            [ref1, ref2],
            "type",
            image_ref,
            manifest_fetch_fn=mock_fetch,
        )
        assert result in (ref1, ref2)

    def test_distinct_layers_raises_error(
        self, image_ref: ImageReference
    ) -> None:
        """Distinct layer sets raise ClickException."""
        ref1 = {"digest": "sha256:manifest1"}
        ref2 = {"digest": "sha256:manifest2"}

        def mock_fetch(img, **kwargs):
            if img.digest == "sha256:manifest1":
                return {"layers": [{"digest": "sha256:blob1"}]}
            return {"layers": [{"digest": "sha256:blob2"}]}

        with pytest.raises(click.ClickException, match="distinct blob sets"):
            deduplicate_referrers(
                [ref1, ref2],
                "type",
                image_ref,
                manifest_fetch_fn=mock_fetch,
            )


class TestPush:
    """Tests for the push() function."""

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_builds_oras_command_with_annotations(
        self, mock_run: Mock, tmp_path: Path
    ) -> None:
        """Push constructs command with annotations and bare filename."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=(
                "Digest: "
                "sha256:1234567890abcdef1234567890abcdef"
                "1234567890abcdef1234567890abcdef\n"
            ),
        )
        artifact_path = tmp_path / "artifact.json"
        artifact_path.write_text('{"data": "test"}')

        annotations = {"key1": "value1", "key2": "value2"}
        push(
            artifact_path,
            "quay.io/registry/repo:latest",
            annotations=annotations,
        )

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "oras"
        assert cmd[1] == "push"
        assert "quay.io/registry/repo:latest" in cmd
        assert "--annotation" in cmd
        assert "key1=value1" in cmd
        assert "key2=value2" in cmd
        assert "artifact.json" in cmd
        assert str(artifact_path) not in cmd  # bare name, not full path

        # Verify cwd is the parent directory
        assert mock_run.call_args[1]["cwd"] == artifact_path.parent

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_extracts_digest_from_stdout(
        self, mock_run: Mock, tmp_path: Path
    ) -> None:
        """Push extracts digest from Digest: line in stdout."""
        digest = (
            "sha256:1234567890abcdef1234567890abcdef"
            "1234567890abcdef1234567890abcdef"
        )
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=f"Digest: {digest}\n",
        )
        artifact_path = tmp_path / "test.json"
        artifact_path.write_text("{}")

        result = push(
            artifact_path,
            "registry/repo:tag",
            annotations={},
        )

        assert result == digest

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_falls_back_to_resolve_when_no_digest_line(
        self, mock_run: Mock, tmp_path: Path
    ) -> None:
        """Push falls back to resolve when digest line not in stdout."""
        digest = (
            "sha256:fedcba0987654321fedcba0987654321"
            "fedcba0987654321fedcba0987654321"
        )
        # First call: push (no digest line)
        # Second call: resolve returns digest
        mock_run.side_effect = [
            Mock(
                returncode=0,
                stderr="",
                stdout="Push succeeded\n",
            ),
            Mock(
                returncode=0,
                stderr="",
                stdout=f"registry/repo:tag@{digest}\n",
            ),
        ]
        artifact_path = tmp_path / "test.json"
        artifact_path.write_text("{}")

        result = push(
            artifact_path,
            "registry/repo:tag",
            annotations={},
        )

        assert result == digest
        assert mock_run.call_count == 2

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_raises_oras_error_when_digest_unresolvable(
        self, mock_run: Mock, tmp_path: Path
    ) -> None:
        """Push raises OrasError when no digest found in push or resolve."""
        # Both push and resolve lack a digest line
        mock_run.side_effect = [
            Mock(
                returncode=0,
                stderr="",
                stdout="No digest info\n",
            ),
            Mock(
                returncode=0,
                stderr="",
                stdout="No @ in this response\n",
            ),
        ]
        artifact_path = tmp_path / "test.json"
        artifact_path.write_text("{}")

        with pytest.raises(OrasError, match="Could not extract digest"):
            push(
                artifact_path,
                "registry/repo:tag",
                annotations={},
            )

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_raises_oras_error_on_nonzero_returncode(
        self, mock_run: Mock, tmp_path: Path
    ) -> None:
        """Push raises OrasError when oras command fails."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: push failed",
            stdout="",
        )
        artifact_path = tmp_path / "test.json"
        artifact_path.write_text("{}")

        with pytest.raises(OrasError, match="oras push failed"):
            push(
                artifact_path,
                "registry/repo:tag",
                annotations={},
            )

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_includes_artifact_type_when_provided(
        self, mock_run: Mock, tmp_path: Path
    ) -> None:
        """Push includes --artifact-type when artifact_type parameter given."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=(
                "Digest: "
                "sha256:1234567890abcdef1234567890abcdef"
                "1234567890abcdef1234567890abcdef\n"
            ),
        )
        artifact_path = tmp_path / "artifact.json"
        artifact_path.write_text("{}")

        push(
            artifact_path,
            "registry/repo:tag",
            artifact_type="application/vnd.custom+json",
            annotations={},
        )

        cmd = mock_run.call_args[0][0]
        assert "--artifact-type" in cmd
        assert "application/vnd.custom+json" in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_with_auth_file(self, mock_run: Mock, tmp_path: Path) -> None:
        """Push includes --registry-config when auth_file provided."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=(
                "Digest: "
                "sha256:1234567890abcdef1234567890abcdef"
                "1234567890abcdef1234567890abcdef\n"
            ),
        )
        artifact_path = tmp_path / "artifact.json"
        artifact_path.write_text("{}")
        auth_file = Path("/path/to/auth.json")

        push(
            artifact_path,
            "registry/repo:tag",
            annotations={},
            auth_file=auth_file,
        )

        cmd = mock_run.call_args[0][0]
        assert "--registry-config" in cmd
        assert str(auth_file) in cmd

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_verbose_prints_command(
        self,
        mock_run: Mock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Push with verbose=True prints the command."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr="",
            stdout=(
                "Digest: "
                "sha256:1234567890abcdef1234567890abcdef"
                "1234567890abcdef1234567890abcdef\n"
            ),
        )
        artifact_path = tmp_path / "artifact.json"
        artifact_path.write_text("{}")

        push(
            artifact_path,
            "registry/repo:tag",
            annotations={},
            verbose=True,
        )

        captured = capsys.readouterr()
        assert "Running: oras push" in captured.out

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_auth_failure(self, mock_run: Mock, tmp_path: Path) -> None:
        """Push raises OrasError for authentication failure."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 401 Unauthorized",
            stdout="",
        )
        artifact_path = tmp_path / "test.json"
        artifact_path.write_text("{}")

        with pytest.raises(OrasError, match="Authentication failed"):
            push(
                artifact_path,
                "quay.io/registry/repo:tag",
                annotations={},
            )

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_not_found(self, mock_run: Mock, tmp_path: Path) -> None:
        """Push raises OrasError for not found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 404 Not Found",
            stdout="",
        )
        artifact_path = tmp_path / "test.json"
        artifact_path.write_text("{}")

        with pytest.raises(OrasError, match="Image not found"):
            push(
                artifact_path,
                "registry/repo:tag",
                annotations={},
            )

    @patch("slan_cuan.oci.subprocess.run")
    def test_push_network_error(self, mock_run: Mock, tmp_path: Path) -> None:
        """Push raises OrasError for network errors."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: connection refused",
            stdout="",
        )
        artifact_path = tmp_path / "test.json"
        artifact_path.write_text("{}")

        with pytest.raises(OrasError, match="Network error pushing"):
            push(
                artifact_path,
                "registry/repo:tag",
                annotations={},
            )


#: Image used by the cross-function classification tests below.
_CLASSIFY_IMAGE = ImageReference(
    registry="quay.io",
    repository="org/repo",
    tag="v1",
    digest=None,
)
_CLASSIFY_BLOB_REF = "quay.io/org/repo@sha256:" + "a" * 64


def _call_pull(tmp_path: Path) -> None:
    pull(_CLASSIFY_IMAGE, tmp_path / "out")


def _call_blob_fetch(tmp_path: Path) -> None:
    blob_fetch(_CLASSIFY_BLOB_REF, tmp_path / "blob")


def _call_manifest_fetch(tmp_path: Path) -> None:
    manifest_fetch(_CLASSIFY_IMAGE)


def _call_discover(tmp_path: Path) -> None:
    discover(_CLASSIFY_IMAGE, "application/vnd.example.sbom")


def _call_push(tmp_path: Path) -> None:
    artifact = tmp_path / "test.json"
    artifact.write_text("{}")
    push(artifact, str(_CLASSIFY_IMAGE), annotations={})


#: (callable, expected not-found message, expected generic prefix)
_ORAS_FUNCS = [
    pytest.param(
        _call_pull,
        f"Image not found: {_CLASSIFY_IMAGE}",
        "oras pull failed: ",
        id="pull",
    ),
    pytest.param(
        _call_blob_fetch,
        f"Blob not found: {_CLASSIFY_BLOB_REF}",
        "oras blob fetch failed: ",
        id="blob_fetch",
    ),
    pytest.param(
        _call_manifest_fetch,
        f"Image not found: {_CLASSIFY_IMAGE}",
        "oras manifest fetch failed: ",
        id="manifest_fetch",
    ),
    pytest.param(
        _call_discover,
        f"Image not found: {_CLASSIFY_IMAGE}",
        "oras discover failed: ",
        id="discover",
    ),
    pytest.param(
        _call_push,
        f"Image not found: {_CLASSIFY_IMAGE}",
        "oras push failed: ",
        id="push",
    ),
]


class TestOrasErrorClassification:
    """Shared stderr classification across every oras wrapper."""

    #: Verbatim stderr from real ``oras pull`` (oras 1.3.0) against Quay
    #: for a tag that does not exist -- no "404"/"manifest unknown".
    REAL_ORAS_NOT_FOUND = (
        "Error response from registry: "
        "quay.io/prometheus/busybox:lwlp4134-nonexistent-tag: not found"
    )

    @pytest.mark.parametrize(("call", "not_found_msg", "generic"), _ORAS_FUNCS)
    @patch("slan_cuan.oci.subprocess.run")
    def test_real_oras_trailing_not_found_is_not_found(
        self,
        mock_run: Mock,
        call: Callable[[Path], None],
        not_found_msg: str,
        generic: str,
        tmp_path: Path,
    ) -> None:
        """Real oras ``...: not found`` stderr is classified as not-found."""
        mock_run.return_value = Mock(
            returncode=1, stderr=self.REAL_ORAS_NOT_FOUND + "\n", stdout=""
        )
        with pytest.raises(OrasError) as excinfo:
            call(tmp_path)
        assert excinfo.value.message == not_found_msg
        assert excinfo.value.stderr == self.REAL_ORAS_NOT_FOUND
        assert excinfo.value.returncode == 1

    @pytest.mark.parametrize(("call", "not_found_msg", "generic"), _ORAS_FUNCS)
    @patch("slan_cuan.oci.subprocess.run")
    def test_trailing_not_found_beats_network_keyword_in_ref(
        self,
        mock_run: Mock,
        call: Callable[[Path], None],
        not_found_msg: str,
        generic: str,
        tmp_path: Path,
    ) -> None:
        """A ref echoing "timeout"/"connection" is still not-found."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr=(
                "Error response from registry: "
                "quay.io/org/repo:timeout-signal-2.0.0: not found"
            ),
            stdout="",
        )
        with pytest.raises(OrasError) as excinfo:
            call(tmp_path)
        assert excinfo.value.message == not_found_msg

    @pytest.mark.parametrize(
        "stderr",
        [
            "Error: credential helper not found in PATH",
            "Error: resource not found: access denied",
        ],
    )
    @pytest.mark.parametrize(("call", "not_found_msg", "generic"), _ORAS_FUNCS)
    @patch("slan_cuan.oci.subprocess.run")
    def test_unanchored_not_found_stays_generic(
        self,
        mock_run: Mock,
        call: Callable[[Path], None],
        not_found_msg: str,
        generic: str,
        stderr: str,
        tmp_path: Path,
    ) -> None:
        """A "not found" that isn't the trailing ``: not found`` is generic."""
        mock_run.return_value = Mock(returncode=1, stderr=stderr, stdout="")
        with pytest.raises(OrasError) as excinfo:
            call(tmp_path)
        assert excinfo.value.message == generic + stderr

    @pytest.mark.parametrize(("call", "not_found_msg", "generic"), _ORAS_FUNCS)
    @patch("slan_cuan.oci.subprocess.run")
    def test_auth_beats_trailing_not_found(
        self,
        mock_run: Mock,
        call: Callable[[Path], None],
        not_found_msg: str,
        generic: str,
        tmp_path: Path,
    ) -> None:
        """Auth failure keeps precedence over a trailing ``: not found``."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr="Error: 401 Unauthorized: token not found",
            stdout="",
        )
        with pytest.raises(OrasError, match="^Authentication failed for "):
            call(tmp_path)

    @pytest.mark.parametrize(
        "stderr",
        [
            "Error: 401 UNAUTHORIZED",
            "Error: Authentication Required",
        ],
    )
    @pytest.mark.parametrize(("call", "not_found_msg", "generic"), _ORAS_FUNCS)
    @patch("slan_cuan.oci.subprocess.run")
    def test_auth_failure_is_case_insensitive(
        self,
        mock_run: Mock,
        call: Callable[[Path], None],
        not_found_msg: str,
        generic: str,
        stderr: str,
        tmp_path: Path,
    ) -> None:
        """Upper/mixed-case auth-failure strings are still classified."""
        mock_run.return_value = Mock(returncode=1, stderr=stderr, stdout="")
        with pytest.raises(OrasError, match="^Authentication failed for "):
            call(tmp_path)

    @pytest.mark.parametrize(("call", "not_found_msg", "generic"), _ORAS_FUNCS)
    @patch("slan_cuan.oci.subprocess.run")
    def test_multiline_stderr_trailing_not_found_is_not_found(
        self,
        mock_run: Mock,
        call: Callable[[Path], None],
        not_found_msg: str,
        generic: str,
        tmp_path: Path,
    ) -> None:
        """Multi-line stderr is not-found when the FINAL line ends that way."""
        stderr = (
            "Warning: using cached credentials\n"
            "Error response from registry: "
            "quay.io/org/repo:tag: not found"
        )
        mock_run.return_value = Mock(returncode=1, stderr=stderr, stdout="")
        with pytest.raises(OrasError) as excinfo:
            call(tmp_path)
        assert excinfo.value.message == not_found_msg

    @pytest.mark.parametrize(("call", "not_found_msg", "generic"), _ORAS_FUNCS)
    @patch("slan_cuan.oci.subprocess.run")
    def test_multiline_stderr_not_found_on_nonfinal_line_stays_generic(
        self,
        mock_run: Mock,
        call: Callable[[Path], None],
        not_found_msg: str,
        generic: str,
        tmp_path: Path,
    ) -> None:
        """A ``: not found`` on a non-final line does not match.

        Only the real final line -- a generic error summary here -- should
        drive classification.
        """
        stderr = (
            "quay.io/org/repo:tag: not found\n"
            "Error: unexpected server error (HTTP 500)"
        )
        mock_run.return_value = Mock(returncode=1, stderr=stderr, stdout="")
        with pytest.raises(OrasError) as excinfo:
            call(tmp_path)
        assert excinfo.value.message == generic + stderr
