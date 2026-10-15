"""Tests for OCI registry operations using oras CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import click
import pytest

from slan_cuan.models import ImageReference
from slan_cuan.oci import (
    OrasError,
    deduplicate_referrers,
    discover,
    manifest_fetch,
    pull,
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
