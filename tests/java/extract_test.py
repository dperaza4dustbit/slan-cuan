"""End-to-end tests for the extract subcommand."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.oci import OrasError


@pytest.fixture
def fake_manifest() -> dict:
    """Create a fake OCI manifest response."""
    return {
        "layers": [
            {
                "digest": "sha256:layer1abc",
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


def create_mock_deliverable(output_dir: Path) -> None:
    """Create a mock deliverable directory with test files.

    Simulates what oras pull would extract.
    """
    deliverable_dir = output_dir / "TEST-build-output"
    deliverable_dir.mkdir(parents=True)

    # Create repository structure
    repo_dir = deliverable_dir / "repository" / "org" / "example" / "artifact"
    version_dir = repo_dir / "1.0.0"
    version_dir.mkdir(parents=True)

    # Create JAR files
    (version_dir / "artifact-1.0.0.jar").write_text("jar content")
    (version_dir / "artifact-1.0.0-sources.jar").write_text("sources")
    (version_dir / "artifact-1.0.0-javadoc.jar").write_text("javadoc")
    (version_dir / "artifact-1.0.0.pom").write_text("<project/>")

    # Create checksums
    (version_dir / "artifact-1.0.0.jar.md5").write_text("md5hash")
    (version_dir / "artifact-1.0.0.jar.sha1").write_text("sha1hash")
    (version_dir / "artifact-1.0.0.jar.sha256").write_text("sha256hash")

    # Create SBOM and provenance
    (deliverable_dir / "cyclonedx.json").write_text('{"bomFormat": "CycloneDX"}')
    (deliverable_dir / "provenance.json").write_text('{"_type": "in-toto"}')

    # Create logs
    logs_dir = deliverable_dir / "logs"
    logs_dir.mkdir(parents=True)
    (logs_dir / "build.log").write_text("build log content")
    (logs_dir / "alignment.log").write_text("alignment log content")


def create_mock_deliverable_zip(output_dir: Path) -> None:
    """Create a mock deliverable as a zip archive.

    Simulates newer PNC images where oras pull produces a zip file.
    """
    zip_path = output_dir / "TEST-build-output.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        prefix = "TEST-build-output"
        zf.writestr(f"{prefix}/cyclonedx.json", '{"bomFormat": "CycloneDX"}')
        zf.writestr(f"{prefix}/provenance.json", '{"_type": "in-toto"}')
        ver = f"{prefix}/repository/org/example/artifact/1.0.0"
        zf.writestr(f"{ver}/artifact-1.0.0.jar", "jar content")
        zf.writestr(f"{ver}/artifact-1.0.0.pom", "<project/>")


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_successful_extraction(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Successful extraction creates all expected files."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        """Create deliverable directory when pull is called."""
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify extract-result.json was created
    result_file = output_dir / "extract-result.json"
    assert result_file.exists()

    # Verify metadata/manifest.json was created
    manifest_file = output_dir / "metadata" / "manifest.json"
    assert manifest_file.exists()

    # Verify extract-result.json content
    with result_file.open() as f:
        result_data = json.load(f)

    assert result_data["image"]["registry"] == "quay.io"
    assert result_data["image"]["digest"] == "sha256:abc123"
    assert result_data["deliverable_dir"] == "TEST-build-output"
    assert len(result_data["layers"]) == 1
    assert result_data["layers"][0]["digest"] == "sha256:layer1abc"

    # Verify files list
    assert "TEST-build-output/cyclonedx.json" in result_data["files"]
    assert "TEST-build-output/provenance.json" in result_data["files"]
    assert any(
        "artifact-1.0.0.jar" in f and "sources" not in f
        for f in result_data["files"]
    )

    # Verify summary output
    assert "Extracted:" in result.output
    assert "artifact(s)" in result.output
    assert "POM(s)" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
def test_extract_dry_run_mode(
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Dry-run mode displays metadata without creating output directory."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify output directory was NOT created
    assert not output_dir.exists()

    # Verify metadata displayed
    assert "Image:" in result.output
    assert "Manifest digest:" in result.output
    assert "Layers:" in result.output
    assert "Deliverable: TEST-build-output" in result.output
    assert "dry-run:" in result.output
    assert "would extract 1 layer(s)" in result.output

    # Verify annotations displayed
    assert "Annotations:" in result.output
    assert "deliverable.name" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_force_overwrite(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Force flag allows overwriting existing output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "existing.txt").write_text("existing content")

    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--force",
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "extract-result.json").exists()
    assert not (output_dir / "existing.txt").exists()


@patch("slan_cuan.java.extract.manifest_fetch")
def test_extract_output_dir_conflict(
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Existing output directory without --force raises error."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert "Use --force to overwrite" in result.output


def test_extract_invalid_image_reference(tmp_path: Path) -> None:
    """Invalid image reference produces error message."""
    output_dir = tmp_path / "output"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "invalid-reference",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Error:" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_oras_error_handling(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """OrasError from pull is caught and converted to ClickException."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest
    mock_pull.side_effect = OrasError(
        "Authentication failed",
        stderr="401 Unauthorized",
        returncode=1,
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "OCI error:" in result.output
    assert "Authentication failed" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_with_registry_auth_file(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Registry auth file is passed to oras commands."""
    output_dir = tmp_path / "output"
    auth_file = tmp_path / "auth.json"
    auth_file.write_text('{"auths": {}}')

    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--registry-auth-file",
            str(auth_file),
        ],
    )

    assert result.exit_code == 0
    mock_manifest_fetch.assert_called_once()
    mock_pull.assert_called_once()

    # Verify auth_file was passed
    manifest_call_kwargs = mock_manifest_fetch.call_args.kwargs
    pull_call_kwargs = mock_pull.call_args.kwargs
    assert manifest_call_kwargs["auth_file"] == auth_file
    assert pull_call_kwargs["auth_file"] == auth_file


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_verbose_mode(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Verbose mode displays additional information."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Parsed image reference:" in result.output
    assert "Fetching manifest" in result.output
    assert "Creating output directory:" in result.output
    assert "Saving manifest" in result.output
    assert "Pulling artifact" in result.output
    assert "Extracted files" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
def test_extract_missing_deliverable_annotation(
    mock_manifest_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Missing deliverable name annotation produces error."""
    output_dir = tmp_path / "output"
    manifest_without_title = {
        "layers": [
            {
                "digest": "sha256:layer1",
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 1000,
            }
        ],
        "annotations": {},
    }
    mock_manifest_fetch.return_value = manifest_without_title

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Could not determine deliverable name" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_writes_tekton_results(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """When --tekton-results-dir is set, extract writes Tekton result files."""
    output_dir = tmp_path / "output"
    results_dir = tmp_path / "results"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify Tekton result files were created
    manifest_digest_file = results_dir / "MANIFEST_DIGEST"
    deliverable_dir_file = results_dir / "DELIVERABLE_DIR"
    attachment_dir_file = results_dir / "ATTACHMENT_DIR"

    assert manifest_digest_file.exists()
    assert deliverable_dir_file.exists()
    assert attachment_dir_file.exists()

    # Verify content
    assert manifest_digest_file.read_text() == "sha256:abc123"
    assert deliverable_dir_file.read_text() == "TEST-build-output"
    assert attachment_dir_file.read_text() == "__EMPTY__"


@patch("slan_cuan.java.extract.manifest_fetch")
def test_extract_dry_run_skips_tekton_results(
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """In dry-run mode, no Tekton result files are written."""
    output_dir = tmp_path / "output"
    results_dir = tmp_path / "results"
    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "--tekton-results-dir",
            str(results_dir),
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify no Tekton result files were created
    assert not results_dir.exists()


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_with_discover_attachments(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Discover attachments pulls referrers into attachments/ dir."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        if "attachments" not in str(out_dir):
            create_mock_deliverable(out_dir)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "sbom.json").write_text('{"bomFormat": "CycloneDX"}')

    mock_pull.side_effect = side_effect_pull
    mock_discover.return_value = [
        {"digest": "sha256:att1", "artifactType": "application/vnd.example.sbom"},
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "application/vnd.example.sbom",
        ],
    )

    assert result.exit_code == 0

    # Verify discover was called
    mock_discover.assert_called_once()
    discover_args = mock_discover.call_args
    assert discover_args[0][1] == "application/vnd.example.sbom"

    # Verify pull was called for the attachment
    assert mock_pull.call_count == 2
    attachment_pull = mock_pull.call_args_list[1]
    assert attachment_pull[0][0].digest == "sha256:att1"

    # Verify attachments dir exists
    assert (output_dir / "attachments").is_dir()

    # Verify attachment_files in result
    result_file = output_dir / "extract-result.json"
    with result_file.open() as f:
        result_data = json.load(f)
    assert len(result_data["attachment_files"]) > 0
    assert any("attachments/" in f for f in result_data["attachment_files"])

    # Verify summary output
    assert "Attachments:" in result.output


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_tekton_result_attachment_dir(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """ATTACHMENT_DIR Tekton result is 'attachments' when attachments exist."""
    output_dir = tmp_path / "output"
    results_dir = tmp_path / "results"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        if "attachments" not in str(out_dir):
            create_mock_deliverable(out_dir)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "sbom.json").write_text("{}")

    mock_pull.side_effect = side_effect_pull
    mock_discover.return_value = [
        {"digest": "sha256:att1", "artifactType": "application/vnd.example.sbom"},
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "application/vnd.example.sbom",
        ],
    )

    assert result.exit_code == 0
    assert (results_dir / "ATTACHMENT_DIR").read_text() == "attachments"


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_discover_no_referrers(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """No referrers found results in empty attachment_files."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull
    mock_discover.return_value = []

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "application/vnd.example.sbom",
        ],
    )

    assert result.exit_code == 0

    result_file = output_dir / "extract-result.json"
    with result_file.open() as f:
        result_data = json.load(f)
    assert result_data["attachment_files"] == []

    # Pull should only be called once (main pull, no attachment pulls)
    assert mock_pull.call_count == 1


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_without_discover_attachments_backward_compat(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Without --discover-attachments, discover is never called."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    with patch("slan_cuan.java.extract.discover") as mock_discover:
        result = runner.invoke(
            main,
            [
                "extract",
                "--image",
                "quay.io/light-castle/tmp-pnc@sha256:abc123",
                "--output-dir",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        mock_discover.assert_not_called()

    result_file = output_dir / "extract-result.json"
    with result_file.open() as f:
        result_data = json.load(f)
    assert result_data["attachment_files"] == []


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
def test_extract_dry_run_with_discover_attachments(
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Dry-run with --discover-attachments shows referrers without pulling."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest
    mock_discover.return_value = [
        {"digest": "sha256:att1", "artifactType": "application/vnd.example.sbom"},
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "application/vnd.example.sbom",
        ],
    )

    assert result.exit_code == 0
    assert not output_dir.exists()
    assert "would discover attachments" in result.output
    assert "1 referrer(s) found" in result.output
    assert "sha256:att1" in result.output


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_discover_multiple_types(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Multiple --discover-attachments values discover each type."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        if "attachments" not in str(out_dir):
            create_mock_deliverable(out_dir)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "att.json").write_text("{}")

    mock_pull.side_effect = side_effect_pull
    mock_discover.side_effect = [
        [{"digest": "sha256:att1", "artifactType": "type1"}],
        [{"digest": "sha256:att2", "artifactType": "type2"}],
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "type1",
            "--discover-attachments",
            "type2",
        ],
    )

    assert result.exit_code == 0
    assert mock_discover.call_count == 2
    # Main pull + 2 attachment pulls
    assert mock_pull.call_count == 3


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_discover_multiple_referrers_deduplicates(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Multiple referrers with identical layer blobs are deduplicated."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        if "attachments" not in str(out_dir):
            create_mock_deliverable(out_dir)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "sbom.json").write_text("{}")

    mock_pull.side_effect = side_effect_pull
    mock_discover.return_value = [
        {
            "digest": "sha256:att1",
            "artifactType": "application/vnd.example.sbom",
        },
        {
            "digest": "sha256:att2",
            "artifactType": "application/vnd.example.sbom",
        },
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "application/vnd.example.sbom",
        ],
    )

    assert result.exit_code == 0


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_discover_multiple_referrers_without_pnc_annotations(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Standard OCI SBOM manifests without deliverable annotations deduplicate."""
    output_dir = tmp_path / "output"

    def side_effect_manifest_fetch(img, **kwargs):
        if img.digest in ("sha256:att1", "sha256:att2"):
            return {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": "application/vnd.example.sbom",
                "layers": [
                    {
                        "digest": "sha256:same_blob_hash",
                        "mediaType": "application/spdx+json",
                        "size": 500,
                    }
                ],
                "annotations": {},
            }
        return fake_manifest

    mock_manifest_fetch.side_effect = side_effect_manifest_fetch

    def side_effect_pull(img, out_dir, **kwargs):
        if "attachments" not in str(out_dir):
            create_mock_deliverable(out_dir)
        else:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "sbom.json").write_text("{}")

    mock_pull.side_effect = side_effect_pull
    mock_discover.return_value = [
        {"digest": "sha256:att1", "artifactType": "application/vnd.example.sbom"},
        {"digest": "sha256:att2", "artifactType": "application/vnd.example.sbom"},
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "application/vnd.example.sbom",
        ],
    )

    assert result.exit_code == 0


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_discover_multiple_referrers_distinct_blobs_fails(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    tmp_path: Path,
) -> None:
    """Multiple referrers with distinct layer blobs raise an error."""
    output_dir = tmp_path / "output"

    def side_effect_manifest_fetch(img, **kwargs):
        if img.digest == "sha256:att1":
            return {
                "layers": [
                    {
                        "digest": "sha256:blob1",
                        "mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "size": 100,
                    }
                ],
                "annotations": {"deliverable.name": "att1"},
            }
        elif img.digest == "sha256:att2":
            return {
                "layers": [
                    {
                        "digest": "sha256:blob2",
                        "mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "size": 200,
                    }
                ],
                "annotations": {"deliverable.name": "att2"},
            }
        return {
            "layers": [
                {
                    "digest": "sha256:layer1abc",
                    "mediaType": (
                        "application/vnd.lightwell.build-output.layer.v1+tar"
                    ),
                    "size": 1000,
                }
            ],
            "annotations": {
                "org.opencontainers.image.title": "TEST-build-output"
            },
        }

    mock_manifest_fetch.side_effect = side_effect_manifest_fetch

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull
    mock_discover.return_value = [
        {
            "digest": "sha256:att1",
            "artifactType": "application/vnd.example.sbom",
        },
        {
            "digest": "sha256:att2",
            "artifactType": "application/vnd.example.sbom",
        },
    ]

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--discover-attachments",
            "application/vnd.example.sbom",
        ],
    )

    assert result.exit_code != 0
    assert "Expected at most 1 unique artifact" in result.output
    assert "found 2 distinct blob sets" in result.output


@patch("slan_cuan.java.extract.discover")
@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_discover_env_var_comma_split(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    mock_discover: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Comma-separated env var value is split into multiple artifact types."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull
    mock_discover.return_value = []

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
        env={"SLAN_CUAN_EXTRACT_DISCOVER_ATTACHMENTS": "type1,type2"},
    )

    assert result.exit_code == 0
    assert mock_discover.call_count == 2
    types_called = [c[0][1] for c in mock_discover.call_args_list]
    assert "type1" in types_called
    assert "type2" in types_called


@patch("slan_cuan.java.extract.manifest_fetch")
@patch("slan_cuan.java.extract.pull")
def test_extract_zip_deliverable(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Zip-archived deliverables are extracted before file discovery."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = {
        "layers": [
            {
                "digest": "sha256:zipdigest",
                "mediaType": "application/zip",
                "size": 5000,
            }
        ],
        "annotations": {
            "org.opencontainers.image.title": "TEST-build-output.zip",
        },
    }
    mock_pull.side_effect = lambda img, out_dir, **kw: (
        create_mock_deliverable_zip(out_dir)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    # The ZIP is kept and is not expanded to disk.
    assert (output_dir / "TEST-build-output.zip").exists()
    assert not (output_dir / "TEST-build-output").exists()

    with (output_dir / "extract-result.json").open() as f:
        data = json.load(f)

    assert data["deliverable_dir"] == "TEST-build-output"
    assert any("artifact-1.0.0.jar" in f for f in data["files"])
    assert "1 artifact(s)" in result.output
    assert "1 POM(s)" in result.output


@patch("slan_cuan.java.extract.pull")
@patch("slan_cuan.java.extract.manifest_fetch")
def test_extract_zip_slip_prevention(
    mock_manifest: MagicMock,
    mock_pull: MagicMock,
    tmp_path: Path,
) -> None:
    """Test that zip archives with directory traversal paths are rejected."""
    output_dir = tmp_path / "output"
    mock_manifest.return_value = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "size": 2,
            "digest": "sha256:e3b0c44",
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 1000,
                "digest": "sha256:layer1",
            }
        ],
        "annotations": {"org.opencontainers.image.title": "malicious.zip"},
    }

    def create_malicious_zip(out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        zip_path = out_dir / "malicious.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../evil.sh", "malicious content")

    mock_pull.side_effect = lambda img, out_dir, **kw: create_malicious_zip(
        out_dir
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Zip-slip path traversal attempt detected" in result.output
