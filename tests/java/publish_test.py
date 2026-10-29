"""Tests for publish subcommand (slan_cuan/publish.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner, Result

from slan_cuan.cli import main
from slan_cuan.pulp import ContentUnit, FileContentUnit, ModifyResult, PulpError

_CONTENT_UNIT = ContentUnit(
    pulp_href="/api/v3/content/maven/artifact/abc/",
    relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
    group_id="org.example",
    artifact_id="artifact",
    version="1.0.0",
    filename="artifact-1.0.0.jar",
)

_REPO_HREF = "/api/v3/repositories/maven/maven/abc/"

_MODIFY_RESULT = ModifyResult(
    task_href="/api/v3/tasks/abc/",
    state="completed",
    repository_version="/api/v3/repositories/maven/maven/abc/versions/1/",
    content_units_added=2,
)

_FILE_CONTENT_UNIT = FileContentUnit(
    pulp_href="/api/v3/content/file/files/abc/",
    relative_path="gav-index.osv.json",
    sha256="deadbeef" * 8,
)

_FILE_PUB_HREF = "/api/v3/publications/file/file/pub-abc/"
_FILE_DIST_HREF = "/api/v3/distributions/file/file/dist-abc/"

_FILE_REPO_HREF = "/api/v3/repositories/file/file/abc/"

_FILE_MODIFY_RESULT = ModifyResult(
    task_href="/api/v3/tasks/file-abc/",
    state="completed",
    repository_version="/api/v3/repositories/file/file/abc/versions/1/",
    content_units_added=1,
)


def _make_ctx_mock() -> Mock:
    """Create a Mock that supports the context manager protocol."""
    m = Mock()
    m.__enter__ = Mock(return_value=m)
    m.__exit__ = Mock(return_value=False)
    return m


def _setup_client_mock(mock_client: Mock) -> None:
    """Configure mock client with upload_content, resolve, and modify."""
    mock_client.upload_content.return_value = _CONTENT_UNIT
    mock_client.resolve_repository.return_value = _REPO_HREF
    mock_client.modify_repository.return_value = _MODIFY_RESULT


def create_test_artifact_dir(
    base_dir: Path,
    *,
    include_metadata: bool = False,
    include_security_metadata: bool = False,
    gav_index_vulns: list[str] | None = None,
    osv_records: list[tuple[str, str]] | None = None,
) -> Path:
    """Create a directory that mimics the extract stage output."""
    deliverable_dir = base_dir / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")
    (repo_dir / "artifact-1.0.0.pom").write_text("<project/>")
    (repo_dir / "artifact-1.0.0.cyclonedx.json").write_text("{}")
    (repo_dir / "artifact-1.0.0.cyclonedx.json.md5").write_text("cdxmd5")
    (repo_dir / "artifact-1.0.0.provenance.sigstore.json").write_text("{}")
    (repo_dir / "artifact-1.0.0.provenance.sigstore.json.md5").write_text(
        "provmd5"
    )

    if include_metadata:
        metadata_dir = (
            deliverable_dir / "repository" / "org" / "example" / "artifact"
        )
        (metadata_dir / "maven-metadata.xml").write_text("<metadata/>")

    vulns = gav_index_vulns if gav_index_vulns is not None else []
    security_metadata_dir = None
    if include_security_metadata:
        sec_dir = deliverable_dir / "security_metadata"
        sec_dir.mkdir(parents=True, exist_ok=True)
        if osv_records is not None:
            # (cve_id, source) -> one OSV file per record, matching gav-index.
            aliases = []
            for cve_id, source in osv_records:
                osv_id = f"x_RHLW-{cve_id}-1.0.0"
                (sec_dir / f"{osv_id}.json").write_text(
                    json.dumps(
                        {
                            "id": osv_id,
                            "aliases": [cve_id],
                            "affected": [{"package": {"name": "example"}}],
                            "database_specific": {
                                "lightwell": {"source": source}
                            },
                        }
                    )
                )
                aliases.append(cve_id)
            metadata_vulns = aliases
        else:
            metadata_vulns = vulns or ["CVE-2026-1234"]
            (sec_dir / "gav-index.osv.json").write_text(
                json.dumps(
                    {
                        "id": "OSV-1",
                        "aliases": metadata_vulns,
                        "affected": [{"package": {"name": "example"}}],
                    }
                )
            )
        vulns = metadata_vulns
        security_metadata_dir = "TEST-build-output/security_metadata"

    attachments_dir = base_dir / "attachments"
    attachments_dir.mkdir()
    gav_index = attachments_dir / "gav-index.json"
    gav_index.write_text(json.dumps({"vulns": vulns}))
    attachment_files = [str(gav_index.relative_to(base_dir))]

    # Create extract-result.json
    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-06-22T12:00:00Z",
        "security_metadata_dir": security_metadata_dir,
        "attachment_files": attachment_files,
    }
    (base_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )
    return base_dir


def test_publish_help_output() -> None:
    """Verify --help shows all options."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-url" in result.output
    assert "--pulp-repository" in result.output
    assert "--artifact-dir" in result.output
    assert "--insecure" in result.output


def test_publish_subcommand_is_reachable() -> None:
    """Verify publish subcommand responds to --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "Publish Maven artifacts to Pulp" in result.output


def test_publish_requires_pulp_url() -> None:
    """Missing --pulp-url fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                ".",
                "--pulp-domain",
                "lightwell",
            ],
        )

    assert result.exit_code != 0
    assert "--pulp-url" in result.output or "Missing option" in result.output


def test_publish_requires_pulp_repository() -> None:
    """Missing --pulp-repository fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-url",
                "https://pulp.example.com",
                "--artifact-dir",
                ".",
                "--pulp-domain",
                "lightwell",
            ],
        )

    assert result.exit_code != 0
    assert (
        "--pulp-repository" in result.output or "Missing option" in result.output
    )


def test_publish_requires_artifact_dir() -> None:
    """Missing --artifact-dir fails."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code != 0
    assert "--artifact-dir" in result.output or "Missing option" in result.output


def test_publish_requires_pulp_domain() -> None:
    """Missing --pulp-domain fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-url",
                "https://pulp.example.com",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                ".",
            ],
        )

    assert result.exit_code != 0
    assert "--pulp-domain" in result.output or "Missing option" in result.output


def test_publish_dry_run(tmp_path: Path) -> None:
    """With --dry-run, shows artifact list, does NOT create client."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "Distribution: test-repo" in result.output
    assert "Pulp URL: https://pulp.example.com" in result.output
    assert "org/example/artifact/1.0.0/artifact-1.0.0.jar" in result.output
    assert "org/example/artifact/1.0.0/artifact-1.0.0.pom" in result.output
    assert "dry-run: would upload" in result.output


def test_publish_missing_extract_result(tmp_path: Path) -> None:
    """artifact-dir exists but has no extract-result.json -> error."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code != 0
    assert "Extract result not found" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_successful_upload(mock_client_cls: Mock, tmp_path: Path) -> None:
    """Mock client, verify upload_content and modify_repository."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify PulpMavenClient was created
    mock_client_cls.assert_called_once()

    # Verify upload_content called for each artifact
    # (jar + pom + cyclonedx + cyclonedx.md5 + provenance + provenance.md5)
    assert mock_client.upload_content.call_count == 6

    # Verify resolve_repository and modify_repository were called
    mock_client.resolve_repository.assert_called_once_with("test-repo")
    mock_client.modify_repository.assert_called_once()

    # Verify context manager was used (close via __exit__)
    mock_client.__exit__.assert_called_once()

    # Verify always-on progress lines (not gated behind --verbose)
    assert "Resolving repository: test-repo" in result.output
    assert "Adding 6 content unit(s) to repository" in result.output

    # Verify summary output
    assert "Published: 6 artifact(s) uploaded" in result.output

    # Verify publish-result.json was created
    publish_result_path = artifact_dir / "publish-result.json"
    assert publish_result_path.exists()

    with publish_result_path.open() as f:
        publish_result = json.load(f)

    assert publish_result["pulp_url"] == "https://pulp.example.com"
    assert publish_result["distribution"] == "test-repo"
    assert publish_result["artifacts_uploaded"] == 6
    assert publish_result["artifacts_skipped"] == 0
    assert publish_result["repository_version"] == (
        "/api/v3/repositories/maven/maven/abc/versions/1/"
    )
    assert len(publish_result["content_unit_hrefs"]) == 6


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_routes_metadata_to_upload_metadata(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """maven-metadata.xml routed to upload_metadata, others to upload_content."""
    artifact_dir = create_test_artifact_dir(tmp_path, include_metadata=True)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)
    mock_client.upload_metadata = Mock(return_value=_CONTENT_UNIT)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # jar + pom + 4 SBOM files go to upload_content
    assert mock_client.upload_content.call_count == 6

    # maven-metadata.xml goes to upload_metadata
    assert mock_client.upload_metadata.call_count == 1
    metadata_call = mock_client.upload_metadata.call_args
    assert metadata_call.kwargs["filename"] == "maven-metadata.xml"

    assert "Published: 7 artifact(s) uploaded" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_routes_metadata_checksums(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Route metadata checksums to upload_metadata, artifact to upload_content."""
    deliverable_dir = tmp_path / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)

    # Create primary artifact
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")
    (repo_dir / "artifact-1.0.0.pom").write_text("<project/>")

    # Create artifact checksum
    (repo_dir / "artifact-1.0.0.jar.md5").write_text("jarmd5")

    # Create maven-metadata.xml and its checksums at artifact level
    metadata_dir = deliverable_dir / "repository" / "org" / "example" / "artifact"
    (metadata_dir / "maven-metadata.xml").write_text("<metadata/>")
    (metadata_dir / "maven-metadata.xml.md5").write_text("metamd5")
    (metadata_dir / "maven-metadata.xml.sha1").write_text("metasha1")

    # Create extract-result.json
    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-06-29T12:00:00Z",
    }
    attachments_dir = tmp_path / "attachments"
    attachments_dir.mkdir()
    (attachments_dir / "gav-index.json").write_text('{"vulns": []}')
    extract_result["attachment_files"] = ["attachments/gav-index.json"]
    (tmp_path / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)
    mock_client.upload_metadata = Mock(return_value=_CONTENT_UNIT)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(tmp_path),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify upload_content: jar + pom + jar.md5 = 3
    assert mock_client.upload_content.call_count == 3

    # Verify upload_metadata: maven-metadata.xml + .md5 + .sha1 = 3
    assert mock_client.upload_metadata.call_count == 3

    # Verify metadata checksum files went to upload_metadata
    metadata_calls = mock_client.upload_metadata.call_args_list
    metadata_filenames = {call.kwargs["filename"] for call in metadata_calls}
    assert metadata_filenames == {
        "maven-metadata.xml",
        "maven-metadata.xml.md5",
        "maven-metadata.xml.sha1",
    }

    assert "Published: 6 artifact(s) uploaded" in result.output


def test_publish_env_var_precedence(tmp_path: Path) -> None:
    """SLAN_CUAN_PUBLISH_PULP_URL sets --pulp-url."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    with patch("slan_cuan.java.publish.PulpMavenClient") as mock_client_cls:
        mock_client = _make_ctx_mock()
        mock_client_cls.return_value = mock_client
        _setup_client_mock(mock_client)

        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                str(artifact_dir),
                "--pulp-domain",
                "lightwell",
                "--pulp-username",
                "testuser",
                "--pulp-password",
                "testpass",
            ],
            env={"SLAN_CUAN_PUBLISH_PULP_URL": "https://env.pulp.com"},
        )

    assert result.exit_code == 0


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_verbose_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --verbose, shows upload details."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "Extract result file:" in result.output
    assert "Artifact directory:" in result.output
    assert "Deliverable directory:" in result.output
    assert "Discovered" in result.output
    assert "Repository root:" in result.output
    assert "Pulp URL:" in result.output
    assert "Distribution:" in result.output
    assert "Uploading:" in result.output
    assert "Resolving repository:" in result.output
    assert "repository version:" in result.output
    assert "Publish result saved:" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_pulp_error_handling(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Mock client raises PulpError, verify ClickException output."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.side_effect = PulpError(
        message="Content upload failed",
        status_code=400,
        response_body="",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output
    assert "HTTP status: 400" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_503_is_reported_and_skipped(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """A recoverable upload 503 is reported while other artifacts continue."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.side_effect = PulpError(
        message="Metadata upload failed", status_code=503, response_body=""
    )
    mock_client.resolve_repository.return_value = _REPO_HREF
    mock_client.modify_repository.return_value = ModifyResult(
        task_href="/task/1/",
        state="completed",
        repository_version="v1",
        content_units_added=0,
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "recoverable HTTP 503" in result.output
    assert "skipping" not in result.output
    assert "0 artifact(s) uploaded" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_pulp_error_includes_response_body(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """PulpError with response body includes truncated body in output."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.side_effect = PulpError(
        message="Task failed: conflict",
        status_code=409,
        response_body='{"error": "duplicate content unit"}',
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output
    assert "HTTP status: 409" in result.output
    assert "duplicate content unit" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_insecure_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --insecure, verify_ssl=False is passed to PulpConfig."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--insecure",
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify PulpConfig was created with verify_ssl=False
    call_args = mock_client_cls.call_args
    config = call_args[0][0]  # First positional argument is config
    assert config.verify_ssl is False


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_ca_cert_propagates(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Global --ca-cert is forwarded to PulpConfig."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    ca_cert = tmp_path / "custom-ca.crt"
    ca_cert.write_text("PEM data")

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--ca-cert",
            str(ca_cert),
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    call_args = mock_client_cls.call_args
    config = call_args[0][0]
    assert config.ca_cert == ca_cert
    assert config.verify_ssl is True


@patch("slan_cuan.java.publish.PulpMavenClient")
@patch("slan_cuan.java.publish.BuildOutput.from_extract_result")
def test_publish_skips_missing_files(
    mock_from_extract: Mock,
    mock_client_cls: Mock,
    tmp_path: Path,
) -> None:
    """Files that don't exist on disk are skipped."""
    from slan_cuan.models import BuildOutput, MavenArtifact

    artifact_dir = create_test_artifact_dir(tmp_path)

    missing = tmp_path / "nonexistent.jar"
    existing_pom = (
        artifact_dir
        / "TEST-build-output"
        / "repository"
        / "org"
        / "example"
        / "artifact"
        / "1.0.0"
        / "artifact-1.0.0.pom"
    )
    mock_from_extract.return_value = BuildOutput(
        deliverable_dir=artifact_dir / "TEST-build-output",
        artifacts=(
            MavenArtifact(
                relative_path=("org/example/artifact/1.0.0/artifact-1.0.0.jar"),
                file_path=missing,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="jar",
                md5=None,
                sha1=None,
                sha256=None,
            ),
            MavenArtifact(
                relative_path=("org/example/artifact/1.0.0/artifact-1.0.0.pom"),
                file_path=existing_pom,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="pom",
                md5=None,
                sha1=None,
                sha256=None,
            ),
        ),
        source_archive_path=None,
        security_metadata_dir=None,
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "Warning: skipping missing file:" in result.output
    assert "1 artifact(s) uploaded, 1 skipped" in result.output
    assert mock_client.upload_content.call_count == 1


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_writes_tekton_results(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """When --tekton-results-dir is set, publish writes result files."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    results_dir = tmp_path / "results"

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify Tekton result files were created
    uploaded_file = results_dir / "ARTIFACTS_UPLOADED"
    skipped_file = results_dir / "ARTIFACTS_SKIPPED"
    outputs_file = results_dir / "PUBLISHED_ARTIFACT_OUTPUTS"

    assert uploaded_file.exists()
    assert skipped_file.exists()
    assert outputs_file.exists()

    # Verify content
    assert uploaded_file.read_text() == "6"
    assert skipped_file.read_text() == "0"

    # Verify JSON format for artifact outputs
    outputs_data = json.loads(outputs_file.read_text())
    assert outputs_data["uri"] == "https://pulp.example.com/pulp/maven/test-repo/"
    assert "digest" in outputs_data


def test_publish_tbr_without_credentials(tmp_path: Path) -> None:
    """TBR auth without username/password raises UsageError."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-auth-type",
            "tbr",
        ],
    )

    assert result.exit_code != 0
    assert "--pulp-username and --pulp-password" in result.output


def test_publish_cert_without_files(tmp_path: Path) -> None:
    """Certificate auth without cert/key files raises UsageError."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-auth-type",
            "cert",
        ],
    )

    assert result.exit_code != 0
    assert "--pulp-client-cert and --pulp-client-key" in result.output


def test_publish_default_auth_type() -> None:
    """Help output shows default auth type is tbr."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-auth-type" in result.output
    assert "tbr" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_env_var_auth_type(mock_client_cls: Mock, tmp_path: Path) -> None:
    """Auth type via environment variable works."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    cert_file = tmp_path / "client.crt"
    cert_file.write_text("cert content")
    key_file = tmp_path / "client.key"
    key_file.write_text("key content")

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-client-cert",
            str(cert_file),
            "--pulp-client-key",
            str(key_file),
        ],
        env={"SLAN_CUAN_PUBLISH_PULP_AUTH_TYPE": "cert"},
    )

    assert result.exit_code == 0
    call_args = mock_client_cls.call_args
    config = call_args[0][0]
    assert config.auth_type == "cert"


def test_publish_help_shows_new_options() -> None:
    """Help output includes all authentication options."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-auth-type" in result.output
    assert "--pulp-username" in result.output
    assert "--pulp-password" in result.output
    assert "--pulp-client-cert" in result.output
    assert "--pulp-client-key" in result.output


def test_publish_dry_run_shows_auth_type(tmp_path: Path) -> None:
    """Dry run output shows auth type."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    cert_file = tmp_path / "client.crt"
    cert_file.write_text("cert content")
    key_file = tmp_path / "client.key"
    key_file.write_text("key content")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-auth-type",
            "cert",
            "--pulp-client-cert",
            str(cert_file),
            "--pulp-client-key",
            str(key_file),
        ],
    )

    assert result.exit_code == 0
    assert "Auth type: cert" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_with_domain(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --pulp-domain, PulpConfig.domain is set."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert mock_client.upload_content.call_count == 6

    config = mock_client_cls.call_args[0][0]
    assert config.domain == "lightwell"


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_default_task_timeout(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Without timeout flags, PulpConfig.task_timeout defaults to 2700.0.

    This corresponds to 45 minutes.
    """
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    config = mock_client_cls.call_args[0][0]
    assert config.task_timeout == 2700.0


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_with_custom_task_timeout(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --pulp-task-timeout, PulpConfig.task_timeout is set."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-task-timeout",
            "3600",
        ],
    )

    assert result.exit_code == 0
    config = mock_client_cls.call_args[0][0]
    assert config.task_timeout == 3600.0


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_with_task_timeout_envvar(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With task timeout envvar, PulpConfig.task_timeout is set."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
        env={"SLAN_CUAN_PUBLISH_PULP_TASK_TIMEOUT": "2400"},
    )

    assert result.exit_code == 0
    config = mock_client_cls.call_args[0][0]
    assert config.task_timeout == 2400.0


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_verbose_with_domain(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --verbose and --pulp-domain, shows upload progress."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "Uploading:" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
@patch("slan_cuan.java.publish.BuildOutput.from_extract_result")
def test_publish_skips_missing_with_domain(
    mock_from_extract: Mock,
    mock_client_cls: Mock,
    tmp_path: Path,
) -> None:
    """One artifact missing on disk is skipped."""
    from slan_cuan.models import BuildOutput, MavenArtifact

    artifact_dir = create_test_artifact_dir(tmp_path)

    missing = tmp_path / "nonexistent.jar"
    existing_pom = (
        artifact_dir
        / "TEST-build-output"
        / "repository"
        / "org"
        / "example"
        / "artifact"
        / "1.0.0"
        / "artifact-1.0.0.pom"
    )

    mock_from_extract.return_value = BuildOutput(
        deliverable_dir=artifact_dir / "TEST-build-output",
        artifacts=(
            MavenArtifact(
                relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
                file_path=missing,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="jar",
                md5=None,
                sha1=None,
                sha256=None,
            ),
            MavenArtifact(
                relative_path="org/example/artifact/1.0.0/artifact-1.0.0.pom",
                file_path=existing_pom,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="pom",
                md5=None,
                sha1=None,
                sha256=None,
            ),
        ),
        source_archive_path=None,
        security_metadata_dir=None,
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "skipping missing file" in result.output
    assert mock_client.upload_content.call_count == 1
    assert "1 artifact(s) uploaded, 1 skipped" in result.output


def test_publish_dry_run_with_domain(tmp_path: Path) -> None:
    """With --dry-run and --pulp-domain, no crash."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "Distribution: test-repo" in result.output
    assert "Pulp URL: https://pulp.example.com" in result.output


def test_publish_help_shows_pulp_domain() -> None:
    """Verify --pulp-domain appears in help output."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-domain" in result.output


def test_publish_verbose_diagnoses_missing_deliverable(tmp_path: Path) -> None:
    """Verbose mode warns when deliverable_dir does not exist."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()
    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "MISSING-build-output",
        "files": [],
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    attachments_dir = artifact_dir / "attachments"
    attachments_dir.mkdir()
    (attachments_dir / "gav-index.json").write_text('{"vulns": []}')
    extract_result["attachment_files"] = ["attachments/gav-index.json"]
    (artifact_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "deliverable path does not exist" in result.output
    assert "Contents of" in result.output


def test_publish_verbose_diagnoses_file_deliverable(tmp_path: Path) -> None:
    """Verbose mode warns when deliverable_dir is a file, not a directory."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()
    (artifact_dir / "build-output.zip").write_text("not a directory")
    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "build-output.zip",
        "files": [],
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    attachments_dir = artifact_dir / "attachments"
    attachments_dir.mkdir()
    (attachments_dir / "gav-index.json").write_text('{"vulns": []}')
    extract_result["attachment_files"] = ["attachments/gav-index.json"]
    (artifact_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "deliverable path is a file, not a directory" in result.output


def test_publish_verbose_diagnoses_missing_repo_dir(tmp_path: Path) -> None:
    """Verbose mode warns when repository/ subdir is missing."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()
    deliverable = artifact_dir / "TEST-build-output"
    deliverable.mkdir()
    (deliverable / "cyclonedx.json").write_text("{}")
    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    attachments_dir = artifact_dir / "attachments"
    attachments_dir.mkdir()
    (attachments_dir / "gav-index.json").write_text('{"vulns": []}')
    extract_result["attachment_files"] = ["attachments/gav-index.json"]
    (artifact_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "repository/ subdirectory not found" in result.output
    assert "cyclonedx.json" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_passes_labels_to_upload(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Mock client, verify upload_content receives labels kwarg."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify upload_content was called with labels
    assert mock_client.upload_content.call_count == 6
    for call in mock_client.upload_content.call_args_list:
        labels = call.kwargs.get("labels")
        assert labels is not None
        assert "build_id" not in labels
        assert labels["source_image"] == "quay.io/test/image@sha256:abc123"


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_labels_with_none_digest(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Extract result with None digest uses tag-only image reference."""
    deliverable_dir = tmp_path / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")

    # Create extract-result.json with digest=None
    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": "latest",
            "digest": None,
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    attachments_dir = tmp_path / "attachments"
    attachments_dir.mkdir()
    (attachments_dir / "gav-index.json").write_text('{"vulns": []}')
    extract_result["attachment_files"] = ["attachments/gav-index.json"]
    (tmp_path / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(tmp_path),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    for call in mock_client.upload_content.call_args_list:
        labels = call.kwargs.get("labels")
        assert labels is not None
        assert "build_id" not in labels
        assert labels["source_image"] == "quay.io/test/image:latest"


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_labels_in_publish_result(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """After publish, publish-result.json contains pulp_labels."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Read publish-result.json
    publish_result_path = artifact_dir / "publish-result.json"
    assert publish_result_path.exists()

    with publish_result_path.open() as f:
        publish_result = json.load(f)

    assert "pulp_labels" in publish_result
    assert "build_id" not in publish_result["pulp_labels"]
    assert (
        publish_result["pulp_labels"]["source_image"]
        == "quay.io/test/image@sha256:abc123"
    )


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_shows_labels_in_output(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Labels appear in regular (non-verbose) output."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "Pulp labels:" in result.output
    assert "source_image" in result.output
    assert "quay.io/test/image@sha256:abc123" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_writes_pulp_labels_tekton_result(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --tekton-results-dir, verify PULP_LABELS file is created."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    results_dir = tmp_path / "results"

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify PULP_LABELS file was created
    labels_file = results_dir / "PULP_LABELS"
    assert labels_file.exists()

    # Verify content is valid JSON
    labels_data = json.loads(labels_file.read_text())
    assert "build_id" not in labels_data
    assert labels_data["source_image"] == "quay.io/test/image@sha256:abc123"


def test_publish_env_var_pulp_domain(tmp_path: Path) -> None:
    """Set SLAN_CUAN_PUBLISH_PULP_DOMAIN env var, verify it propagates."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    with patch("slan_cuan.java.publish.PulpMavenClient") as mock_client_cls:
        mock_client = _make_ctx_mock()
        mock_client_cls.return_value = mock_client
        _setup_client_mock(mock_client)

        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-url",
                "https://pulp.example.com",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                str(artifact_dir),
                "--pulp-username",
                "testuser",
                "--pulp-password",
                "testpass",
            ],
            env={"SLAN_CUAN_PUBLISH_PULP_DOMAIN": "testdomain"},
        )

    assert result.exit_code == 0

    config = mock_client_cls.call_args[0][0]
    assert config.domain == "testdomain"


def test_publish_upload_workers_in_help() -> None:
    """Verify --upload-workers appears in --help output."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])
    assert result.exit_code == 0
    assert "--upload-workers" in result.output


def test_publish_upload_workers_default() -> None:
    """Verify default value (4) appears in help."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])
    assert result.exit_code == 0
    assert "4" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_upload_workers_env_var(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Verify SLAN_CUAN_PUBLISH_UPLOAD_WORKERS env var is recognized."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
        env={"SLAN_CUAN_PUBLISH_UPLOAD_WORKERS": "2"},
    )
    assert result.exit_code == 0
    assert mock_client.upload_content.call_count == 6


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_upload_workers_one_sequential(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --upload-workers 1, verify single-threaded behavior."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--upload-workers",
            "1",
        ],
    )
    assert result.exit_code == 0
    assert "Published: 6 artifact(s) uploaded" in result.output
    assert mock_client.upload_content.call_count == 6
    mock_client.resolve_repository.assert_called_once()
    mock_client.modify_repository.assert_called_once()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_concurrent_upload_collects_all_hrefs(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Verify all content_unit_hrefs collected regardless of order."""
    artifact_dir = create_test_artifact_dir(tmp_path, include_metadata=True)
    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client

    # Return distinct hrefs for each upload
    hrefs = [
        "/api/v3/content/maven/artifact/001/",
        "/api/v3/content/maven/artifact/002/",
        "/api/v3/content/maven/artifact/003/",
    ]
    call_count = 0

    def _side_effect(**kwargs: object) -> ContentUnit:
        nonlocal call_count
        href = hrefs[call_count % len(hrefs)]
        call_count += 1
        return ContentUnit(
            pulp_href=href,
            relative_path=str(kwargs.get("relative_path", "")),
            group_id=str(kwargs.get("group_id", "")),
            artifact_id=str(kwargs.get("artifact_id", "")),
            version=str(kwargs.get("version", "")),
            filename=str(kwargs.get("filename", "")),
        )

    mock_client.upload_content.side_effect = _side_effect
    mock_client.upload_metadata.side_effect = _side_effect
    mock_client.resolve_repository.return_value = _REPO_HREF
    mock_client.modify_repository.return_value = _MODIFY_RESULT

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--upload-workers",
            "2",
        ],
    )
    assert result.exit_code == 0

    publish_result_path = artifact_dir / "publish-result.json"
    with publish_result_path.open() as f:
        publish_result = json.load(f)

    assert len(publish_result["content_unit_hrefs"]) == 7
    assert "Published: 7 artifact(s) uploaded" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_concurrent_upload_error_fails_fast(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """When upload fails, command fails and modify_repository not called."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client

    mock_client.upload_content.side_effect = PulpError(
        message="Upload failed: server error",
        status_code=500,
        response_body="",
    )
    mock_client.resolve_repository.return_value = _REPO_HREF

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--upload-workers",
            "2",
        ],
    )
    assert result.exit_code != 0
    assert "Pulp error:" in result.output
    mock_client.modify_repository.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
@patch("slan_cuan.java.publish.BuildOutput.from_extract_result")
def test_publish_concurrent_skips_missing_before_pool(
    mock_from_extract: Mock,
    mock_client_cls: Mock,
    tmp_path: Path,
) -> None:
    """Missing files are filtered before the thread pool, not inside it."""
    from slan_cuan.models import BuildOutput, MavenArtifact

    artifact_dir = create_test_artifact_dir(tmp_path)
    missing = tmp_path / "nonexistent.jar"
    existing_pom = (
        artifact_dir
        / "TEST-build-output"
        / "repository"
        / "org"
        / "example"
        / "artifact"
        / "1.0.0"
        / "artifact-1.0.0.pom"
    )
    mock_from_extract.return_value = BuildOutput(
        deliverable_dir=artifact_dir / "TEST-build-output",
        artifacts=(
            MavenArtifact(
                relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
                file_path=missing,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="jar",
                md5=None,
                sha1=None,
                sha256=None,
            ),
            MavenArtifact(
                relative_path="org/example/artifact/1.0.0/artifact-1.0.0.pom",
                file_path=existing_pom,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="pom",
                md5=None,
                sha1=None,
                sha256=None,
            ),
        ),
        source_archive_path=None,
        security_metadata_dir=None,
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--upload-workers",
            "4",
        ],
    )
    assert result.exit_code == 0
    assert "skipping missing file" in result.output
    assert mock_client.upload_content.call_count == 1
    assert "1 artifact(s) uploaded, 1 skipped" in result.output


def test_publish_dry_run_shows_upload_workers(tmp_path: Path) -> None:
    """Verify dry-run output includes worker count."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--upload-workers",
            "8",
        ],
    )
    assert result.exit_code == 0
    assert "Upload workers: 8" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_modify_repository_error(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """PulpError from modify_repository is reported as ClickException."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.return_value = _CONTENT_UNIT
    mock_client.resolve_repository.return_value = _REPO_HREF
    mock_client.modify_repository.side_effect = PulpError(
        message="Task failed: conflict",
        status_code=409,
        response_body="",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output
    assert "HTTP status: 409" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_resolve_repository_error(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """PulpError from resolve_repository is reported as ClickException."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.return_value = _CONTENT_UNIT
    mock_client.resolve_repository.side_effect = PulpError(
        message="Repository 'test-repo' not found",
        status_code=404,
        response_body="",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output
    assert "not found" in result.output


def test_publish_help_shows_require_supply_chain_metadata() -> None:
    """Verify --require-supply-chain-metadata appears in help."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--require-supply-chain-metadata" in result.output


def test_publish_default_allows_missing_sbom(tmp_path: Path) -> None:
    """Default allows publishing without SBOMs."""
    deliverable_dir = tmp_path / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")
    (repo_dir / "artifact-1.0.0.pom").write_text("<project/>")

    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-07-06T12:00:00Z",
    }
    attachments_dir = tmp_path / "attachments"
    attachments_dir.mkdir()
    (attachments_dir / "gav-index.json").write_text('{"vulns": []}')
    extract_result["attachment_files"] = ["attachments/gav-index.json"]
    (tmp_path / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(tmp_path),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "dry-run: would upload" in result.output


def test_publish_require_supply_chain_metadata_fails_without_sbom(
    tmp_path: Path,
) -> None:
    """--require-supply-chain-metadata fails when SBOMs are missing."""
    deliverable_dir = tmp_path / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")
    (repo_dir / "artifact-1.0.0.pom").write_text("<project/>")

    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-07-06T12:00:00Z",
    }
    (tmp_path / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(tmp_path),
            "--pulp-domain",
            "lightwell",
            "--require-supply-chain-metadata",
        ],
    )

    assert result.exit_code != 0
    assert "Missing SBOM artifacts for" in result.output


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_require_supply_chain_metadata_passes_with_sbom(
    mock_client_cls: Mock, mock_file_client_cls: Mock, tmp_path: Path
) -> None:
    """--require-supply-chain-metadata succeeds when SBOMs are present."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    mock_file_client = _make_ctx_mock()
    mock_file_client_cls.return_value = mock_file_client
    mock_file_client.upload_content.return_value = _FILE_CONTENT_UNIT
    mock_file_client.resolve_repository.return_value = _FILE_REPO_HREF
    mock_file_client.modify_repository.return_value = _FILE_MODIFY_RESULT
    mock_file_client.create_publication.return_value = _FILE_PUB_HREF
    mock_file_client.resolve_distribution.return_value = _FILE_DIST_HREF
    mock_file_client.update_distribution.return_value = None

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--require-supply-chain-metadata",
            "--pulp-file-repository",
            "test-file-repo",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Published: 6 artifact(s) uploaded" in result.output


def test_publish_require_supply_chain_metadata_env_var(tmp_path: Path) -> None:
    """SLAN_CUAN_PUBLISH_REQUIRE_SUPPLY_CHAIN_METADATA env var enables check."""
    deliverable_dir = tmp_path / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")

    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-07-06T12:00:00Z",
    }
    (tmp_path / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(tmp_path),
            "--pulp-domain",
            "lightwell",
        ],
        env={"SLAN_CUAN_PUBLISH_REQUIRE_SUPPLY_CHAIN_METADATA": "true"},
    )

    assert result.exit_code != 0
    assert "Missing SBOM artifacts for" in result.output


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_uploads_security_metadata_to_file_repo(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """Security metadata files are uploaded to the Pulp File repository."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    mock_file.upload_content.return_value = _FILE_CONTENT_UNIT
    mock_file.resolve_repository.return_value = _FILE_REPO_HREF
    mock_file.modify_repository.return_value = _FILE_MODIFY_RESULT
    mock_file.create_publication.return_value = _FILE_PUB_HREF
    mock_file.resolve_distribution.return_value = _FILE_DIST_HREF
    mock_file.update_distribution.return_value = None

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            "test-file-repo",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Security metadata: 1 file(s) uploaded" in result.output
    mock_file.resolve_repository.assert_called_once_with("test-file-repo")
    mock_file.upload_content.assert_called_once()
    call_kwargs = mock_file.upload_content.call_args
    assert "gav-index.osv.json" in str(call_kwargs)
    assert call_kwargs.kwargs.get("repository_href") == _FILE_REPO_HREF
    mock_file.modify_repository.assert_not_called()
    mock_file.create_publication.assert_called_once_with(_FILE_REPO_HREF)
    mock_file.resolve_distribution.assert_called_once_with("test-file-repo")
    mock_file.update_distribution.assert_called_once_with(
        _FILE_DIST_HREF, _FILE_PUB_HREF
    )


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_skips_file_upload_when_no_security_metadata(
    mock_maven_cls: Mock,
    tmp_path: Path,
) -> None:
    """No file client is created when security metadata is absent."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Security metadata" not in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_requires_file_repo_when_security_metadata_exists(
    mock_maven_cls: Mock,
    tmp_path: Path,
) -> None:
    """Error when security metadata exists but --pulp-file-repository missing."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "pulp-file-repository" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_whitespace_file_repo_treated_as_absent(
    mock_maven_cls: Mock,
    tmp_path: Path,
) -> None:
    """Whitespace-only --pulp-file-repository is normalised to None."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            "   ",
        ],
    )

    assert result.exit_code != 0
    assert "pulp-file-repository" in result.output


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_requires_file_repo_when_gav_index_lists_vulnerabilities(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """Vulnerability IDs require a File repository before OSV generation."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        gav_index_vulns=["CVE-2026-1234"],
    )

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "pulp-file-repository" in result.output
    mock_maven_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_preflights_file_repo_before_maven_mutation(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """An unresolvable required File repo prevents Maven uploads."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        gav_index_vulns=["CVE-2026-1234"],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    mock_file.resolve_repository.side_effect = PulpError(
        message="File repository 'test-file-repo' not found",
        status_code=404,
        response_body="",
    )

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            "test-file-repo",
        ],
    )

    assert result.exit_code != 0
    assert (
        "Unable to verify the required OSV publication repository"
        in result.output
    )
    # The raw Pulp error message must not leak; the repo name may still
    # appear via the (unrelated) unrecognized-repo type-filtering warning,
    # since "test-file-repo" matches neither the backport nor novel pattern.
    assert "File repository 'test-file-repo' not found" not in result.output
    mock_file.resolve_repository.assert_called_once_with("test-file-repo")
    mock_maven.upload_content.assert_not_called()
    mock_maven.modify_repository.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_skips_file_repo_for_clean_gav_index_without_osv_files(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """A clean index with no generated OSV files does not need a File repo."""
    artifact_dir = create_test_artifact_dir(tmp_path, gav_index_vulns=[])
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("index_contents", "expected_error"),
    [
        ("not json", "Unable to parse the required GAV index"),
        (json.dumps({"vulns": "CVE-2026-1234"}), "invalid vulnerability data"),
        (json.dumps({"vulns": [None]}), "invalid vulnerability data"),
    ],
)
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_fails_closed_for_invalid_gav_index(
    mock_maven_cls: Mock,
    tmp_path: Path,
    index_contents: str,
    expected_error: str,
) -> None:
    """Invalid security input cannot be treated as a clean release."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    (artifact_dir / "attachments" / "gav-index.json").write_text(index_contents)

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert expected_error in result.output
    mock_maven_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_fails_closed_when_gav_index_attachment_is_missing(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """A missing declared GAV index prevents Maven-only publication."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    (artifact_dir / "attachments" / "gav-index.json").unlink()

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Unable to verify the required GAV index attachment" in result.output
    mock_maven_cls.assert_not_called()


def test_gav_index_vulnerabilities_rejects_non_list_attachment_files(
    tmp_path: Path,
) -> None:
    """A non-list attachment_files value is a controlled ValueError.

    Regression test: ``attachment_files`` previously lost its upfront
    list-type check, so a malformed value such as ``null`` in
    extract-result.json raised an uncaught ``TypeError`` from iteration
    instead of the ``ValueError`` that ``publish`` catches.
    """
    from slan_cuan.java.publish import _gav_index_vulnerabilities

    with pytest.raises(
        ValueError, match="Unable to verify the required GAV index attachment"
    ):
        _gav_index_vulnerabilities(None, tmp_path)  # type: ignore[arg-type]


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_fails_closed_when_attachment_files_is_null(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """A null attachment_files in extract-result.json fails closed via Click.

    Regression test for the same bug as
    ``test_gav_index_vulnerabilities_rejects_non_list_attachment_files``,
    exercised end-to-end through the CLI to confirm the error is reported
    as a normal ``ClickException`` rather than crashing the process.
    """
    artifact_dir = create_test_artifact_dir(tmp_path)
    extract_result_path = artifact_dir / "extract-result.json"
    extract_result = json.loads(extract_result_path.read_text())
    extract_result["attachment_files"] = None
    extract_result_path.write_text(json.dumps(extract_result))

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Unable to verify the required GAV index attachment" in result.output
    mock_maven_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_rejects_arbitrary_security_metadata(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """Security metadata must be valid OSV/VEX, not merely an arbitrary file."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )
    metadata_file = (
        artifact_dir / "TEST-build-output/security_metadata/gav-index.osv.json"
    )
    metadata_file.write_text('{"not": "security metadata"}')

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            "file-repo",
        ],
    )

    assert result.exit_code != 0
    assert "not OSV, VEX, or SBOM JSON" in result.output
    mock_maven_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_rejects_vulnerable_index_without_osv_metadata(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """Vulnerability claims must be backed by generated OSV before upload."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, gav_index_vulns=["CVE-2026-1234"]
    )

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            "file-repo",
        ],
    )

    assert result.exit_code != 0
    assert "no generated OSV metadata" in result.output
    mock_maven_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_with_custom_headers_cli(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --pulp-custom-headers, headers are passed to PulpConfig."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-custom-headers",
            "X-TASK-DIAGNOSTICS: pyinstrument,memory\nCorrelation-ID: cid-123",
        ],
    )

    assert result.exit_code == 0
    config = mock_client_cls.call_args[0][0]
    assert config.custom_headers == {
        "X-TASK-DIAGNOSTICS": "pyinstrument,memory",
        "Correlation-ID": "cid-123",
    }


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_with_custom_headers_envvar(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With custom headers envvar, headers are parsed and passed to PulpConfig."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    runner = CliRunner()
    headers_json = json.dumps({"X-TASK-DIAGNOSTICS": "memray"})
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
        env={"SLAN_CUAN_PUBLISH_PULP_CUSTOM_HEADERS": headers_json},
    )

    assert result.exit_code == 0
    config = mock_client_cls.call_args[0][0]
    assert config.custom_headers == {"X-TASK-DIAGNOSTICS": "memray"}


def test_expected_source_for_repo_backport() -> None:
    """Backport repo names map to the pnc-build source."""
    from slan_cuan.java.publish import _expected_source_for_repo

    assert _expected_source_for_repo("osv-java-backport") == "pnc-build"


def test_expected_source_for_repo_novel() -> None:
    """Novel repo names map to the novel-pipeline source."""
    from slan_cuan.java.publish import _expected_source_for_repo

    assert _expected_source_for_repo("osv-java-novel") == "novel-pipeline"


def test_expected_source_for_repo_unrecognized() -> None:
    """Unrecognized repo names return None (routing skipped)."""
    from slan_cuan.java.publish import _expected_source_for_repo

    assert _expected_source_for_repo("some-other-repo") is None


def test_classify_osv_source_reads_source_field(tmp_path: Path) -> None:
    """The authoritative database_specific.lightwell.source field wins."""
    from slan_cuan.java.publish import _classify_osv_source

    f = tmp_path / "x_RHLW-CVE-2025-48924-3.17.0.json"
    f.write_text(
        json.dumps(
            {
                "id": "x_RHLW-CVE-2025-48924-3.17.0",
                "database_specific": {"lightwell": {"source": "pnc-build"}},
            }
        )
    )
    assert _classify_osv_source(f) == "pnc-build"


def test_classify_osv_source_falls_back_to_id_prefix(tmp_path: Path) -> None:
    """Without a source field, the id prefix drives classification.

    Note the id contains "x_RHLW-" whose "LW" must not be mistaken for a
    novel record.
    """
    from slan_cuan.java.publish import _classify_osv_source

    f = tmp_path / "x_RHLW-CVE-2025-48924-3.17.0.json"
    f.write_text(json.dumps({"id": "x_RHLW-CVE-2025-48924-3.17.0"}))
    assert _classify_osv_source(f) == "pnc-build"


def test_classify_osv_source_novel_id_prefix(tmp_path: Path) -> None:
    """An LW- id prefix classifies as novel-pipeline."""
    from slan_cuan.java.publish import _classify_osv_source

    f = tmp_path / "x_RHLW-LW-2026-0087-4.5.12.json"
    f.write_text(json.dumps({"id": "x_RHLW-LW-2026-0087-4.5.12"}))
    assert _classify_osv_source(f) == "novel-pipeline"


def test_classify_osv_source_unclassifiable(tmp_path: Path) -> None:
    """A record with no recognizable id prefix is unclassifiable."""
    from slan_cuan.java.publish import _classify_osv_source

    f = tmp_path / "mystery.json"
    f.write_text(json.dumps({"id": "not-an-osv-id"}))
    assert _classify_osv_source(f) is None


def test_classify_osv_source_non_dict_lightwell_is_none(tmp_path: Path) -> None:
    """A non-dict ``lightwell`` value returns None, not AttributeError."""
    from slan_cuan.java.publish import _classify_osv_source

    f = tmp_path / "malformed.json"
    f.write_text(json.dumps({"database_specific": {"lightwell": "oops"}}))
    assert _classify_osv_source(f) is None


def _setup_file_client(mock_file: Mock) -> None:
    """Configure mock file client with upload/publication/distribution."""
    mock_file.upload_content.return_value = _FILE_CONTENT_UNIT
    mock_file.resolve_repository.return_value = _FILE_REPO_HREF
    mock_file.modify_repository.return_value = _FILE_MODIFY_RESULT
    mock_file.create_publication.return_value = _FILE_PUB_HREF
    mock_file.resolve_distribution.return_value = _FILE_DIST_HREF
    mock_file.update_distribution.return_value = None


def _run_publish_with_file_repo(artifact_dir: Path, file_repo: str) -> Result:
    """Invoke the publish command against a Pulp File repository."""
    runner = CliRunner()
    return runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            file_repo,
        ],
    )


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_novel_repo_skips_cve_records(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Novel repo keeps x_RHLW-LW-* and warns-and-skips x_RHLW-CVE-*."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("LW-2026-0087", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = _run_publish_with_file_repo(artifact_dir, "osv-java-novel")

    assert result.exit_code == 0, result.output
    # Only the novel record uploaded.
    assert mock_file.upload_content.call_count == 1
    uploaded_name = mock_file.upload_content.call_args.kwargs["relative_path"]
    assert uploaded_name.startswith("x_RHLW-LW-")
    assert "Warning: skipping OSV record x_RHLW-CVE-2025-48924" in result.output
    assert "Security metadata: 1 file(s) uploaded" in result.output


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_backport_repo_skips_novel_records(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Backport repo keeps x_RHLW-CVE-* and warns-and-skips x_RHLW-LW-*."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("LW-2026-0087", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = _run_publish_with_file_repo(artifact_dir, "osv-java-backport")

    assert result.exit_code == 0, result.output
    assert mock_file.upload_content.call_count == 1
    uploaded_name = mock_file.upload_content.call_args.kwargs["relative_path"]
    assert uploaded_name.startswith("x_RHLW-CVE-")
    assert "Warning: skipping OSV record x_RHLW-LW-2026-0087" in result.output


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_unrecognized_repo_uploads_all(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Unrecognized repo name uploads every record (legacy) with a warning."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("LW-2026-0087", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = _run_publish_with_file_repo(artifact_dir, "some-other-file-repo")

    assert result.exit_code == 0, result.output
    assert mock_file.upload_content.call_count == 2
    assert "not a recognized" in result.output


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_all_records_skipped_no_publication(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """When every record is filtered out, no publication/distribution runs."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2025-48924", "pnc-build")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    # Novel repo, only a CVE record present -> all skipped.
    result = _run_publish_with_file_repo(artifact_dir, "osv-java-novel")

    assert result.exit_code == 0, result.output
    assert mock_file.upload_content.call_count == 0
    mock_file.create_publication.assert_not_called()
    mock_file.update_distribution.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_writes_security_metadata_skipped_tekton_result(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """SECURITY_METADATA_SKIPPED Tekton result reflects the filtered count."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("LW-2026-0087", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    results_dir = tmp_path / "tekton-results"
    results_dir.mkdir()
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            "osv-java-novel",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (results_dir / "SECURITY_METADATA_SKIPPED").read_text() == "1"
    assert (results_dir / "SECURITY_METADATA_UPLOADED").read_text() == "1"


# ---------------------------------------------------------------------------
# New-format (upstream) record validation tests
# ---------------------------------------------------------------------------


def _new_format_record(
    advisory_id: str = "RHLW-2026-5fc0229c48c1b99c",
    upstream: list[str] | None = None,
) -> dict:
    """Build a new-format advisory OSV record with upstream."""
    return {
        "id": advisory_id,
        "upstream": upstream or ["CVE-2024-25710"],
        "affected": [
            {
                "package": {
                    "ecosystem": "Red Hat Lightwell:Maven",
                    "name": "example",
                    "purl": "pkg:maven/org.example/example",
                },
                "database_specific": {
                    "lightwell": {
                        "backport_base_version": "1.0.0",
                        "remediated_version": "1.0.0.rhlw-00001",
                        "repository_url": "https://packages.redhat.com/lightwell/java/remediated/",
                    }
                },
            },
        ],
    }


def test_upstream_record_accepted(tmp_path: Path) -> None:
    """New-format upstream record passes is_osv."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()
    rec = _new_format_record()
    (sec_dir / "RHLW-2026-5fc0229c48c1b99c.json").write_text(json.dumps(rec))

    files = (sec_dir / "RHLW-2026-5fc0229c48c1b99c.json",)
    _validate_security_metadata(files, ("CVE-2024-25710",))


def test_coverage_check_uses_upstream(tmp_path: Path) -> None:
    """Vuln coverage check passes when CVEs are in 'upstream' (not 'aliases')."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()
    rec = _new_format_record(upstream=["CVE-2024-25710", "CVE-2024-26308"])
    (sec_dir / "RHLW-2026-5fc0229c48c1b99c.json").write_text(json.dumps(rec))

    files = (sec_dir / "RHLW-2026-5fc0229c48c1b99c.json",)
    _validate_security_metadata(files, ("CVE-2024-25710", "CVE-2024-26308"))


def test_classify_source_new_id(tmp_path: Path) -> None:
    """Advisory records (no source, RHLW- prefix) classified as pnc-build."""
    from slan_cuan.java.publish import _classify_osv_source

    rec = _new_format_record()
    path = tmp_path / "RHLW-2026-5fc0229c48c1b99c.json"
    path.write_text(json.dumps(rec))
    assert _classify_osv_source(path) == "pnc-build"


def test_classify_source_per_cve_record(tmp_path: Path) -> None:
    """Per-CVE records with top-level source still classified correctly."""
    from slan_cuan.java.publish import _classify_osv_source

    rec = {
        "id": "x_RHLW-CVE-2024-25710-1.0.0",
        "aliases": ["CVE-2024-25710"],
        "affected": [{"package": {"name": "example"}}],
        "database_specific": {"lightwell": {"source": "pnc-build"}},
    }
    path = tmp_path / "x_RHLW-CVE-2024-25710-1.0.0.json"
    path.write_text(json.dumps(rec))
    assert _classify_osv_source(path) == "pnc-build"


def test_mixed_old_new_records(tmp_path: Path) -> None:
    """Old and new format records coexist in security metadata dir."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()

    old_rec = {
        "id": "x_RHLW-CVE-2024-25710-1.0.0",
        "aliases": ["CVE-2024-25710"],
        "affected": [{"package": {"name": "example"}}],
        "database_specific": {"lightwell": {"source": "pnc-build"}},
    }
    (sec_dir / "x_RHLW-CVE-2024-25710-1.0.0.json").write_text(json.dumps(old_rec))

    new_rec = _new_format_record(
        advisory_id="RHLW-2026-bbbbbbbbbbbbbbbb",
        upstream=["CVE-2024-26308"],
    )
    (sec_dir / "RHLW-2026-bbbbbbbbbbbbbbbb.json").write_text(json.dumps(new_rec))

    files = (
        sec_dir / "x_RHLW-CVE-2024-25710-1.0.0.json",
        sec_dir / "RHLW-2026-bbbbbbbbbbbbbbbb.json",
    )
    _validate_security_metadata(files, ("CVE-2024-25710", "CVE-2024-26308"))


def test_coverage_rejects_substring_match(tmp_path: Path) -> None:
    """CVE-2024-2571 must not be covered by a record for CVE-2024-25710."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()
    rec = {
        "id": "x_RHLW-CVE-2024-25710-1.0.0",
        "aliases": ["CVE-2024-25710"],
        "affected": [{"package": {"name": "example"}}],
        "database_specific": {"lightwell": {"source": "pnc-build"}},
    }
    (sec_dir / "x_RHLW-CVE-2024-25710-1.0.0.json").write_text(json.dumps(rec))

    files = (sec_dir / "x_RHLW-CVE-2024-25710-1.0.0.json",)
    with pytest.raises(ValueError, match="does not cover all"):
        _validate_security_metadata(files, ("CVE-2024-2571",))


def test_empty_aliases_and_upstream_rejected(tmp_path: Path) -> None:
    """A record with empty aliases and no upstream is not valid OSV."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()
    rec = {
        "id": "x_RHLW-CVE-2024-99999-1.0.0",
        "aliases": [],
        "upstream": [],
        "affected": [{"package": {"name": "example"}}],
    }
    (sec_dir / "empty.json").write_text(json.dumps(rec))

    with pytest.raises(ValueError, match="not OSV, VEX, or SBOM"):
        _validate_security_metadata(
            (sec_dir / "empty.json",), ("CVE-2024-99999",)
        )


def test_null_aliases_and_upstream_handled(tmp_path: Path) -> None:
    """Explicit JSON null for aliases/upstream must not TypeError."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()
    rec = {
        "id": "x_RHLW-CVE-2024-25710-1.0.0",
        "aliases": None,
        "upstream": None,
        "affected": [{"package": {"name": "example"}}],
    }
    (sec_dir / "null_fields.json").write_text(json.dumps(rec))

    files = (sec_dir / "null_fields.json",)
    with pytest.raises(ValueError, match="not OSV, VEX, or SBOM"):
        _validate_security_metadata(files, ("CVE-2024-25710",))


_GITHUB_OSV_REPO = "project-lightwell/lightwell-osv"


def _run_publish_with_github(
    artifact_dir: Path, file_repo: str, *github_args: str
) -> Result:
    """Invoke publish against a Pulp File repo with GitHub OSV options."""
    runner = CliRunner()
    return runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
            "--pulp-file-repository",
            file_repo,
            *github_args,
        ],
    )


_GITHUB_ENABLED_ARGS = (
    "--github-osv-repo",
    _GITHUB_OSV_REPO,
    "--github-osv-token",
    "ghp_secret",
)


def _setup_pulp_mocks(mock_maven_cls: Mock, mock_file_cls: Mock) -> Mock:
    """Wire Maven and File client mocks; return the File client mock."""
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)
    return mock_file


def _add_cyclonedx_sbom(artifact_dir: Path) -> None:
    """Drop a CycloneDX SBOM next to the OSV records, as generation does."""
    sec_dir = artifact_dir / "TEST-build-output" / "security_metadata"
    (sec_dir / "org.example.artifact-1.0.0.bom.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": []})
    )


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_pushes_only_backport_osv_records_to_github(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """GitHub gets pnc-build OSV records only; CycloneDX stays Pulp-only."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2026-1111", "pnc-build")],
    )
    _add_cyclonedx_sbom(artifact_dir)
    mock_file = _setup_pulp_mocks(mock_maven_cls, mock_file_cls)
    mock_gh = Mock()
    mock_gh.publish.return_value = "abc123"
    mock_gh_cls.return_value = mock_gh

    result = _run_publish_with_github(
        artifact_dir, "osv-java-backport", *_GITHUB_ENABLED_ARGS
    )

    assert result.exit_code == 0, result.output
    # Pulp still receives both the OSV record and the SBOM.
    assert mock_file.upload_content.call_count == 2
    assert mock_gh_cls.call_args.args == (_GITHUB_OSV_REPO, "ghp_secret")
    assert mock_gh_cls.call_args.kwargs["path"] == "advisories"
    pushed_files, commit_message = mock_gh.publish.call_args.args
    assert [p.name for p in pushed_files] == ["x_RHLW-CVE-2026-1111-1.0.0.json"]
    assert commit_message == (
        "Publish 1 OSV record(s) from quay.io/test/image@sha256:abc123"
    )
    assert "GitHub OSV: pushed 1 record(s)" in result.output


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_excludes_novel_records(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """Novel-pipeline records never reach the GitHub OSV repository."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("CVE-2026-2222", "pnc-build"),
            ("LW-2026-0001", "novel-pipeline"),
        ],
    )
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)
    mock_gh = Mock()
    mock_gh.publish.return_value = "abc123"
    mock_gh_cls.return_value = mock_gh

    result = _run_publish_with_github(
        artifact_dir, "osv-java-backport", *_GITHUB_ENABLED_ARGS
    )

    assert result.exit_code == 0, result.output
    pushed_files = mock_gh.publish.call_args.args[0]
    assert [p.name for p in pushed_files] == ["x_RHLW-CVE-2026-2222-1.0.0.json"]
    assert "GitHub OSV: skipping x_RHLW-LW-2026-0001-1.0.0.json" in result.output


@pytest.mark.parametrize("file_repo", ["test-file-repo", "osv-java-novel"])
@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_requires_backport_file_repository(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    file_repo: str,
    tmp_path: Path,
) -> None:
    """A novel or unrecognized file repo fails closed before Pulp upload."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2026-3333", "pnc-build")],
    )
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_github(
        artifact_dir, file_repo, *_GITHUB_ENABLED_ARGS
    )

    assert result.exit_code != 0
    assert "not recognized as one" in result.output
    mock_maven_cls.assert_not_called()
    mock_file_cls.assert_not_called()
    mock_gh_cls.assert_not_called()


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_fails_closed_on_unclassifiable_record(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """An OSV record with no recognizable source aborts before any upload."""
    # Default fixture record ("OSV-1") carries no source and no RHLW id.
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_github(
        artifact_dir, "osv-java-backport", *_GITHUB_ENABLED_ARGS
    )

    assert result.exit_code != 0
    assert "cannot classify the source of gav-index.osv.json" in result.output
    mock_maven_cls.assert_not_called()
    mock_file_cls.assert_not_called()
    mock_gh_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_rejects_malformed_repo_before_pulp(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """A repo not in owner/name form fails before anything is uploaded."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2026-4444", "pnc-build")],
    )
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_github(
        artifact_dir,
        "osv-java-backport",
        "--github-osv-repo",
        "lightwell-osv",
        "--github-osv-token",
        "ghp_secret",
    )

    assert result.exit_code != 0
    assert "'owner/name' form" in result.output
    mock_maven_cls.assert_not_called()


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_in_sync_is_distinguishable_from_unconfigured(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """A configured in-sync no-op is distinct from GitHub being unconfigured."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2026-5555", "pnc-build")],
    )
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)
    mock_gh = Mock()
    # Records already match the repo -> no commit.
    mock_gh.publish.return_value = None
    mock_gh_cls.return_value = mock_gh

    result = _run_publish_with_github(
        artifact_dir, "osv-java-backport", *_GITHUB_ENABLED_ARGS
    )

    assert result.exit_code == 0, result.output
    from slan_cuan.models import PublishResult

    publish_result = PublishResult.from_file(artifact_dir / "publish-result.json")
    # Configured, even though nothing was uploaded this run.
    assert publish_result.github_osv_configured is True
    assert publish_result.github_osv_repo == _GITHUB_OSV_REPO
    assert publish_result.github_osv_uploaded == 0
    assert publish_result.github_osv_commit is None


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_skips_github_when_not_configured(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """GitHub publication is skipped when repo/token are not provided."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_file_repo(artifact_dir, "test-file-repo")

    assert result.exit_code == 0, result.output
    mock_gh_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_repo_without_token_points_at_secret(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """An empty token (e.g. missing Secret) names the Secret param."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    result = _run_publish_with_github(
        artifact_dir,
        "osv-java-backport",
        "--github-osv-repo",
        _GITHUB_OSV_REPO,
    )

    assert result.exit_code != 0
    assert "token is empty" in result.output
    assert "GITHUB_OSV_TOKEN_SECRET" in result.output
    mock_maven_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_token_without_repo_errors(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """A token with no repository is a usage error."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    result = _run_publish_with_github(
        artifact_dir,
        "osv-java-backport",
        "--github-osv-token",
        "ghp_secret",
    )

    assert result.exit_code != 0
    assert "--github-osv-repo is" in result.output
    mock_maven_cls.assert_not_called()
