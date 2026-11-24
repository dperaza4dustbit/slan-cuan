"""Tests for publish subcommand (slan_cuan/publish.py)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner, Result

from slan_cuan.cli import main
from slan_cuan.pulp import (
    ContentUnit,
    FileContentUnit,
    MavenDistribution,
    ModifyResult,
    PulpError,
)

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

_FILE_REPO_HREF = "/api/v3/repositories/file/file/abc/"
_PREDISCLOSURE_DISTRIBUTION = MavenDistribution(
    pulp_href="/api/v3/distributions/maven/maven/predisclosure/",
    name="java-predisclosure",
    base_path="java/predisclosure",
    repository=_REPO_HREF,
)
_PUBLIC_DISTRIBUTION = MavenDistribution(
    pulp_href="/api/v3/distributions/maven/maven/public/",
    name="java-public",
    base_path="java/public",
    repository=_REPO_HREF,
)
_FOREIGN_PREDISCLOSURE_DISTRIBUTION = MavenDistribution(
    pulp_href="/api/v3/distributions/maven/maven/other/",
    name="java-predisclosure",
    base_path="java/predisclosure",
    repository="/api/v3/repositories/maven/maven/other/",
)

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
    mock_client.list_distributions.return_value = (_PREDISCLOSURE_DISTRIBUTION,)


def _rhlw_id(vuln_id: str) -> str:
    """Return a stable per-release advisory ID (RHLW-YYYY-<16 hex>) for a test."""
    return f"RHLW-2026-{hashlib.sha256(vuln_id.encode()).hexdigest()[:16]}"


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
            # (cve_id, source) -> one RHLW- advisory record per entry,
            # matching gav-index. Legacy x_RHLW- records are never published
            # (LWLP-5093), so fixtures don't use them.
            aliases = []
            for cve_id, source in osv_records:
                osv_id = _rhlw_id(cve_id)
                (sec_dir / f"{osv_id}.json").write_text(
                    json.dumps(
                        {
                            "id": osv_id,
                            "upstream": [cve_id],
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


_BASIC_PUBLISH_ARGS = [
    "publish",
    "--pulp-url",
    "https://pulp.example.com",
    "--pulp-repository",
    "test-repo",
    "--pulp-domain",
    "lightwell",
    "--pulp-username",
    "testuser",
    "--pulp-password",
    "testpass",
]


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_skip_associate_uploads_without_modify(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """--skip-associate uploads and labels content but never modifies the repo."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    result = CliRunner().invoke(
        main,
        [
            *_BASIC_PUBLISH_ARGS,
            "--artifact-dir",
            str(artifact_dir),
            "--skip-associate",
        ],
    )

    assert result.exit_code == 0, result.output
    assert mock_client.upload_content.call_count == 6
    mock_client.modify_repository.assert_not_called()
    mock_client.resolve_repository.assert_not_called()
    assert (
        "Skipping association: 6 content unit(s) uploaded but not added to the "
        "repository (--skip-associate)"
    ) in result.output
    with (artifact_dir / "publish-result.json").open() as f:
        publish_result = json.load(f)
    assert publish_result["repository_version"] is None
    assert len(publish_result["content_unit_hrefs"]) == 6
    assert publish_result["pulp_labels"]["source_image"]


@pytest.mark.parametrize(
    ("env_value", "modify_calls"),
    [("true", 0), ("false", 1)],
)
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_skip_associate_env_var(
    mock_client_cls: Mock, tmp_path: Path, env_value: str, modify_calls: int
) -> None:
    """SLAN_CUAN_PUBLISH_SKIP_ASSOCIATE turns the mode on only for "true"."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

    result = CliRunner().invoke(
        main,
        [*_BASIC_PUBLISH_ARGS, "--artifact-dir", str(artifact_dir)],
        env={"SLAN_CUAN_PUBLISH_SKIP_ASSOCIATE": env_value},
    )

    assert result.exit_code == 0, result.output
    assert mock_client.modify_repository.call_count == modify_calls


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
    mock_file_client.get_distribution_repository.return_value = _FILE_REPO_HREF
    mock_file_client.get_repository_autopublish.return_value = True

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
    mock_file.get_distribution_repository.return_value = _FILE_REPO_HREF
    mock_file.get_repository_autopublish.return_value = True

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
    mock_file.get_distribution_repository.assert_called_once_with(
        "test-file-repo"
    )
    mock_file.get_repository_autopublish.assert_called_once_with(_FILE_REPO_HREF)


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_fails_closed_when_file_distribution_is_pinned(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """A publication-pinned distribution fails the publish before any upload."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)
    mock_file.get_distribution_repository.return_value = None

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
    assert "does not serve repository" in result.output
    assert "pinned to a publication" in result.output
    assert mock_file.upload_content.call_count == 0
    mock_maven.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_fails_closed_when_file_distribution_serves_other_repository(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """A distribution backed by a different repository fails the publish."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)
    mock_file.get_distribution_repository.return_value = (
        "/api/v3/repositories/file/file/other/"
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
    assert "does not serve repository" in result.output
    assert mock_file.upload_content.call_count == 0
    mock_maven.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_fails_closed_when_file_repository_not_autopublish(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """A repository without autopublish fails the publish before any upload."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)
    mock_file.get_repository_autopublish.return_value = False

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
    assert "does not have autopublish enabled" in result.output
    assert mock_file.upload_content.call_count == 0
    mock_maven.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_wraps_distribution_lookup_error(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """A PulpError from the distribution lookup is wrapped, not leaked."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)
    mock_file.get_distribution_repository.side_effect = PulpError(
        message="Distribution 'test-file-repo' not found",
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
    assert "Distribution 'test-file-repo' not found" not in result.output
    assert mock_file.upload_content.call_count == 0
    mock_maven.upload_content.assert_not_called()


def _add_vex_document(artifact_dir: Path, vuln_id: str = "CVE-2026-1234") -> Path:
    """Write a CycloneDX VEX document next to the OSV records."""
    sec_dir = artifact_dir / "TEST-build-output" / "security_metadata"
    path = sec_dir / f"{vuln_id}-2026-08-06T16:00:00Z.bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [{"id": vuln_id}],
            }
        )
    )
    return path


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_uploads_vex_to_separate_repository(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """VEX documents go to the VEX repository. OSV stays on the OSV repository."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )
    vex_path = _add_vex_document(artifact_dir)

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    mock_osv = _make_ctx_mock()
    mock_vex = _make_ctx_mock()
    _setup_file_client(mock_osv)
    _setup_file_client(mock_vex)
    mock_osv.resolve_repository.return_value = "/osv-repo/"
    mock_vex.resolve_repository.return_value = "/vex-repo/"
    mock_osv.get_distribution_repository.return_value = "/osv-repo/"
    mock_vex.get_distribution_repository.return_value = "/vex-repo/"
    mock_file_cls.side_effect = [mock_osv, mock_vex]

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
            "osv/java/remediated",
            "--pulp-vex-repository",
            "vex-java-backport",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Security metadata: 1 file(s) uploaded" in result.output
    assert "VEX metadata: 1 file(s) uploaded" in result.output
    assert mock_osv.upload_content.call_args.kwargs["relative_path"] == (
        "gav-index.osv.json"
    )
    assert mock_osv.upload_content.call_args.kwargs["repository_href"] == (
        "/osv-repo/"
    )
    assert mock_vex.upload_content.call_args.kwargs["relative_path"] == (
        vex_path.name
    )
    assert mock_vex.upload_content.call_args.kwargs["repository_href"] == (
        "/vex-repo/"
    )
    mock_osv.resolve_repository.assert_called_once_with("osv/java/remediated")
    mock_vex.resolve_repository.assert_called_once_with("vex-java-backport")
    mock_osv.get_distribution_repository.assert_called_once_with(
        "osv/java/remediated"
    )
    mock_vex.get_distribution_repository.assert_called_once_with(
        "vex-java-backport"
    )
    mock_osv.get_repository_autopublish.assert_called_once_with("/osv-repo/")
    mock_vex.get_repository_autopublish.assert_called_once_with("/vex-repo/")
    assert mock_file_cls.call_args_list[0].args[1] == "osv/java/remediated"
    assert mock_file_cls.call_args_list[1].args[1] == "vex-java-backport"


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_skip_associate_still_publishes_osv_and_vex(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """--skip-associate skips only the Maven modify; OSV/VEX still get published.

    File records upload straight into their (autopublish) repository, so the
    check is that each upload still targets the repository href.
    """
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )
    vex_path = _add_vex_document(artifact_dir)

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)

    mock_osv = _make_ctx_mock()
    mock_vex = _make_ctx_mock()
    _setup_file_client(mock_osv)
    _setup_file_client(mock_vex)
    mock_osv.resolve_repository.return_value = "/osv-repo/"
    mock_vex.resolve_repository.return_value = "/vex-repo/"
    mock_osv.get_distribution_repository.return_value = "/osv-repo/"
    mock_vex.get_distribution_repository.return_value = "/vex-repo/"
    mock_file_cls.side_effect = [mock_osv, mock_vex]

    result = CliRunner().invoke(
        main,
        [
            *_BASIC_PUBLISH_ARGS,
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-file-repository",
            "osv/java/remediated",
            "--pulp-vex-repository",
            "vex-java-backport",
            "--skip-associate",
        ],
    )

    assert result.exit_code == 0, result.output
    mock_maven.modify_repository.assert_not_called()
    assert "Skipping association:" in result.output
    assert "Security metadata: 1 file(s) uploaded" in result.output
    assert "VEX metadata: 1 file(s) uploaded" in result.output
    assert mock_osv.upload_content.call_args.kwargs["repository_href"] == (
        "/osv-repo/"
    )
    assert mock_vex.upload_content.call_args.kwargs["relative_path"] == (
        vex_path.name
    )
    assert mock_vex.upload_content.call_args.kwargs["repository_href"] == (
        "/vex-repo/"
    )


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_requires_vex_repository_when_vex_exists(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    tmp_path: Path,
) -> None:
    """VEX documents fail closed when --pulp-vex-repository is missing."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )
    _add_vex_document(artifact_dir)
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
            "--pulp-file-repository",
            "osv/java/remediated",
            "--pulp-vex-repository",
            "   ",
        ],
    )

    assert result.exit_code != 0
    assert "pulp-vex-repository" in result.output
    mock_maven.upload_content.assert_not_called()
    mock_file_cls.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_embargoed_build_uploads_all_vex_to_predisclosure_repo(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Every VEX of an LW- build goes to the predisclosure VEX repository.

    The CVE-only VEX is embargoed content too (it belongs to a build with an
    LW- fix), so it is uploaded rather than skipped as pnc-build.
    """
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("LW-2026-0087", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    lw_vex = _add_vex_document(artifact_dir, "LW-2026-0087")
    cve_vex = _add_vex_document(artifact_dir, "CVE-2025-48924")

    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_osv = _make_ctx_mock()
    mock_vex = _make_ctx_mock()
    _setup_file_client(mock_osv)
    _setup_file_client(mock_vex)
    mock_file_cls.side_effect = lambda _config, name: {
        "osv-java-novel": mock_osv,
        "vex-java-novel": mock_vex,
    }[name]

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "lightwell-java-predisclosure",
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
            "--pulp-vex-repository",
            "vex-java-novel",
        ],
    )

    assert result.exit_code == 0, result.output
    vex_uploaded = {
        call.kwargs["relative_path"]
        for call in mock_vex.upload_content.call_args_list
    }
    assert vex_uploaded == {lw_vex.name, cve_vex.name}
    osv_uploaded = {
        call.kwargs["relative_path"]
        for call in mock_osv.upload_content.call_args_list
    }
    assert osv_uploaded == {
        f"{_rhlw_id('LW-2026-0087')}.json",
        f"{_rhlw_id('CVE-2025-48924')}.json",
    }
    assert "skipping" not in result.output
    assert "VEX metadata: 2 file(s) uploaded" in result.output
    mock_osv.get_distribution_base_path.assert_called_with("osv-java-novel")
    mock_vex.get_distribution_base_path.assert_called_with("vex-java-novel")


@pytest.mark.parametrize(
    "sbom",
    [
        {"bomFormat": "CycloneDX", "components": [{"name": "artifact"}]},
        {
            "bomFormat": "CycloneDX",
            "components": [{"name": "artifact"}],
            "vulnerabilities": [],
        },
        {
            "bomFormat": "CycloneDX",
            "components": [{"name": "artifact"}],
            "vulnerabilities": [{"id": "CVE-2026-1234"}],
        },
    ],
    ids=["sbom", "sbom-empty-vulnerabilities", "sbom-with-vulnerabilities"],
)
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_rejects_sbom_in_security_metadata(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    sbom: dict[str, object],
    tmp_path: Path,
) -> None:
    """A CycloneDX SBOM in security metadata fails before any upload.

    SBOMs belong next to the artifact in the Maven repository; they are never
    routed to the OSV (or VEX) File repository.
    """
    artifact_dir = create_test_artifact_dir(
        tmp_path, include_security_metadata=True
    )
    sec_dir = artifact_dir / "TEST-build-output" / "security_metadata"
    sbom_name = "org.example.artifact-1.0.0.bom.json"
    (sec_dir / sbom_name).write_text(json.dumps(sbom))
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_file_repo(artifact_dir, "test-file-repo")

    assert result.exit_code != 0
    assert f"CycloneDX document {sbom_name} is not VEX" in result.output
    mock_maven_cls.assert_not_called()
    mock_file_cls.assert_not_called()


def test_record_is_vex_rejects_sbom_shapes() -> None:
    """CycloneDX SBOMs stay false even when vulnerabilities is present."""
    from slan_cuan.java.publish import _record_is_vex

    empty_vulns = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "artifact"}],
        "vulnerabilities": [],
    }
    mixed = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "artifact"}],
        "vulnerabilities": [{"id": "CVE-2026-1234"}],
    }
    vex = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [{"id": "CVE-2026-1234"}],
    }
    assert _record_is_vex(empty_vulns) is False
    assert _record_is_vex(mixed) is False
    assert _record_is_vex(vex) is True


def test_vex_vulnerability_ids_handles_openvex() -> None:
    """OpenVEX IDs come from statements[], not the CycloneDX vulnerabilities[]."""
    from slan_cuan.java.publish import _vex_vulnerability_ids

    cdx_vex = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [{"id": "CVE-2026-1234"}],
    }
    open_vex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [
            {"vulnerability": {"name": "LW-2026-0087"}},
            {"vulnerability": {"name": "CVE-2026-1234"}},
        ],
    }
    assert _vex_vulnerability_ids(cdx_vex) == ["CVE-2026-1234"]
    assert _vex_vulnerability_ids(open_vex) == ["LW-2026-0087", "CVE-2026-1234"]
    assert _vex_vulnerability_ids({"@context": "...", "statements": []}) == []
    assert _vex_vulnerability_ids(None) == []


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
    mock_maven.list_distributions.return_value = ()
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
    mock_maven.list_distributions.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_rejects_lw_vulns_to_non_predisclosure_repo(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Embargoed (LW-) builds must not publish to non-predisclosure repos."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        gav_index_vulns=["LW-2026-0001"],
        include_security_metadata=True,
        osv_records=[("LW-2026-0001", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_maven.list_distributions.return_value = (_PUBLIC_DISTRIBUTION,)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-novel-landing",
            "--pulp-file-repository",
            "osv-java-novel",
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

    assert result.exit_code != 0, (
        "Should reject LW- vulns to non-predisclosure repo"
    )
    assert "embargoed" in result.output.lower()
    mock_maven.upload_content.assert_not_called()


def test_lw_build_without_osv_fails_metadata_check() -> None:
    """LW- builds are not exempt from the OSV coverage check.

    They produce OSV (and VEX) records for the novel fix; a build without
    them must not publish silently.
    """
    from slan_cuan.java.publish import _validate_security_metadata

    with pytest.raises(ValueError, match="no generated OSV metadata"):
        _validate_security_metadata((), ("LW-2026-0001",))
    with pytest.raises(ValueError, match="no generated OSV metadata"):
        _validate_security_metadata((), ("CVE-2024-25710", "LW-2026-0001"))


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_lw_build_without_osv_fails_before_upload(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """An LW- build without OSV records fails closed before any upload."""
    artifact_dir = create_test_artifact_dir(
        tmp_path, gav_index_vulns=["LW-2026-0001"]
    )
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
            "lightwell-java-predisclosure",
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
    assert "no generated OSV metadata" in result.output
    mock_maven.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_allows_lw_vulns_to_predisclosure_repo(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Embargoed (LW-) builds are allowed to predisclosure repos."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        gav_index_vulns=["LW-2026-0001"],
        include_security_metadata=True,
        osv_records=[("LW-2026-0001", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_maven.list_distributions.return_value = (_PREDISCLOSURE_DISTRIBUTION,)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-novel-landing",
            "--pulp-file-repository",
            "osv-java-novel",
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


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_rejects_lw_vulns_when_repository_has_no_distribution(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Embargoed builds fail closed when no distribution serves the repo."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        gav_index_vulns=["LW-2026-0001"],
        include_security_metadata=True,
        osv_records=[("LW-2026-0001", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_maven.list_distributions.return_value = ()
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-novel-landing",
            "--pulp-file-repository",
            "osv-java-novel",
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
    assert "not associated with a predisclosure distribution" in result.output
    mock_maven.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_fails_closed_when_distribution_lookup_fails(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Embargoed builds fail closed when distribution lookup errors."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        gav_index_vulns=["LW-2026-0001"],
        include_security_metadata=True,
        osv_records=[("LW-2026-0001", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_maven.list_distributions.side_effect = PulpError(
        "Maven distribution lookup failed",
        status_code=500,
        response_body="Internal Server Error",
    )
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-novel-landing",
            "--pulp-file-repository",
            "osv-java-novel",
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
    assert "Unable to verify the predisclosure distribution" in result.output
    mock_maven.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_rejects_predisclosure_distribution_for_foreign_repository(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """A predisclosure path cannot validate a different repository."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        gav_index_vulns=["LW-2026-0001"],
        include_security_metadata=True,
        osv_records=[("LW-2026-0001", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_maven.list_distributions.return_value = (
        _FOREIGN_PREDISCLOSURE_DISTRIBUTION,
    )

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-novel-landing",
            "--pulp-file-repository",
            "osv-java-novel",
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
    assert "not associated with a predisclosure distribution" in result.output
    mock_maven.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_dry_run_validates_embargoed_predisclosure_route(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """Embargoed dry runs validate routing before reporting success."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        gav_index_vulns=["LW-2026-0001"],
        include_security_metadata=True,
        osv_records=[("LW-2026-0001", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = CliRunner().invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-novel-landing",
            "--pulp-file-repository",
            "osv-java-novel",
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
    assert "dry-run: would upload" in result.output
    mock_maven.resolve_repository.assert_called_once_with("test-novel-landing")
    mock_maven.list_distributions.assert_called_once_with(_REPO_HREF)
    mock_maven.upload_content.assert_not_called()
    mock_maven.modify_repository.assert_not_called()
    mock_file.get_distribution_base_path.assert_called_once_with("osv-java-novel")
    mock_file.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_dry_run_rejects_embargoed_non_predisclosure_route(
    mock_maven_cls: Mock, tmp_path: Path
) -> None:
    """Embargoed dry runs fail closed on unsafe routing."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        gav_index_vulns=["LW-2026-0001"],
        include_security_metadata=True,
        osv_records=[("LW-2026-0001", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_maven.list_distributions.return_value = (_PUBLIC_DISTRIBUTION,)

    result = CliRunner().invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-novel-landing",
            "--pulp-file-repository",
            "osv-java-novel",
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
    assert "not associated with a predisclosure distribution" in result.output
    assert "dry-run: would upload" not in result.output
    mock_maven.upload_content.assert_not_called()


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
    assert "not OSV or VEX JSON" in result.output
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


def test_classify_cdx_source_vex_with_cve() -> None:
    """VEX with CVE- vulnerability IDs routes to pnc-build."""
    from slan_cuan.java.publish import _classify_cdx_source

    record = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [{"id": "CVE-2024-1234"}],
    }
    assert _classify_cdx_source(record, Path("test.bom.json")) == "pnc-build"


def test_classify_cdx_source_vex_with_lw() -> None:
    """VEX with LW- vulnerability IDs routes to novel-pipeline."""
    from slan_cuan.java.publish import _classify_cdx_source

    record = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [{"id": "LW-2026-00001"}],
    }
    assert _classify_cdx_source(record, Path("test.bom.json")) == "novel-pipeline"


def test_classify_cdx_source_sbom_with_cve_patches() -> None:
    """SBOM with CVE- patches routes to pnc-build."""
    from slan_cuan.java.publish import _classify_cdx_source

    record = {
        "bomFormat": "CycloneDX",
        "components": [
            {"pedigree": {"patches": [{"resolves": [{"id": "CVE-2024-5678"}]}]}}
        ],
    }
    assert _classify_cdx_source(record, Path("test.bom.json")) == "pnc-build"


def test_classify_cdx_source_clean_sbom_returns_none() -> None:
    """SBOM with no vulns and no patches returns None."""
    from slan_cuan.java.publish import _classify_cdx_source

    record = {
        "bomFormat": "CycloneDX",
        "components": [{"pedigree": {"patches": []}}],
    }
    assert _classify_cdx_source(record, Path("test.bom.json")) is None


def test_classify_cdx_source_mixed_sources_routes_novel() -> None:
    """Mixed CVE- and LW- sources route to novel-pipeline (embargo rule)."""
    from slan_cuan.java.publish import _classify_cdx_source

    record = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [
            {"id": "CVE-2024-1234"},
            {"id": "LW-2026-00001"},
        ],
    }
    assert _classify_cdx_source(record, Path("test.bom.json")) == "novel-pipeline"


def test_classify_cdx_source_filename_fallback() -> None:
    """When record has no IDs, filename prefix is used as fallback."""
    from slan_cuan.java.publish import _classify_cdx_source

    record = {"bomFormat": "CycloneDX"}
    assert (
        _classify_cdx_source(record, Path("CVE-2024-1234-2026.bom.json"))
        == "pnc-build"
    )
    assert _classify_cdx_source(record, Path("clean.bom.json")) is None


# File distributions as served in Pulp (distribution name == repository name).
# osv-java-novel is the existing novel stream, served at a predisclosure path.
_FILE_DISTRIBUTIONS = {
    "osv-java-backport": "osv/java/remediated",
    "osv-java-novel": "osv/java/predisclosure",
    "osv-java-novel-predisclosure": "osv/java/predisclosure",
    "vex-java-backport": "vex/java/remediated",
    "vex-java-novel": "vex/java/predisclosure",
    "vex-java-novel-predisclosure": "vex/java/predisclosure",
    "some-other-file-repo": "files/other",
}


def _setup_file_client(mock_file: Mock) -> None:
    """Configure mock file client with upload/autopublish verification."""
    mock_file.upload_content.return_value = _FILE_CONTENT_UNIT
    mock_file.resolve_repository.return_value = _FILE_REPO_HREF
    mock_file.modify_repository.return_value = _FILE_MODIFY_RESULT
    mock_file.get_distribution_repository.return_value = _FILE_REPO_HREF
    mock_file.get_repository_autopublish.return_value = True
    mock_file.get_distribution_base_path.side_effect = _FILE_DISTRIBUTIONS.get


def _run_publish_with_file_repo(
    artifact_dir: Path, file_repo: str, maven_repo: str = "test-repo"
) -> Result:
    """Invoke the publish command against a Pulp File repository."""
    runner = CliRunner()
    return runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            maven_repo,
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
def test_publish_embargoed_build_keeps_all_osv_records_in_predisclosure_repo(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """All OSV records of an LW- build go to the predisclosure OSV repo."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("LW-2026-0087", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    mock_file = _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_file_repo(
        artifact_dir,
        "osv-java-novel",
        maven_repo="lightwell-java-predisclosure",
    )

    assert result.exit_code == 0, result.output
    assert mock_file.upload_content.call_count == 2
    assert "Embargoed build: uploading all 2 OSV record(s)" in result.output
    assert "Warning: skipping" not in result.output
    assert "Security metadata: 2 file(s) uploaded" in result.output


@pytest.mark.parametrize(
    ("file_repo", "served"),
    [
        ("osv-java-backport", "'osv/java/remediated'"),
        ("some-other-file-repo", "'files/other'"),
        ("osv-java-unknown", "no distribution"),
    ],
)
@pytest.mark.parametrize("dry_run", [False, True])
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_embargoed_build_rejects_non_predisclosure_osv_repo(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    dry_run: bool,
    file_repo: str,
    served: str,
    tmp_path: Path,
) -> None:
    """Build-level LW- gate: the OSV repo must be served at a predisclosure path.

    Checked against the Pulp File distribution, before any upload and also in
    dry-run mode.
    """
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

    args = [
        "publish",
        "--pulp-url",
        "https://pulp.example.com",
        "--pulp-repository",
        "lightwell-java-predisclosure",
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
    ]
    result = CliRunner().invoke(main, (["--dry-run"] if dry_run else []) + args)

    assert result.exit_code != 0
    assert (
        f"--pulp-file-repository '{file_repo}' is served at {served}, not a "
        "predisclosure distribution" in result.output
    )
    mock_file.get_distribution_base_path.assert_called_once_with(file_repo)
    mock_maven.upload_content.assert_not_called()
    mock_file.upload_content.assert_not_called()


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_embargoed_build_fails_closed_on_file_distribution_lookup_error(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """An unreadable File distribution lookup fails closed before upload."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("LW-2026-0087", "novel-pipeline")],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)
    mock_file.get_distribution_base_path.side_effect = PulpError(
        "boom", status_code=500, response_body=""
    )

    result = _run_publish_with_file_repo(
        artifact_dir, "osv-java-novel", maven_repo="lightwell-java-predisclosure"
    )

    assert result.exit_code != 0
    assert "Unable to verify the predisclosure distribution of" in result.output
    mock_maven.upload_content.assert_not_called()
    mock_file.upload_content.assert_not_called()


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
            ("CVE-2025-11111", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    mock_maven = _make_ctx_mock()
    mock_maven_cls.return_value = mock_maven
    _setup_client_mock(mock_maven)
    mock_file = _make_ctx_mock()
    mock_file_cls.return_value = mock_file
    _setup_file_client(mock_file)

    result = _run_publish_with_file_repo(
        artifact_dir,
        "some-other-file-repo",
        maven_repo="lightwell-java-predisclosure",
    )

    assert result.exit_code == 0, result.output
    assert mock_file.upload_content.call_count == 2
    assert "not a recognized" in result.output


@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_all_records_skipped_no_upload(
    mock_maven_cls: Mock, mock_file_cls: Mock, tmp_path: Path
) -> None:
    """When every record is filtered out, nothing is uploaded."""
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
            ("CVE-2025-11111", "novel-pipeline"),
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
            "lightwell-java-predisclosure",
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
    """Validation accepts a legacy record beside the advisory.

    publish then drops the legacy record (LWLP-5093); see
    test_publish_never_uploads_legacy_x_rhlw_records.
    """
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
    rec = _new_format_record(
        advisory_id="RHLW-2026-aaaaaaaaaaaaaaaa", upstream=["CVE-2024-25710"]
    )
    (sec_dir / "RHLW-2026-aaaaaaaaaaaaaaaa.json").write_text(json.dumps(rec))

    files = (sec_dir / "RHLW-2026-aaaaaaaaaaaaaaaa.json",)
    with pytest.raises(ValueError, match="does not cover all"):
        _validate_security_metadata(files, ("CVE-2024-2571",))


def test_empty_aliases_and_upstream_rejected(tmp_path: Path) -> None:
    """A record with empty aliases and no upstream is not valid OSV."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()
    rec = {
        "id": "RHLW-2026-cccccccccccccccc",
        "aliases": [],
        "upstream": [],
        "affected": [{"package": {"name": "example"}}],
    }
    (sec_dir / "empty.json").write_text(json.dumps(rec))

    with pytest.raises(ValueError, match="not OSV or VEX"):
        _validate_security_metadata(
            (sec_dir / "empty.json",), ("CVE-2024-99999",)
        )


def test_null_aliases_and_upstream_handled(tmp_path: Path) -> None:
    """Explicit JSON null for aliases/upstream must not TypeError."""
    from slan_cuan.java.publish import _validate_security_metadata

    sec_dir = tmp_path / "sec"
    sec_dir.mkdir()
    rec = {
        "id": "RHLW-2026-dddddddddddddddd",
        "aliases": None,
        "upstream": None,
        "affected": [{"package": {"name": "example"}}],
    }
    (sec_dir / "null_fields.json").write_text(json.dumps(rec))

    files = (sec_dir / "null_fields.json",)
    with pytest.raises(ValueError, match="not OSV or VEX"):
        _validate_security_metadata(files, ("CVE-2024-25710",))


_GITHUB_OSV_REPO = "project-lightwell/lightwell-osv"


def _run_publish_with_github(
    artifact_dir: Path,
    file_repo: str,
    *github_args: str,
    maven_repo: str = "test-repo",
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
            maven_repo,
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


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_pushes_only_backport_osv_records_to_github(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """GitHub gets pnc-build OSV records only."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2026-1111", "pnc-build")],
    )
    mock_file = _setup_pulp_mocks(mock_maven_cls, mock_file_cls)
    mock_gh = Mock()
    mock_gh.publish.return_value = "abc123"
    mock_gh_cls.return_value = mock_gh

    result = _run_publish_with_github(
        artifact_dir, "osv-java-backport", *_GITHUB_ENABLED_ARGS
    )

    assert result.exit_code == 0, result.output
    assert mock_file.upload_content.call_count == 1
    assert mock_gh_cls.call_args.args == (_GITHUB_OSV_REPO, "ghp_secret")
    assert mock_gh_cls.call_args.kwargs["path"] == "advisories"
    pushed_files, commit_message = mock_gh.publish.call_args.args
    assert [p.name for p in pushed_files] == [f"{_rhlw_id('CVE-2026-1111')}.json"]
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
            ("CVE-2026-3333", "novel-pipeline"),
        ],
    )
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)
    mock_gh = Mock()
    mock_gh.publish.return_value = "abc123"
    mock_gh_cls.return_value = mock_gh

    result = _run_publish_with_github(
        artifact_dir,
        "osv-java-backport",
        *_GITHUB_ENABLED_ARGS,
    )

    assert result.exit_code == 0, result.output
    pushed_files = mock_gh.publish.call_args.args[0]
    assert [p.name for p in pushed_files] == [f"{_rhlw_id('CVE-2026-2222')}.json"]
    assert (
        f"GitHub OSV: skipping {_rhlw_id('CVE-2026-3333')}.json" in result.output
    )


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


# --- Pedigree enrichment tests ---


def _create_pedigree_sidecar(
    security_metadata_dir: Path,
    *,
    group_id: str = "org.example",
    artifact_id: str = "lib",
    version: str = "1.0.0.rhlw-00001",
    base_version: str = "1.0.0",
    repo_url: str = ("https://packages.redhat.com/lightwell/java/validated/"),
    vulns: list[str] | None = None,
) -> Path:
    """Write a pedigree sidecar JSON file and return its path."""
    if vulns is None:
        vulns = []
    has_lw = any(v.startswith("LW-") for v in vulns)
    has_cves = any(not v.startswith("LW-") for v in vulns)

    patches = []
    for v in vulns:
        if not v.startswith("LW-"):
            patches.append(
                {
                    "type": "backport",
                    "resolves": [
                        {
                            "type": "security",
                            "id": v,
                            "source": {
                                "name": "NVD",
                                "url": (f"https://nvd.nist.gov/vuln/detail/{v}"),
                            },
                        }
                    ],
                }
            )

    if has_lw:
        notes = (
            f"Lightwell novel fix: embargoed security fixes to "
            f"{artifact_id} {base_version}. Build {version}."
        )
    elif has_cves:
        notes = (
            f"Lightwell remediation: backported security fixes to "
            f"{artifact_id} {base_version}. Build {version}."
        )
    else:
        notes = (
            f"Lightwell validated build of "
            f"{artifact_id} {base_version}. Build {version}."
        )

    pedigree = {
        "ancestors": [
            {
                "type": "library",
                "group": group_id,
                "name": artifact_id,
                "version": base_version,
                "purl": (f"pkg:maven/{group_id}/{artifact_id}@{base_version}"),
            }
        ],
        "patches": patches,
        "notes": notes,
    }
    sidecar = {
        "group_id": group_id,
        "artifact_id": artifact_id,
        "version": version,
        "base_version": base_version,
        "repository_url": repo_url,
        "pedigree": pedigree,
        "serial_number": "urn:uuid:test-serial-00001",
        "purl_qualified": (
            f"pkg:maven/{group_id}/{artifact_id}@{version}"
            f"?repository_url={repo_url}&type=jar"
        ),
        "timestamp": "2026-01-01T00:00:00Z",
    }
    security_metadata_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{group_id}.{artifact_id}-{version}.pedigree.json"
    path = security_metadata_dir / filename
    path.write_text(json.dumps(sidecar, indent=2))
    return path


def test_enriched_sboms_filtered_from_security_metadata(
    tmp_path: Path,
) -> None:
    """enriched-sboms/ directory must not appear in security_metadata_files."""
    sec_dir = tmp_path / "security_metadata"
    sec_dir.mkdir()

    # Write an enriched SBOM in the enriched-sboms/ subdirectory
    enriched_dir = (
        sec_dir / "enriched-sboms" / "org" / "example" / "lib" / "1.0.0"
    )
    enriched_dir.mkdir(parents=True)
    (enriched_dir / "lib-1.0.0.bom.json").write_text('{"bomFormat":"CycloneDX"}')

    # Write a pedigree sidecar and a regular OSV record
    _create_pedigree_sidecar(sec_dir)
    osv = _new_format_record(
        advisory_id="RHLW-2026-eeeeeeeeeeeeeeee", upstream=["CVE-2024-1234"]
    )
    (sec_dir / "RHLW-2026-eeeeeeeeeeeeeeee.json").write_text(json.dumps(osv))

    # Simulate the filtering logic from publish
    all_files = tuple(f for f in sec_dir.rglob("*") if f.is_file())
    filtered = tuple(
        f
        for f in all_files
        if f.is_file()
        and not f.name.endswith(".pedigree.json")
        and "enriched-sboms" not in f.relative_to(sec_dir).parts
    )

    assert len(all_files) == 3  # enriched SBOM + sidecar + OSV
    assert len(filtered) == 1
    assert filtered[0].name == "RHLW-2026-eeeeeeeeeeeeeeee.json"


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_github_refused_for_embargoed_build(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """Nothing from an LW- build reaches the public GitHub OSV repository.

    Not even the CVE record, and without relying on per-record
    classification. Pulp predisclosure publication still happens.
    """
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("CVE-2026-2222", "pnc-build"),
            ("LW-2026-0001", "novel-pipeline"),
        ],
    )
    mock_file = _setup_pulp_mocks(mock_maven_cls, mock_file_cls)
    results_dir = tmp_path / "tekton-results"
    results_dir.mkdir()

    result = CliRunner().invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "lightwell-java-predisclosure",
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
            *_GITHUB_ENABLED_ARGS,
        ],
    )

    assert result.exit_code == 0, result.output
    mock_gh_cls.assert_not_called()
    assert "not publishing to the public repository" in result.output
    assert mock_file.upload_content.call_count == 2
    assert (results_dir / "GITHUB_OSV_UPLOADED").read_text() == "0"
    assert (results_dir / "GITHUB_OSV_COMMIT").read_text() == ""


@pytest.mark.parametrize("vex_repo", ["vex-java-backport"])
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_embargoed_build_rejects_non_predisclosure_vex_repo(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    vex_repo: str,
    tmp_path: Path,
) -> None:
    """Build-level gate applies to VEX even when the VEX has no LW- ID."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[
            ("LW-2026-0087", "novel-pipeline"),
            ("CVE-2025-48924", "pnc-build"),
        ],
    )
    # Only a CVE-only VEX: a content-only check would let it through.
    _add_vex_document(artifact_dir, "CVE-2025-48924")
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = CliRunner().invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "lightwell-java-predisclosure",
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
            "--pulp-vex-repository",
            vex_repo,
        ],
    )

    assert result.exit_code != 0
    assert (
        f"--pulp-vex-repository '{vex_repo}' is served at 'vex/java/remediated', "
        "not a predisclosure distribution" in result.output
    )
    mock_file = mock_file_cls.return_value
    mock_file.upload_content.assert_not_called()
    mock_maven_cls.return_value.upload_content.assert_not_called()


def test_verify_requires_vex_repository_checks() -> None:
    """VEX repo: required, distinct from the OSV repo, recognized by name."""
    import click

    from slan_cuan.java.publish import (
        _metadata_has_embargo,
        _verify_requires_vex_repository,
    )

    cve_vex = Path("CVE-2026-1-2026-08-06T16:00:00Z.bom.json")
    lw_vex = Path("LW-2026-1-2026-08-06T16:00:00Z.bom.json")
    lw_openvex = Path("openvex-2026-08-06T16:00:00Z.bom.json")
    records = {
        cve_vex: {
            "bomFormat": "CycloneDX",
            "vulnerabilities": [{"id": "CVE-2026-1"}],
        },
        lw_vex: {
            "bomFormat": "CycloneDX",
            "vulnerabilities": [{"id": "LW-2026-1"}],
        },
        lw_openvex: {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{"vulnerability": {"name": "LW-2026-1"}}],
        },
    }

    assert _verify_requires_vex_repository((), None) is False
    with pytest.raises(
        click.UsageError, match="--pulp-vex-repository is required"
    ):
        _verify_requires_vex_repository((cve_vex,), None)
    with pytest.raises(click.UsageError, match="must differ"):
        _verify_requires_vex_repository(
            (cve_vex,), "vex-java-backport", "vex-java-backport", records
        )
    with pytest.raises(click.UsageError, match="not recognized"):
        _verify_requires_vex_repository(
            (cve_vex,), "vex/java/remediated", "osv-java-backport", records
        )
    # LW- content (also in OpenVEX) makes the build embargoed; its VEX
    # repository is then checked against its Pulp distribution.
    assert _metadata_has_embargo({lw_openvex: records[lw_openvex]})
    assert _verify_requires_vex_repository(
        (cve_vex,), "vex-java-backport", "osv-java-backport", records
    )
    assert _verify_requires_vex_repository(
        (lw_vex,),
        "vex-java-novel",
        "osv-java-novel",
        records,
    )


def test_metadata_has_embargo_detects_lw_content() -> None:
    """LW- IDs are found in OSV id/aliases/upstream and VEX vulnerabilities."""
    from slan_cuan.java.publish import _metadata_has_embargo

    def has(record: dict[str, object]) -> bool:
        return _metadata_has_embargo({Path("f.json"): record})

    assert has({"id": "x_RHLW-LW-2026-0001-1.0.0"})
    assert has({"id": "RHLW-2026-0123456789abcdef", "upstream": ["LW-2026-1"]})
    assert has({"id": "x_RHLW-CVE-2026-1-1.0.0", "aliases": ["LW-2026-1"]})
    assert has(
        {"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "LW-2026-1"}]}
    )
    assert has(
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{"vulnerability": {"name": "LW-2026-1"}}],
        }
    )
    assert not has(
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{"vulnerability": {"name": "CVE-2026-1"}}],
        }
    )
    # The LW inside RHLW is never mistaken for an LW- ID.
    assert not has(
        {"id": "RHLW-2026-0123456789abcdef", "upstream": ["CVE-2026-1", "GHSA-x"]}
    )
    assert not has({"id": "x_RHLW-CVE-2026-1-1.0.0", "aliases": ["CVE-2026-1"]})


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_lw_content_without_lw_in_gav_index_is_embargoed(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """LW- content in generated files makes the build embargoed.

    Even when the GAV index lists only CVEs (fail closed on inconsistent input).
    """
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2025-48924", "pnc-build")],
    )
    _add_vex_document(artifact_dir, "LW-2026-0087")
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_github(
        artifact_dir,
        "osv-java-backport",
        "--pulp-vex-repository",
        "vex-java-novel",
        *_GITHUB_ENABLED_ARGS,
    )

    assert result.exit_code != 0
    assert "treating the build as embargoed" in result.output
    assert (
        "--pulp-file-repository 'osv-java-backport' is served at "
        "'osv/java/remediated', not a predisclosure distribution" in result.output
    )
    mock_maven_cls.return_value.upload_content.assert_not_called()
    mock_file_cls.return_value.upload_content.assert_not_called()
    mock_gh_cls.assert_not_called()


# --- LWLP-5093: legacy per-CVE x_RHLW- records are never published ---------


def _add_legacy_osv_record(artifact_dir: Path, vuln_id: str) -> Path:
    """Add a legacy per-CVE x_RHLW- record next to the advisory."""
    osv_id = f"x_RHLW-{vuln_id}-1.0.0"
    path = (
        artifact_dir
        / "TEST-build-output"
        / "security_metadata"
        / f"{osv_id}.json"
    )
    path.write_text(
        json.dumps(
            {
                "id": osv_id,
                "aliases": [vuln_id],
                "affected": [
                    {
                        "package": {"name": "example"},
                        "database_specific": {
                            "lightwell": {"source": "pnc-build"}
                        },
                    }
                ],
            }
        )
    )
    return path


def test_is_legacy_osv_record_uses_id_then_file_name(tmp_path: Path) -> None:
    """The record id decides; the file name is only a fallback."""
    from slan_cuan.java.publish import _is_legacy_osv_record

    legacy = tmp_path / "x_RHLW-CVE-2026-1-1.0.0.json"
    advisory = tmp_path / "RHLW-2026-aaaaaaaaaaaaaaaa.json"
    assert _is_legacy_osv_record(legacy, {"id": "x_RHLW-CVE-2026-1-1.0.0"})
    assert _is_legacy_osv_record(legacy, None)
    assert not _is_legacy_osv_record(
        advisory, {"id": "RHLW-2026-aaaaaaaaaaaaaaaa"}
    )
    assert _is_legacy_osv_record(advisory, {"id": "x_RHLW-CVE-2026-1-1.0.0"})


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_never_uploads_legacy_x_rhlw_records(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """Only the RHLW- advisory reaches Pulp and GitHub; x_RHLW- is skipped."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2026-1111", "pnc-build")],
    )
    legacy = _add_legacy_osv_record(artifact_dir, "CVE-2026-1111")
    mock_file = _setup_pulp_mocks(mock_maven_cls, mock_file_cls)
    mock_gh = Mock()
    mock_gh.publish.return_value = "abc123"
    mock_gh_cls.return_value = mock_gh
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    result = CliRunner().invoke(
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
            "osv-java-backport",
            *_GITHUB_ENABLED_ARGS,
        ],
    )

    assert result.exit_code == 0, result.output
    advisory = f"{_rhlw_id('CVE-2026-1111')}.json"
    uploaded = [
        call.kwargs["relative_path"]
        for call in mock_file.upload_content.call_args_list
    ]
    assert uploaded == [advisory]
    pushed_files = mock_gh.publish.call_args.args[0]
    assert [p.name for p in pushed_files] == [advisory]
    assert f"Skipping legacy per-CVE OSV record {legacy.name}" in result.output
    assert (results_dir / "SECURITY_METADATA_SKIPPED").read_text().strip() == "1"


@patch("slan_cuan.java.publish.GitHubOsvClient")
@patch("slan_cuan.java.publish.PulpFileClient")
@patch("slan_cuan.java.publish.PulpMavenClient")
def test_publish_lw_id_in_legacy_record_still_embargoes_the_build(
    mock_maven_cls: Mock,
    mock_file_cls: Mock,
    mock_gh_cls: Mock,
    tmp_path: Path,
) -> None:
    """Dropped legacy records still count for the LW- gate (fail closed)."""
    artifact_dir = create_test_artifact_dir(
        tmp_path,
        include_security_metadata=True,
        osv_records=[("CVE-2026-1111", "pnc-build")],
    )
    _add_legacy_osv_record(artifact_dir, "LW-2026-0001")
    _setup_pulp_mocks(mock_maven_cls, mock_file_cls)

    result = _run_publish_with_github(
        artifact_dir, "osv-java-backport", *_GITHUB_ENABLED_ARGS
    )

    assert "treating the build as embargoed" in result.output
    mock_gh_cls.assert_not_called()
