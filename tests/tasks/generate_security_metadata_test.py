"""Unit tests for the generate-security-metadata subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner
from fath_cuan.workflow import resolve_module_vulns as real_resolve_module_vulns

from slan_cuan.models import EXTRACT_RESULT_FILENAME, ExtractResult, GlobalContext
from slan_cuan.tasks.generate_security_metadata import (
    generate_security_metadata,
)


def _primary_module_name(index_data: dict) -> str:
    if "primaryGav" in index_data:
        group, artifact, _ = index_data["primaryGav"].split(":")
        return f"{group}:{artifact}"
    from packageurl import PackageURL

    purl = PackageURL.from_string(index_data["primaryPurl"])
    return f"{purl.namespace}:{purl.name}" if purl.namespace else purl.name


@pytest.fixture(autouse=True)
def primary_placement():
    """Place every vulnerability on the primary module, without network calls.

    fath-cuan's resolve_module_vulns() looks the vulnerabilities up on
    osv.dev/OSIDB; the generate tests use this stand-in (the behaviour for a
    build whose fixes are all in the primary module) unless they patch
    resolve_module_vulns themselves.
    """

    def _place(index_data: dict, osidb_client=None) -> dict[str, list[str]]:
        vulns = list(index_data.get("vulns") or [])
        return {_primary_module_name(index_data): vulns} if vulns else {}

    with patch(
        "slan_cuan.tasks.generate_security_metadata.resolve_module_vulns",
        side_effect=_place,
    ) as mock_place:
        yield mock_place


@pytest.fixture
def ctx() -> GlobalContext:
    """Default non-verbose, non-dry-run context."""
    return GlobalContext(
        verbose=False,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=None,
    )


@pytest.fixture
def fake_osv_records() -> list[dict]:
    """Sample OSV records as returned by process_osv."""
    return [
        {
            "id": "x_RHLW-CVE-2024-001-1.0.0",
            "summary": "Buffer overflow in example-lib",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:example-lib",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }
    ]


def _create_index_file(directory: Path, name: str = "gav-index.json") -> Path:
    """Write a minimal build-index JSON file into *directory*."""
    data = {
        "buildId": "12345",
        "vulns": ["CVE-2024-1234"],
        "primaryGav": "org.example:lib:1.0.0",
        "artifacts": [
            {
                "groupId": "org.example",
                "artifactId": "lib",
                "version": "1.0.0",
            }
        ],
    }
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def _create_extract_result(workdir: Path, create_repo: bool = False) -> None:
    """Write a minimal extract-result.json into *workdir*.

    When *create_repo* is True, also create the ``repository/``
    subdirectory so that ``repo_dir`` resolves in production code.
    """
    data = {
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
        "extracted_at": "2026-06-19T12:00:00Z",
    }
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / EXTRACT_RESULT_FILENAME).write_text(json.dumps(data, indent=2))
    if create_repo:
        repo_dir = workdir / "TEST-build-output" / "repository"
        repo_dir.mkdir(parents=True, exist_ok=True)


def _invoke(
    runner,
    index_basedir,
    output_dir,
    ctx,
    index_filename=None,
    workdir=None,
    osidb_keytab=None,
    osidb_kerberos_principal="user@REALM",
    osidb_api_url="https://osidb.example.com/api/v1",
    advisory_id=None,
):
    args = [
        "--index-basedir",
        str(index_basedir),
        "--output-dir",
        str(output_dir),
        "--osidb-api-url",
        osidb_api_url,
        "--osidb-kerberos-principal",
        osidb_kerberos_principal,
    ]
    if workdir is not None:
        args += ["--workdir", str(workdir)]
    if index_filename is not None:
        args += ["--index-filename", index_filename]
    if osidb_keytab is not None:
        args += ["--osidb-keytab", str(osidb_keytab)]
    if advisory_id is not None:
        args += ["--advisory-id", advisory_id]
    return runner.invoke(generate_security_metadata, args, obj=ctx)


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_creates_osv_output(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Successful attestation writes an OSV file from the index."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert "Processing" in result.output
    assert "Security metadata generation completed" in result.output

    assert output_dir.is_dir()
    osv_file = output_dir / "x_RHLW-CVE-2024-001-1.0.0.json"
    assert osv_file.exists()

    written = json.loads(osv_file.read_text())
    assert written == fake_osv_records[0]

    updated_result = ExtractResult.from_file(workdir / EXTRACT_RESULT_FILENAME)
    assert updated_result.security_metadata_dir == "security_metadata"


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_custom_filename(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A custom --index-filename produces an OSV file named after the stem."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir, name="cve-report.json")

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        index_filename="cve-report.json",
        workdir=workdir,
    )

    assert result.exit_code == 0, result.output

    osv_file = output_dir / "x_RHLW-CVE-2024-001-1.0.0.json"
    assert osv_file.exists()

    written = json.loads(osv_file.read_text())
    assert written == fake_osv_records[0]


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_passes_index_data_to_process_osv(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """process_osv receives the parsed JSON data from the index file."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    index_data = {"buildId": "99", "artifacts": []}
    (index_dir / "gav-index.json").write_text(json.dumps(index_data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = []

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_process_osv.assert_called_once_with(
        index_data,
        osidb_client=None,
        module_vulns=None,
        repository_url="https://packages.redhat.com/lightwell/java/validated/",
    )


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_writes_tekton_results(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    tmp_path: Path,
) -> None:
    """SECURITY_METADATA_DIR Tekton result is written when results dir is set."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"
    results_dir = tmp_path / "results"

    mock_process_osv.return_value = fake_osv_records

    tekton_ctx = GlobalContext(
        verbose=False,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=results_dir,
    )

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, tekton_ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    security_metadata_dir_file = results_dir / "SECURITY_METADATA_DIR"
    assert security_metadata_dir_file.exists()
    assert security_metadata_dir_file.read_text() == str(output_dir)


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generate_security_metadata_creates_nested_output_dir(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Nested output_dir is created with intermediate parents."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "nested" / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert output_dir.is_dir()
    assert (output_dir / "x_RHLW-CVE-2024-001-1.0.0.json").exists()


def test_generate_security_metadata_missing_required_options() -> None:
    """Missing --index-basedir or --output-dir produces an error."""
    runner = CliRunner()

    result = runner.invoke(
        generate_security_metadata, ["--output-dir", "/tmp/out"]
    )
    assert result.exit_code != 0

    result = runner.invoke(
        generate_security_metadata, ["--index-basedir", "/tmp/idx"]
    )
    assert result.exit_code != 0


def test_generate_security_metadata_allows_omitted_osidb_options(
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Omitting the osidb-* options is allowed (they default to empty)."""
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    runner = CliRunner()
    result = runner.invoke(
        generate_security_metadata,
        [
            "--index-basedir",
            str(tmp_path / "nonexistent"),
            "--output-dir",
            str(workdir / "security_metadata"),
            "--workdir",
            str(workdir),
        ],
        obj=ctx,
    )

    assert result.exit_code == 0, result.output
    assert "osidb-api-url" not in result.output
    assert "osidb-kerberos-principal" not in result.output


def test_generate_security_metadata_allows_empty_osidb_options(
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Passing empty strings for the osidb-* options is allowed."""
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    runner = CliRunner()
    result = runner.invoke(
        generate_security_metadata,
        [
            "--index-basedir",
            str(tmp_path / "nonexistent"),
            "--output-dir",
            str(workdir / "security_metadata"),
            "--workdir",
            str(workdir),
            "--osidb-api-url",
            "",
            "--osidb-kerberos-principal",
            "",
            "--osidb-keytab",
            "",
        ],
        obj=ctx,
    )

    assert result.exit_code == 0, result.output


def test_generate_security_metadata_file_not_found(
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A missing index file skips generation gracefully."""
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = workdir / "security_metadata"

    runner = CliRunner()
    result = _invoke(
        runner, tmp_path / "nonexistent", output_dir, ctx, workdir=workdir
    )

    assert result.exit_code == 0
    assert "skipping security metadata generation" in result.output
    assert not output_dir.exists()


# ── OSIDB authentication tests ──────────────────────────────────


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_no_keytab_skips_osidb(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Without a keytab, OSIDB is skipped and process_osv gets None."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert "skipping OSIDB fetching" in result.output
    mock_process_osv.assert_called_once()
    call_args = mock_process_osv.call_args
    assert call_args[1]["osidb_client"] is None
    assert "advisory_id" in call_args[0][0]


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_nonexistent_keytab_skips_osidb(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A keytab path that doesn't exist skips OSIDB."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=tmp_path / "missing.keytab",
    )

    assert result.exit_code == 0, result.output
    assert "skipping OSIDB fetching" in result.output
    mock_process_osv.assert_called_once()
    call_args = mock_process_osv.call_args
    assert call_args[1]["osidb_client"] is None
    assert "advisory_id" in call_args[0][0]


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_empty_vulnerabilities_skip_osidb_with_valid_keytab(
    mock_process_osv: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Validated builds skip OSIDB even when a keytab is available."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    index_path = _create_index_file(index_dir)
    index_data = json.loads(index_path.read_text())
    index_data["vulns"] = []
    index_path.write_text(json.dumps(index_data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"
    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")
    mock_process_osv.return_value = fake_osv_records

    result = _invoke(
        CliRunner(),
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=keytab,
    )

    assert result.exit_code == 0, result.output
    assert "No vulnerabilities found in index" in result.output
    mock_get_token.assert_not_called()
    mock_osidb_client_cls.assert_not_called()
    mock_process_osv.assert_called_once_with(
        index_data,
        osidb_client=None,
        module_vulns=None,
        repository_url="https://packages.redhat.com/lightwell/java/validated/",
    )


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_valid_keytab_creates_osidb_client(
    mock_process_osv: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A valid keytab authenticates and passes the client to process_osv."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")

    mock_get_token.return_value = "jwt-token-123"
    mock_client = MagicMock()
    mock_client.available = True
    mock_osidb_client_cls.return_value = mock_client
    mock_process_osv.return_value = fake_osv_records

    api_url = "https://osidb.example.com/api/v1"
    principal = "user@REALM"

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=keytab,
        osidb_kerberos_principal=principal,
        osidb_api_url=api_url,
    )

    assert result.exit_code == 0, result.output
    assert "Creating OSIDB client" in result.output

    mock_get_token.assert_called_once_with(
        api_url, principal, str(keytab), verbose=False
    )
    mock_osidb_client_cls.assert_called_once_with(
        base_url="https://osidb.example.com", token="jwt-token-123"
    )
    mock_process_osv.assert_called_once()
    call_args = mock_process_osv.call_args
    assert call_args[1]["osidb_client"] is mock_client
    assert "advisory_id" in call_args[0][0]


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_osidb_client_unavailable_aborts(
    mock_process_osv: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """When OsidbClient reports unavailable, the command aborts."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")

    mock_get_token.return_value = "jwt-token-123"
    mock_client = MagicMock()
    mock_client.available = False
    mock_osidb_client_cls.return_value = mock_client

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        osidb_keytab=keytab,
    )

    assert result.exit_code != 0
    assert "Failed to create OSIDB client" in result.output
    mock_process_osv.assert_not_called()


@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_uses_spnego(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
) -> None:
    """_get_osidb_auth_token gets a TGT and negotiates via SPNEGO."""
    import os
    import tempfile

    from slan_cuan.tasks.generate_security_metadata import (
        _get_osidb_auth_token,
    )

    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.json.return_value = {"access": "my-jwt"}
    mock_session = MagicMock()
    mock_session.get.return_value = mock_response
    mock_session_cls.return_value = mock_session

    token = _get_osidb_auth_token(
        "https://osidb.example.com/api/v1",
        "user@REALM",
        "/path/to/keytab",
    )

    assert token == "my-jwt"
    expected_ccache = os.path.join(tempfile.gettempdir(), "osidb_krb5cc")
    mock_krbticket_cls.init.assert_called_once_with(
        "user@REALM", keytab="/path/to/keytab", ccache_name=expected_ccache
    )
    call_args = mock_session.get.call_args
    assert call_args[0][0] == "https://osidb.example.com/auth/token"
    mock_response.raise_for_status.assert_called_once()


@patch("slan_cuan.tasks.generate_security_metadata.time.sleep")
@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_retries_on_failure(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
    mock_sleep: Mock,
) -> None:
    """_get_osidb_auth_token retries transient failures and succeeds."""
    import requests

    from slan_cuan.tasks.generate_security_metadata import _get_osidb_auth_token

    ok_response = MagicMock()
    ok_response.json.return_value = {"access": "my-jwt"}
    mock_session = MagicMock()
    mock_session.get.side_effect = [
        requests.exceptions.ConnectionError("boom"),
        requests.exceptions.ConnectionError("boom again"),
        ok_response,
    ]
    mock_session_cls.return_value = mock_session

    token = _get_osidb_auth_token(
        "https://osidb.example.com/api/v1",
        "user@REALM",
        "/path/to/keytab",
    )

    assert token == "my-jwt"
    assert mock_session.get.call_count == 3
    assert mock_sleep.call_count == 2


@patch("slan_cuan.tasks.generate_security_metadata.time.sleep")
@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_raises_after_max_retries(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
    mock_sleep: Mock,
) -> None:
    """_get_osidb_auth_token raises once all retries are exhausted."""
    import click
    import requests

    from slan_cuan.tasks.generate_security_metadata import (
        _OSIDB_TOKEN_MAX_RETRIES,
        _get_osidb_auth_token,
    )

    mock_session = MagicMock()
    mock_session.get.side_effect = requests.exceptions.ConnectionError("boom")
    mock_session_cls.return_value = mock_session

    with pytest.raises(click.ClickException, match="Failed to retrieve OSIDB"):
        _get_osidb_auth_token(
            "https://osidb.example.com/api/v1",
            "user@REALM",
            "/path/to/keytab",
        )

    assert mock_session.get.call_count == _OSIDB_TOKEN_MAX_RETRIES


@patch("slan_cuan.tasks.generate_security_metadata.time.sleep")
@patch("requests.Session")
@patch("krbticket.KrbTicket")
def test_get_osidb_auth_token_missing_access_key(
    mock_krbticket_cls: Mock,
    mock_session_cls: Mock,
    mock_sleep: Mock,
) -> None:
    """_get_osidb_auth_token fails when the 'access' key is absent."""
    import click

    from slan_cuan.tasks.generate_security_metadata import _get_osidb_auth_token

    bad_response = MagicMock()
    bad_response.json.return_value = {"detail": "unauthorized"}
    mock_session = MagicMock()
    mock_session.get.return_value = bad_response
    mock_session_cls.return_value = mock_session

    with pytest.raises(click.ClickException, match="Failed to retrieve OSIDB"):
        _get_osidb_auth_token(
            "https://osidb.example.com/api/v1",
            "user@REALM",
            "/path/to/keytab",
        )


# ---------------------------------------------------------------------------
# Advisory ID injection tests
# ---------------------------------------------------------------------------


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_advisory_id_injected(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """advisory_id appears in the dict passed to process_osv."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    aid = "RHLW-2026-aaaaaaaaaaaaaaaa"
    mock_process_osv.return_value = [{"id": aid, "affected": []}]

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        advisory_id=aid,
    )
    assert result.exit_code == 0, result.output
    call_args = mock_process_osv.call_args
    index_data = call_args[0][0]
    assert index_data["advisory_id"] == aid


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_advisory_id_auto_derived(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Without --advisory-id, the derived ID is injected automatically."""
    from slan_cuan.tasks.generate_security_metadata import (
        _ADVISORY_ID_RE,
    )

    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)
    assert result.exit_code == 0, result.output
    call_args = mock_process_osv.call_args
    index_data = call_args[0][0]
    assert "advisory_id" in index_data
    assert _ADVISORY_ID_RE.match(index_data["advisory_id"])


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_output_filename_uses_advisory_id(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Output file is named with a valid MurmurHash advisory ID."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    aid = "RHLW-2026-aaaaaaaaaaaaaaaa"
    mock_process_osv.return_value = [{"id": aid, "affected": []}]

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        advisory_id=aid,
    )
    assert result.exit_code == 0, result.output
    assert (output_dir / f"{aid}.json").exists()


# ---------------------------------------------------------------------------
# _derive_advisory_id tests
# ---------------------------------------------------------------------------


def test_derive_advisory_id_purl_path() -> None:
    """PURL-based build index produces a deterministic MurmurHash ID."""
    from slan_cuan.tasks.generate_security_metadata import (
        _ADVISORY_ID_RE,
        _derive_advisory_id,
    )

    index = {
        "ecosystem": "maven",
        "primaryPurl": "pkg:maven/org.example/artifact@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/artifact@1.0.0.rhlw-00001"],
        "vulns": ["CVE-2024-25710"],
        "created": "2026-07-15T14:02:27+00:00",
    }
    result = _derive_advisory_id(index)
    assert result is not None
    assert _ADVISORY_ID_RE.match(result)
    assert result == "RHLW-2026-5fc0229c48c1b99c"


def test_derive_advisory_id_gav_path() -> None:
    """GAV-based build index produces a deterministic MurmurHash ID."""
    from slan_cuan.tasks.generate_security_metadata import (
        _ADVISORY_ID_RE,
        _derive_advisory_id,
    )

    index = {
        "primaryGav": "org.example:artifact:1.0.0.rhlw-00001",
        "vulns": ["CVE-2024-25710"],
        "created": "2026-07-15T14:02:27+00:00",
    }
    result = _derive_advisory_id(index)
    assert result is not None
    assert _ADVISORY_ID_RE.match(result)
    assert result == "RHLW-2026-5fc0229c48c1b99c"


def test_derive_advisory_id_deterministic() -> None:
    """Same input always produces the same hash."""
    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "primaryGav": "org.example:artifact:1.0.0.rhlw-00001",
        "vulns": ["CVE-2024-25710"],
        "created": "2026-07-15T14:02:27+00:00",
    }
    assert _derive_advisory_id(index) == _derive_advisory_id(index)


def test_derive_advisory_id_no_vulns() -> None:
    """No vulns returns None."""
    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {"primaryGav": "org.example:artifact:1.0.0", "vulns": []}
    assert _derive_advisory_id(index) is None


def test_derive_advisory_id_no_primary() -> None:
    """Missing primary purl and GAV raises ClickException."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {"vulns": ["CVE-2024-25710"]}
    with pytest.raises(click.ClickException, match="no primaryGav"):
        _derive_advisory_id(index)


def test_derive_advisory_id_missing_version() -> None:
    """A GAV with no version raises ClickException."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "primaryGav": "org.example:artifact:",
        "vulns": ["CVE-2024-25710"],
    }
    with pytest.raises(click.ClickException, match="empty version"):
        _derive_advisory_id(index)


def test_derive_advisory_id_bad_ecosystem() -> None:
    """Unsupported ecosystem raises ClickException."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "ecosystem": "npm",
        "purls": ["pkg:npm/foo@1.0.0"],
        "vulns": ["CVE-2024-25710"],
    }
    with pytest.raises(click.ClickException, match="not supported"):
        _derive_advisory_id(index)


def test_derive_advisory_id_golden_value() -> None:
    """Golden-value test with a synthetic package."""
    from slan_cuan.tasks.generate_security_metadata import (
        _derive_advisory_id,
    )

    index = {
        "ecosystem": "maven",
        "primaryPurl": "pkg:maven/com.example/foobar@1.0.0.rhlw-00042",
        "purls": ["pkg:maven/com.example/foobar@1.0.0.rhlw-00042"],
        "vulns": ["CVE-2099-00001"],
        "created": "2026-01-01T00:00:00+00:00",
    }
    result = _derive_advisory_id(index)
    assert result == "RHLW-2026-1c8a4ea22ac9467c"


# ---------------------------------------------------------------------------
# _validate_advisory_id tests
# ---------------------------------------------------------------------------


def test_validate_advisory_id_accepts_valid() -> None:
    """Valid MurmurHash-format ID is accepted."""
    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    result = _validate_advisory_id(None, None, "RHLW-2026-5fc0229c48c1b99c")
    assert result == "RHLW-2026-5fc0229c48c1b99c"


def test_validate_advisory_id_rejects_old_dot_format() -> None:
    """Old dot-delimited format is rejected."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    with pytest.raises(click.BadParameter, match="must match"):
        _validate_advisory_id(None, None, "RHLW-Maven.org.example:artifact.1.0.0")


def test_validate_advisory_id_rejects_old_numeric() -> None:
    """Old numeric ID is rejected."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    with pytest.raises(click.BadParameter, match="must match"):
        _validate_advisory_id(None, None, "RHLW-2026-00042")


def test_validate_advisory_id_rejects_path_separator() -> None:
    """Path separators in the ID are rejected by the regex."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _validate_advisory_id,
    )

    with pytest.raises(click.BadParameter, match="must match"):
        _validate_advisory_id(None, None, "RHLW-2026-5fc0229c/8c1b99c")


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_derived_id_malformed_raises(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A malformed derived ID raises ClickException."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata._derive_advisory_id",
        return_value="RHLW-bad-format",
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)
    assert result.exit_code != 0
    assert "malformed" in result.output


@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_override_divergence_warning(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """When --advisory-id diverges from derivation, a warning is emitted."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "12345",
        "vulns": ["CVE-2024-1234"],
        "primaryGav": "org.example:lib:1.0.0",
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"
    mock_process_osv.return_value = []

    override_id = "RHLW-2026-aaaaaaaaaaaaaaaa"
    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        workdir=workdir,
        advisory_id=override_id,
    )
    assert result.exit_code == 0, result.output
    assert "overrides" in result.output


# --- Regression tests for reviewer findings ---


def test_clean_build_enriched_sbom(ctx: GlobalContext, tmp_path: Path) -> None:
    """A clean build (no vulns) produces an enriched SBOM in enriched-sboms/.

    The enriched SBOM must have empty pedigree.patches and "validated
    build" notes. No repo_dir is required.
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "clean-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists(), f"Expected enriched SBOM at {sbom_path}"
    sbom = json.loads(sbom_path.read_text())

    assert sbom["bomFormat"] == "CycloneDX"
    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    assert pedigree["patches"] == []
    assert "validated build" in pedigree["notes"].lower()
    assert "remediation" not in pedigree["notes"].lower()

    # PURL must use the validated repository URL
    assert "/validated/" in comp["purl"]
    assert "/remediated/" not in comp["purl"]


def test_clean_build_skips_vex(ctx: GlobalContext, tmp_path: Path) -> None:
    """A clean build (no vulns) must not call _generate_vex_from_index."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "clean-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ) as mock_vex,
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_vex.assert_not_called()


def test_remediation_enriched_sbom(ctx: GlobalContext, tmp_path: Path) -> None:
    """Remediation builds produce an enriched SBOM with correct notes."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "remediation-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "2.0.0",
            "full": "2.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/com.example/core@2.0.0.rhlw-00001",
        "purls": ["pkg:maven/com.example/core@2.0.0.rhlw-00001"],
        "vulns": ["CVE-2024-1234"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ) as mock_vex,
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_vex.assert_called_once()

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "com/example/core/2.0.0.rhlw-00001"
        / "core-2.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists(), f"Expected enriched SBOM at {sbom_path}"
    sbom = json.loads(sbom_path.read_text())

    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    assert "backported security fixes" in pedigree["notes"].lower()
    assert len(pedigree["patches"]) == 1
    assert pedigree["patches"][0]["resolves"][0]["id"] == "CVE-2024-1234"

    assert "/remediated/" in comp["purl"]
    assert "/validated/" not in comp["purl"]


def test_repo_dir_missing_succeeds(ctx: GlobalContext, tmp_path: Path) -> None:
    """Generate succeeds without repository/ — enriched SBOMs still written."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "no-repo-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists(), "Enriched SBOM must be written without repo_dir"


def test_lw_only_vulns_novel_notes(ctx: GlobalContext, tmp_path: Path) -> None:
    """LW-only vulns produce novel-fix notes with empty patches.

    LW- IDs denote embargoed/novel fixes, not backports of publicly
    disclosed CVEs. The pedigree notes must say "novel fix," and
    LW- IDs are excluded from patches (no NVD entry).
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "novel-only-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": ["LW-novel-001"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists()
    sbom = json.loads(sbom_path.read_text())

    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    assert pedigree["patches"] == [], "LW- IDs must not appear in patches"
    assert "novel fix" in pedigree["notes"].lower()
    assert "embargoed" in pedigree["notes"].lower()
    assert "backported" not in pedigree["notes"].lower()

    assert "/predisclosure/" in comp["purl"]
    assert "/remediated/" not in comp["purl"]
    assert "/validated/" not in comp["purl"]


def test_lw_only_vulns_calls_vex(ctx: GlobalContext, tmp_path: Path) -> None:
    """LW-only builds (truthy vulns) must still invoke VEX generation."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "novel-vex-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": ["LW-novel-001"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ) as mock_vex,
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_vex.assert_called_once()


def test_mixed_cve_lw_build_uses_predisclosure(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """Mixed CVE+LW build is contaminated — predisclosure only."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "mixed-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 1,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": ["CVE-2024-1234", "LW-novel-001"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists()
    sbom = json.loads(sbom_path.read_text())
    comp = sbom["components"][0]
    pedigree = comp["pedigree"]

    assert "/predisclosure/" in comp["purl"]
    assert "/remediated/" not in comp["purl"]
    assert "/validated/" not in comp["purl"]

    assert "novel fix" in pedigree["notes"].lower()
    assert "embargoed" in pedigree["notes"].lower()


def _write_multi_module_index(index_dir: Path, vulns: list[str]) -> None:
    index_dir.mkdir()
    data = {
        "buildId": "multi-purl-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib-core@1.0.0.rhlw-00001",
        "purls": [
            "pkg:maven/org.example/lib-core@1.0.0.rhlw-00001",
            "pkg:maven/org.example/lib-util@1.0.0.rhlw-00001",
        ],
        "vulns": vulns,
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))


_MULTI_CORE_SBOM = Path(
    "enriched-sboms/org/example/lib-core/1.0.0.rhlw-00001"
    "/lib-core-1.0.0.rhlw-00001.bom.json"
)
_MULTI_UTIL_SBOM = Path(
    "enriched-sboms/org/example/lib-util/1.0.0.rhlw-00001"
    "/lib-util-1.0.0.rhlw-00001.bom.json"
)


def test_multi_purl_enriches_only_the_primary_module(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """A multi-module build gets one enriched SBOM: the primary module's.

    The other modules are dependents; they keep the PNC SBOM (LWLP-4822).
    """
    index_dir = tmp_path / "index"
    _write_multi_module_index(index_dir, vulns=[])

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    core_sbom_path = output_dir / _MULTI_CORE_SBOM
    assert core_sbom_path.exists(), f"Expected SBOM at {core_sbom_path}"
    assert not (output_dir / _MULTI_UTIL_SBOM).exists()
    sboms = list((output_dir / "enriched-sboms").rglob("*.bom.json"))
    assert sboms == [core_sbom_path]
    core = json.loads(core_sbom_path.read_text())
    assert core["components"][0]["name"] == "lib-core"


def test_multi_purl_dependent_module_never_claims_the_fix(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """With CVEs, only the primary module's SBOM lists the patches."""
    index_dir = tmp_path / "index"
    _write_multi_module_index(index_dir, vulns=["CVE-2026-0001"])

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index"
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert not (output_dir / _MULTI_UTIL_SBOM).exists()
    core = json.loads((output_dir / _MULTI_CORE_SBOM).read_text())
    patches = core["components"][0]["pedigree"]["patches"]
    assert [p["resolves"][0]["id"] for p in patches] == ["CVE-2026-0001"]


def test_pnc_sbom_pedigree_is_merged_not_replaced(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """PNC pedigree.ancestors (exact ?type=jar purl) and fields survive.

    Shape taken from a real PNC SBOM (jsoup-1.22.1.rhlw-00002.bom.json).
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "pnc-merge",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.22.1",
            "full": "1.22.1.rhlw-00002",
            "b": 2,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.jsoup/jsoup@1.22.1.rhlw-00002",
        "purls": ["pkg:maven/org.jsoup/jsoup@1.22.1.rhlw-00002"],
        "vulns": ["CVE-2026-0001", "CVE-2026-0002"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"
    ancestor = {
        "group": "org.jsoup",
        "name": "jsoup",
        "purl": "pkg:maven/org.jsoup/jsoup@1.22.1?type=jar",
        "type": "library",
        "version": "1.22.1",
    }
    supplier = {"name": "Red Hat Lightwell", "url": ["https://www.redhat.com"]}
    pnc_sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "version": 1,
        "metadata": {
            "timestamp": "2026-11-04T00:12:23+00:00",
            "supplier": supplier,
            "properties": [{"name": "lightwell:aiAssisted", "value": "true"}],
            "tools": {"components": [{"name": "lightwell-sbom-generator"}]},
        },
        "components": [
            {
                "bom-ref": "pkg:maven/org.jsoup/jsoup@1.22.1.rhlw-00002?type=jar",
                "group": "org.jsoup",
                "name": "jsoup",
                "version": "1.22.1.rhlw-00002",
                "type": "library",
                "purl": (
                    "pkg:maven/org.jsoup/jsoup@1.22.1.rhlw-00002"
                    "?repository_url=https://packages.redhat.com/lightwell/"
                    "java/remediated/&type=jar"
                ),
                "supplier": supplier,
                "hashes": [{"alg": "SHA-256", "content": "abc"}],
                "licenses": [{"license": {"id": "MIT"}}],
                "pedigree": {"ancestors": [ancestor]},
            }
        ],
    }
    upstream_dir = (
        workdir / "upstream-sboms" / "org/jsoup/jsoup/1.22.1.rhlw-00002"
    )
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "jsoup-1.22.1.rhlw-00002.bom.json").write_text(
        json.dumps(pnc_sbom)
    )

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index"
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    sbom = json.loads(
        (
            output_dir
            / "enriched-sboms/org/jsoup/jsoup/1.22.1.rhlw-00002"
            / "jsoup-1.22.1.rhlw-00002.bom.json"
        ).read_text()
    )
    comp = sbom["components"][0]
    assert comp["pedigree"]["ancestors"] == [ancestor]
    assert [p["resolves"][0]["id"] for p in comp["pedigree"]["patches"]] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert "remediation" in comp["pedigree"]["notes"].lower()
    # PNC identity and metadata are kept; only the serial is re-derived.
    assert comp["bom-ref"] == pnc_sbom["components"][0]["bom-ref"]
    assert comp["purl"] == pnc_sbom["components"][0]["purl"]
    assert comp["supplier"] == supplier
    assert sbom["metadata"] == pnc_sbom["metadata"]
    assert sbom["$schema"] == pnc_sbom["$schema"]
    assert sbom["serialNumber"] != pnc_sbom["serialNumber"]


def test_upstream_sbom_enriched(ctx: GlobalContext, tmp_path: Path) -> None:
    """When an upstream SBOM exists, its fields are preserved after enrichment."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "enrich-test",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    # Create an upstream SBOM in upstream-sboms/
    upstream_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "supplier": {"name": "PNC"},
        },
        "components": [
            {
                "type": "library",
                "group": "org.example",
                "name": "lib",
                "version": "1.0.0.rhlw-00001",
                "purl": ("pkg:maven/org.example/lib@1.0.0.rhlw-00001?type=jar"),
                "hashes": [{"alg": "SHA-256", "content": "abc123upstream"}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        ],
    }
    upstream_dir = workdir / "upstream-sboms" / "org/example/lib/1.0.0.rhlw-00001"
    upstream_dir.mkdir(parents=True)
    (upstream_dir / "lib-1.0.0.rhlw-00001.bom.json").write_text(
        json.dumps(upstream_sbom)
    )

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "org/example/lib/1.0.0.rhlw-00001"
        / "lib-1.0.0.rhlw-00001.bom.json"
    )
    assert sbom_path.exists()
    sbom = json.loads(sbom_path.read_text())

    # Upstream fields preserved
    assert sbom["specVersion"] == "1.6"
    comp = sbom["components"][0]
    assert comp["hashes"] == [{"alg": "SHA-256", "content": "abc123upstream"}]
    assert comp["licenses"] == [{"license": {"id": "Apache-2.0"}}]

    # Enrichment applied
    assert "pedigree" in comp
    assert "validated build" in comp["pedigree"]["notes"].lower()
    assert "/validated/" in comp["purl"]
    assert "serialNumber" in sbom


def test_version_traversal_rejected(ctx: GlobalContext, tmp_path: Path) -> None:
    """A PURL with '..' in version is rejected by the enrichment guard."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    traversal_version = "..%2F..%2F..%2F..%2Fetc"
    data = {
        "buildId": "traversal-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "../../../../etc",
            "b": 0,
            "n": 0,
        },
        "primaryPurl": f"pkg:maven/org.example/artifact@{traversal_version}",
        "purls": [f"pkg:maven/org.example/artifact@{traversal_version}"],
        "vulns": [],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_osv",
        return_value=[],
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code != 0, "Should reject unsafe version"
    assert "unsafe characters" in result.output.lower()


def test_osgi_qualified_version_sidecar(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """OSGi-qualified versions (hyphen rhlw suffix) produce correct sidecars.

    ADR-0026 §1.1: versions like 4.1.132.Final use a hyphen separator
    (4.1.132.Final-rhlw-00002) because the qualifier already occupies
    the fourth dot segment.
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "osgi-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "4.1.132.Final",
            "full": "4.1.132.Final-rhlw-00002",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": (
            "pkg:maven/io.netty/netty-codec-dns@4.1.132.Final-rhlw-00002"
        ),
        "purls": ["pkg:maven/io.netty/netty-codec-dns@4.1.132.Final-rhlw-00002"],
        "vulns": ["CVE-2025-99999"],
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ),
    ):
        runner = CliRunner()
        result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    sbom_path = (
        output_dir
        / "enriched-sboms"
        / "io/netty/netty-codec-dns/4.1.132.Final-rhlw-00002"
        / "netty-codec-dns-4.1.132.Final-rhlw-00002.bom.json"
    )
    assert sbom_path.exists(), f"Expected enriched SBOM at {sbom_path}"
    sbom = json.loads(sbom_path.read_text())

    comp = sbom["components"][0]
    pedigree = comp["pedigree"]
    ancestor = pedigree["ancestors"][0]
    assert ancestor["version"] == "4.1.132.Final"
    assert "rhlw" not in ancestor["version"]

    assert "backported security fixes" in pedigree["notes"].lower()
    assert len(pedigree["patches"]) == 1

    assert "/remediated/" in comp["purl"]


# ---------------------------------------------------------------------------
# LWLP-4254: multi-CVE VEX only for >=2 CVEs; one normalized timestamp
# ---------------------------------------------------------------------------


def _vex_doc(*cve_ids: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [{"id": c} for c in cve_ids],
    }


def _run_vex(tmp_path: Path, per_cve: list, multi_cve: dict | None) -> Path:
    from fath_cuan.converters.vex import ModuleVEX, VEXResult

    from slan_cuan.tasks.generate_security_metadata import (
        _generate_vex_from_index,
    )

    module = ModuleVEX(
        purl="pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        per_cve=per_cve,
        multi_cve=multi_cve,
        timestamp="2026-10-30T20:34:00Z",
    )
    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_vex",
        return_value=VEXResult(
            per_cve=per_cve, multi_cve=multi_cve, modules=[module]
        ),
    ):
        _generate_vex_from_index({}, tmp_path, None, {}, "2026-10-30T20:34:00Z")
    return tmp_path


def test_single_cve_build_writes_no_multi_cve_vex(tmp_path: Path) -> None:
    """A single-CVE build must not also emit a duplicate multi-CVE file."""
    out = _run_vex(
        tmp_path,
        [("CVE-2024-1", _vex_doc("CVE-2024-1"))],
        _vex_doc("CVE-2024-1"),
    )

    assert sorted(p.name for p in out.iterdir()) == [
        "CVE-2024-1-2026-10-30T20:34:00Z.bom.json"
    ]


def test_multi_cve_build_writes_one_combined_vex(tmp_path: Path) -> None:
    """Two or more CVEs produce ONE combined VEX file, no per-CVE files.

    Agreed Sonatype format: one VEX per module; <datetime>.bom.json holds
    all statements (per-CVE files beside it would publish them twice).
    """
    out = _run_vex(
        tmp_path,
        [
            ("CVE-2024-1", _vex_doc("CVE-2024-1")),
            ("CVE-2024-2", _vex_doc("CVE-2024-2")),
        ],
        _vex_doc("CVE-2024-1", "CVE-2024-2"),
    )

    assert sorted(p.name for p in out.iterdir()) == [
        "2026-10-30T20:34:00Z.bom.json"
    ]
    doc = json.loads((out / "2026-10-30T20:34:00Z.bom.json").read_text())
    assert [v["id"] for v in doc["vulnerabilities"]] == [
        "CVE-2024-1",
        "CVE-2024-2",
    ]


def test_malformed_multi_cve_falls_back_to_single_per_cve(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A multi_cve without usable statements and one per-CVE doc -> that doc."""
    out = _run_vex(
        tmp_path,
        [("CVE-2024-1", _vex_doc("CVE-2024-1"))],
        {"bomFormat": "CycloneDX"},
    )

    assert sorted(p.name for p in out.iterdir()) == [
        "CVE-2024-1-2026-10-30T20:34:00Z.bom.json"
    ]
    assert "1 statement(s)" in capsys.readouterr().out


def test_several_per_cve_without_combined_vex_is_refused(tmp_path: Path) -> None:
    """Never publish several per-CVE files for one module."""
    import click

    with pytest.raises(click.ClickException, match="refusing to publish"):
        _run_vex(
            tmp_path,
            [
                ("CVE-2024-1", _vex_doc("CVE-2024-1")),
                ("CVE-2024-2", _vex_doc("CVE-2024-2")),
            ],
            None,
        )


@pytest.mark.parametrize(
    ("created", "expected"),
    [
        ("2026-10-30T20:34:12Z", "2026-10-30T20:34:12Z"),
        ("2026-10-30T20:34:12+00:00", "2026-10-30T20:34:12Z"),
        ("2026-10-30T22:34:12+02:00", "2026-10-30T20:34:12Z"),
        ("2026-10-30T20:34:12.123456Z", "2026-10-30T20:34:12Z"),
        ("2026-10-30T20:34:12", "2026-10-30T20:34:12Z"),
        ("2026-10-30", "2026-10-30T00:00:00Z"),
    ],
)
def test_normalize_build_timestamp(created: str, expected: str) -> None:
    """``created`` is normalized to second-precision UTC with a Z suffix."""
    from slan_cuan.tasks.generate_security_metadata import (
        _normalize_build_timestamp,
    )

    assert _normalize_build_timestamp(created) == expected


def test_normalize_build_timestamp_rejects_garbage() -> None:
    """A non-ISO ``created`` fails instead of silently producing bad dates."""
    import click

    from slan_cuan.tasks.generate_security_metadata import (
        _normalize_build_timestamp,
    )

    with pytest.raises(click.ClickException, match="not ISO-8601"):
        _normalize_build_timestamp("last tuesday")


def test_vex_receives_same_timestamp_as_filename(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """fath-cuan sees the normalized ``created`` used for VEX filenames.

    Keeps VEX published/updated identical to the filename datetime even
    when the build index carries an offset timestamp.
    """
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    data = {
        "buildId": "ts-build",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/lib@1.0.0.rhlw-00001",
        "purls": ["pkg:maven/org.example/lib@1.0.0.rhlw-00001"],
        "vulns": ["CVE-2024-1234"],
        "created": "2026-10-30T22:34:12+02:00",
    }
    (index_dir / "gav-index.json").write_text(json.dumps(data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    output_dir = workdir / "security_metadata"

    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "slan_cuan.tasks.generate_security_metadata._generate_vex_from_index",
        ) as mock_vex,
    ):
        result = _invoke(CliRunner(), index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    index_arg, _, _, _, ts_arg = mock_vex.call_args.args
    assert ts_arg == "2026-10-30T20:34:12Z"
    assert index_arg["created"] == ts_arg


# ---------------------------------------------------------------------------
# Legacy gav-index -> VEX (primary module only, metadata.component from SBOM)
# ---------------------------------------------------------------------------

# A real production PNC gav-index (legacy format: primaryGav/gavs, no
# purls/ecosystem). Only the primary module carries the fix; the published
# OSV advisory has a single affected entry for it.
_ZOOKEEPER_GAV_INDEX = {
    "buildConfig": {
        "buildType": "MVN",
        "id": "37361",
        "name": (
            "org.apache.zookeeper-parent-3.8.3-rhlw-secure-patch-81706a4dedd6"
        ),
    },
    "buildId": "BSL5OB2UQPQAA",
    "created": "2026-11-09T00:50:22+00:00",
    "gavCount": 5,
    "gavIndexTag": "idx-BSL5OB2UQPQAA",
    "gavs": [
        "org.apache.zookeeper:zookeeper:3.8.3.rhlw-00015",
        "org.apache.zookeeper:parent:3.8.3.rhlw-00015",
        "org.apache.zookeeper:zookeeper-jute:3.8.3.rhlw-00015",
        "org.apache.zookeeper:zookeeper-metrics-providers:3.8.3.rhlw-00015",
        "org.apache.zookeeper:zookeeper-prometheus-metrics:3.8.3.rhlw-00015",
    ],
    "primaryArtifact": {
        "artifactId": "zookeeper",
        "groupId": "org.apache.zookeeper",
        "version": "3.8.3.rhlw-00015",
    },
    "primaryGav": "org.apache.zookeeper:zookeeper:3.8.3.rhlw-00015",
    "vulns": [
        "CVE-2024-23944",
        "CVE-2026-24308",
        "CVE-2026-59739",
        "CVE-2026-59969",
        "CVE-2026-79993",
        "CVE-2026-84439",
        "CVE-2026-84501",
    ],
}
_NO_ENRICHMENT = {
    "osidb_meta": None,
    "upstream": None,
    "upstream_aliases": [],
    "nvd": None,
}
_ZK_PRIMARY = "org/apache/zookeeper/zookeeper/3.8.3.rhlw-00015"


def _run_generate_real_vex(
    ctx: GlobalContext, tmp_path: Path, index: dict, upstream: dict | None = None
):
    """Run generate with fath-cuan's real VEX converter (enrichment stubbed)."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    (index_dir / "gav-index.json").write_text(json.dumps(index))
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir, create_repo=False)
    for rel, sbom in (upstream or {}).items():
        path = workdir / "upstream-sboms" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sbom))
    output_dir = workdir / "security_metadata"
    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_osv",
            return_value=[],
        ),
        patch(
            "fath_cuan.converters.vex._prefetch_enrichment",
            return_value=_NO_ENRICHMENT,
        ),
    ):
        result = _invoke(
            CliRunner(),
            index_dir,
            output_dir,
            ctx,
            index_filename="gav-index.json",
            workdir=workdir,
        )
    vex = {
        p.name: json.loads(p.read_text())
        for p in sorted(output_dir.glob("*.bom.json"))
    }
    return result, output_dir, vex


def _bom_link(serial: str, bom_ref: str) -> str:
    from urllib.parse import quote

    return (
        f"urn:cdx:{serial.removeprefix('urn:uuid:')}/1#{quote(bom_ref, safe='')}"
    )


def test_legacy_gav_index_produces_vex_for_primary_module_only(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """A legacy gav-index is converted; VEX covers only the primary module.

    Mirrors the OSV advisory (one affected entry): one document set, each
    statement affecting only the primary SBOM, and metadata.component equal
    to that SBOM's components[0] identity (purl with repository_url+type).
    """
    result, output_dir, vex = _run_generate_real_vex(
        ctx, tmp_path, _ZOOKEEPER_GAV_INDEX
    )

    assert result.exit_code == 0, result.output
    assert "Legacy gav-index converted to a build-index" in result.output
    # ONE VEX for the module, holding all 7 CVEs (agreed Sonatype format).
    ts = "2026-11-09T00:50:22Z"
    assert set(vex) == {f"{ts}.bom.json"}
    assert [v["id"] for v in vex[f"{ts}.bom.json"]["vulnerabilities"]] == (
        _ZOOKEEPER_GAV_INDEX["vulns"]
    )

    sbom = json.loads(
        (
            output_dir
            / "enriched-sboms"
            / _ZK_PRIMARY
            / "zookeeper-3.8.3.rhlw-00015.bom.json"
        ).read_text()
    )
    subject = sbom["components"][0]
    assert subject["purl"] == (
        "pkg:maven/org.apache.zookeeper/zookeeper@3.8.3.rhlw-00015"
        "?repository_url=https://packages.redhat.com/lightwell/java/remediated/"
        "&type=jar"
    )
    link = _bom_link(sbom["serialNumber"], subject["bom-ref"])
    for name, doc in vex.items():
        component = doc["metadata"]["component"]
        for key in ("type", "bom-ref", "group", "name", "version", "purl"):
            assert component[key] == subject[key], (name, key)
        for statement in doc["vulnerabilities"]:
            assert [a["ref"] for a in statement["affects"]] == [link], name
        assert "parent" not in json.dumps(doc), name
        assert "zookeeper-jute" not in json.dumps(doc), name


def test_vex_bom_link_uses_upstream_sbom_bom_ref(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """With a PNC SBOM (bom-ref ?type=jar), VEX references that exact bom-ref."""
    pnc_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "serialNumber": "urn:uuid:c1573583-6884-55df-b85f-b2691dcd2ec4",
        "components": [
            {
                "type": "library",
                "bom-ref": (
                    "pkg:maven/org.apache.zookeeper/zookeeper@3.8.3.rhlw-00015"
                    "?type=jar"
                ),
                "group": "org.apache.zookeeper",
                "name": "zookeeper",
                "version": "3.8.3.rhlw-00015",
                "purl": (
                    "pkg:maven/org.apache.zookeeper/zookeeper@3.8.3.rhlw-00015"
                    "?type=jar"
                ),
                "hashes": [{"alg": "SHA-256", "content": "abc"}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        ],
    }
    result, output_dir, vex = _run_generate_real_vex(
        ctx,
        tmp_path,
        _ZOOKEEPER_GAV_INDEX,
        upstream={f"{_ZK_PRIMARY}/zookeeper-3.8.3.rhlw-00015.bom.json": pnc_sbom},
    )

    assert result.exit_code == 0, result.output
    sbom = json.loads(
        (
            output_dir
            / "enriched-sboms"
            / _ZK_PRIMARY
            / "zookeeper-3.8.3.rhlw-00015.bom.json"
        ).read_text()
    )
    subject = sbom["components"][0]
    assert subject["bom-ref"].endswith("?type=jar")
    assert "repository_url=" in subject["purl"]
    link = _bom_link(sbom["serialNumber"], subject["bom-ref"])
    for name, doc in vex.items():
        assert doc["metadata"]["component"]["bom-ref"] == subject["bom-ref"]
        assert doc["metadata"]["component"]["purl"] == subject["purl"]
        for statement in doc["vulnerabilities"]:
            assert [a["ref"] for a in statement["affects"]] == [link], name


def test_build_index_with_several_modules_vex_primary_only(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """A build-index with several purls also yields VEX for the primary only."""
    index = {
        "buildId": "multi",
        "ecosystem": "maven",
        "version": {
            "upstream": "1.0.0",
            "full": "1.0.0.rhlw-00001",
            "b": 1,
            "n": 0,
        },
        "primaryPurl": "pkg:maven/org.example/core@1.0.0.rhlw-00001",
        "purls": [
            "pkg:maven/org.example/core@1.0.0.rhlw-00001",
            "pkg:maven/org.example/parent@1.0.0.rhlw-00001",
        ],
        "vulns": ["CVE-2024-1234"],
        "created": "2026-11-09T00:00:00Z",
    }
    result, _, vex = _run_generate_real_vex(ctx, tmp_path, index)

    assert result.exit_code == 0, result.output
    assert set(vex) == {"CVE-2024-1234-2026-11-09T00:00:00Z.bom.json"}
    doc = vex["CVE-2024-1234-2026-11-09T00:00:00Z.bom.json"]
    assert doc["metadata"]["component"]["name"] == "core"
    affects = doc["vulnerabilities"][0]["affects"]
    assert len(affects) == 1
    assert "parent" not in affects[0]["ref"]


def test_index_without_known_format_warns_and_skips_vex(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """An index that is neither format warns instead of silently skipping.

    (With vulnerabilities such an index already fails earlier, when the
    advisory ID cannot be derived.)
    """
    result, _, vex = _run_generate_real_vex(
        ctx, tmp_path, {"buildId": "x", "vulns": []}
    )

    assert result.exit_code == 0, result.output
    assert "neither a build-index" in result.output
    assert vex == {}


def test_unconvertible_legacy_index_warns_and_skips_vex(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """A legacy index that cannot be converted warns; OSV still runs."""
    index = {
        "buildId": "x",
        "created": "2026-11-09T00:00:00Z",
        "primaryGav": "org.example:core:1.0.0",
        "gavs": ["org.example:core:1.0.0"],
        "vulns": ["CVE-2024-1234"],
    }
    result, _, vex = _run_generate_real_vex(ctx, tmp_path, index)

    assert result.exit_code == 0, result.output
    assert "could not be converted to a build-index" in result.output
    assert vex == {}


def test_legacy_index_conversion_keyerror_warns_and_skips_vex(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """A KeyError from migrate_document falls through to the warning path.

    fath-cuan 0.9.0 validates the whole index with pydantic first (missing
    fields raise ValidationError, a ValueError), so KeyError is forced here
    to guard against a future migrate_document change crashing the CLI.
    """
    with patch(
        "slan_cuan.tasks.generate_security_metadata.migrate_document",
        side_effect=KeyError("gavs"),
    ):
        result, _, vex = _run_generate_real_vex(
            ctx, tmp_path, json.loads(json.dumps(_ZOOKEEPER_GAV_INDEX))
        )

    assert result.exit_code == 0, result.output
    assert "could not be converted to a build-index ('gavs')" in result.output
    assert vex == {}


# ---------------------------------------------------------------------------
# LWLP-5917: one OSV advisory, one SBOM and one VEX per module with a fix
# ---------------------------------------------------------------------------

_LOGBACK_INDEX = {
    "buildId": "BSO7LXV6QPQAA",
    "created": "2026-11-13T18:59:33+00:00",
    "primaryGav": "ch.qos.logback:logback-classic:1.5.9.rhlw-00034",
    "gavs": [
        "ch.qos.logback:logback-classic:1.5.9.rhlw-00034",
        "ch.qos.logback:logback-access:1.5.9.rhlw-00034",
        "ch.qos.logback:logback-core:1.5.9.rhlw-00034",
        "ch.qos.logback:logback-parent:1.5.9.rhlw-00034",
    ],
    "vulns": [
        "CVE-2024-12798",
        "CVE-2024-12801",
        "CVE-2026-10532",
        "CVE-2026-19880",
    ],
}

_LOGBACK_PLACEMENT = {
    "ch.qos.logback:logback-classic": ["CVE-2026-19880"],
    "ch.qos.logback:logback-core": [
        "CVE-2024-12798",
        "CVE-2024-12801",
        "CVE-2026-10532",
    ],
}


def _logback_upstream(vuln_id: str) -> dict | None:
    # CVE-2026-19880 and LW- IDs have no osv.dev package data.
    if vuln_id == "CVE-2026-19880" or not vuln_id.startswith("CVE-"):
        return None
    return {
        "affected": [
            {
                "package": {
                    "ecosystem": "Maven",
                    "name": "ch.qos.logback:logback-core",
                }
            }
        ]
    }


def _run_logback(
    ctx: GlobalContext,
    tmp_path: Path,
    placement: dict | None,
    index: dict = _LOGBACK_INDEX,
    expect_ok: bool = True,
) -> tuple[Path, str]:
    """Generate for the logback build; *placement* None runs fath-cuan's own."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    (index_dir / "gav-index.json").write_text(json.dumps(index))
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)
    output_dir = workdir / "security_metadata"
    placing = (
        {"side_effect": real_resolve_module_vulns}
        if placement is None
        else {"return_value": placement}
    )
    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.resolve_module_vulns",
            **placing,
        ),
        patch(
            "fath_cuan.converters.osv._fetch_upstream_osv",
            side_effect=_logback_upstream,
        ),
        patch("fath_cuan.converters.osv._fetch_nvd", return_value=None),
        patch(
            "fath_cuan.converters.vex._fetch_upstream_osv",
            side_effect=_logback_upstream,
        ),
        patch("fath_cuan.converters.vex._fetch_nvd", return_value=None),
        patch(
            "fath_cuan.converters.osv._fetch_lightwell_advisories",
            return_value=[],
        ),
    ):
        result = _invoke(CliRunner(), index_dir, output_dir, ctx, workdir=workdir)
    if expect_ok:
        assert result.exit_code == 0, result.output
    else:
        assert result.exit_code != 0, result.output
    return output_dir, result.output


def test_multi_module_build_one_record_set_per_module(
    ctx: GlobalContext, tmp_path: Path
) -> None:
    """Logback 1.5.9.rhlw-00034: advisory, SBOM and VEX for each fixed module."""
    out, _ = _run_logback(ctx, tmp_path, _LOGBACK_PLACEMENT)

    osv = {p.name: json.loads(p.read_text()) for p in out.glob("RHLW-*.json")}
    by_package = {r["affected"][0]["package"]["name"]: r for r in osv.values()}
    assert set(by_package) == set(_LOGBACK_PLACEMENT)
    assert (
        by_package["ch.qos.logback:logback-classic"]["id"]
        == "RHLW-2026-33400e52ea4f277c"
    )
    for name, record in by_package.items():
        assert len(record["affected"]) == 1
        assert [
            u for u in record["upstream"] if u.startswith("CVE-")
        ] == _LOGBACK_PLACEMENT[name]

    sboms = sorted(
        p.relative_to(out / "enriched-sboms").as_posix()
        for p in (out / "enriched-sboms").rglob("*.bom.json")
    )
    assert sboms == [
        "ch/qos/logback/logback-classic/1.5.9.rhlw-00034/logback-classic-1.5.9.rhlw-00034.bom.json",
        "ch/qos/logback/logback-core/1.5.9.rhlw-00034/logback-core-1.5.9.rhlw-00034.bom.json",
    ]
    core_sbom = json.loads((out / "enriched-sboms" / sboms[1]).read_text())
    patched = [
        r["id"]
        for p in core_sbom["components"][0]["pedigree"]["patches"]
        for r in p["resolves"]
    ]
    assert patched == _LOGBACK_PLACEMENT["ch.qos.logback:logback-core"]

    vex = {p.name: json.loads(p.read_text()) for p in out.glob("*.bom.json")}
    assert sorted(vex) == [
        "2026-11-13T18:59:34Z.bom.json",
        "CVE-2026-19880-2026-11-13T18:59:33Z.bom.json",
    ]
    classic = vex["CVE-2026-19880-2026-11-13T18:59:33Z.bom.json"]
    core = vex["2026-11-13T18:59:34Z.bom.json"]
    assert classic["metadata"]["component"]["name"] == "logback-classic"
    assert core["metadata"]["component"]["name"] == "logback-core"
    assert core["metadata"]["timestamp"] == "2026-11-13T18:59:34Z"
    assert [v["id"] for v in core["vulnerabilities"]] == _LOGBACK_PLACEMENT[
        "ch.qos.logback:logback-core"
    ]
    # A module never names another module's upstream fix (no sibling fallback).
    assert "logback-core" not in classic["vulnerabilities"][0]["recommendation"]
    assert all(
        v["recommendation"].startswith("Update to logback-core 1.5.9.rhlw-00034 ")
        for v in core["vulnerabilities"]
    )
    assert classic["vulnerabilities"][0]["recommendation"].startswith(
        "Update to logback-classic 1.5.9.rhlw-00034 "
    )


@pytest.mark.parametrize(
    ("placement", "unplaced"),
    [
        (
            {"ch.qos.logback:logback-core": ["CVE-2024-12798"]},
            "CVE-2024-12801, CVE-2026-10532, CVE-2026-19880",
        ),
        ({}, "CVE-2024-12798, CVE-2024-12801, CVE-2026-10532, CVE-2026-19880"),
    ],
    ids=["some-unplaced", "nothing-placed"],
)
def test_unplaced_vulnerabilities_fail_the_run(
    ctx: GlobalContext, tmp_path: Path, placement: dict, unplaced: str
) -> None:
    """A vulnerability no module of this build fixes stops the run.

    No OSV or VEX would name it, and publish refuses a release whose OSV
    doesn't cover every GAV index vulnerability: fail early, with the IDs.
    """
    out, output = _run_logback(ctx, tmp_path, placement, expect_ok=False)

    assert "Not placed on any module of this build" in output
    assert unplaced in output
    assert list(out.glob("RHLW-*.json")) == []


def test_real_placement_without_osidb(ctx: GlobalContext, tmp_path: Path) -> None:
    """fath-cuan's own placement, no OSIDB keytab (osv.dev mocked).

    CVEs with osv.dev package data go to the module it names; a CVE without
    it and an LW- ID (osv.dev has no LW- records) fall back to the primary
    module, because OSIDB is the only other source.
    """
    vulns = [*_LOGBACK_INDEX["vulns"], "LW-2026-0023"]
    index = {**_LOGBACK_INDEX, "vulns": vulns}
    out, output = _run_logback(ctx, tmp_path, None, index=index)

    assert "No OSIDB keytab file found, skipping OSIDB fetching." in output
    assert (
        "Fixes in ch.qos.logback:logback-classic: CVE-2026-19880, LW-2026-0023"
    ) in output
    assert (
        "Fixes in ch.qos.logback:logback-core: "
        "CVE-2024-12798, CVE-2024-12801, CVE-2026-10532"
    ) in output
    upstream_by_module = {
        r["affected"][0]["package"]["name"]: r["upstream"]
        for r in (json.loads(p.read_text()) for p in out.glob("RHLW-*.json"))
    }
    assert upstream_by_module == {
        "ch.qos.logback:logback-classic": ["CVE-2026-19880", "LW-2026-0023"],
        "ch.qos.logback:logback-core": [
            "CVE-2024-12798",
            "CVE-2024-12801",
            "CVE-2026-10532",
        ],
    }
    vex_ids_by_module = {
        d["metadata"]["component"]["name"]: [
            v["id"] for v in d["vulnerabilities"]
        ]
        for d in (json.loads(p.read_text()) for p in out.glob("*.bom.json"))
    }
    assert vex_ids_by_module == {
        "logback-classic": ["CVE-2026-19880", "LW-2026-0023"],
        "logback-core": ["CVE-2024-12798", "CVE-2024-12801", "CVE-2026-10532"],
    }


def test_vex_file_from_an_earlier_run_is_overwritten(tmp_path: Path) -> None:
    """A leftover file in the output directory doesn't block a local re-run."""
    from fath_cuan.converters.vex import ModuleVEX, VEXResult

    from slan_cuan.tasks.generate_security_metadata import (
        _generate_vex_from_index,
    )

    ts = "2026-11-13T18:59:33Z"
    leftover = tmp_path / f"{ts}.bom.json"
    leftover.write_text('{"old": true}')
    module = ModuleVEX(
        purl="pkg:maven/g/a@1",
        per_cve=[],
        timestamp=ts,
        multi_cve=_vex_doc("CVE-2024-1", "CVE-2024-2"),
    )
    with patch(
        "slan_cuan.tasks.generate_security_metadata.process_vex",
        return_value=VEXResult(per_cve=[], multi_cve=None, modules=[module]),
    ):
        _generate_vex_from_index({}, tmp_path, None, {}, ts)

    assert json.loads(leftover.read_text()) == _vex_doc(
        "CVE-2024-1", "CVE-2024-2"
    )


def test_vex_file_is_never_overwritten(tmp_path: Path) -> None:
    """Two modules must never write the same VEX filename."""
    import click
    from fath_cuan.converters.vex import ModuleVEX, VEXResult

    from slan_cuan.tasks.generate_security_metadata import (
        _generate_vex_from_index,
    )

    same_ts = "2026-11-13T18:59:33Z"
    modules = [
        ModuleVEX(
            purl=f"pkg:maven/g/{a}@1",
            per_cve=[],
            timestamp=same_ts,
            multi_cve=_vex_doc("CVE-2024-1", "CVE-2024-2"),
        )
        for a in ("a", "b")
    ]
    with (
        patch(
            "slan_cuan.tasks.generate_security_metadata.process_vex",
            return_value=VEXResult(per_cve=[], multi_cve=None, modules=modules),
        ),
        pytest.raises(click.ClickException, match="refusing to overwrite"),
    ):
        _generate_vex_from_index({}, tmp_path, None, {}, same_ts)
