"""Unit tests for the generate-security-metadata-from-snapshot subcommand."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.models import GlobalContext
from slan_cuan.tasks.generate_security_metadata import (
    generate_security_metadata_from_snapshot,
)


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
        }
    ]


@pytest.fixture
def osidb_keytab(tmp_path: Path) -> Path:
    """Provide a present, readable fake keytab file so OSIDB auth succeeds."""
    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")
    return keytab


def _osidb_kwargs(keytab: Path) -> dict:
    """Build standard OSIDB CLI kwargs pointing at a valid keytab."""
    return {
        "osidb_api_url": "https://osidb.example.com/api/v1",
        "osidb_kerberos_principal": "user@REALM",
        "osidb_keytab": keytab,
    }


def _write_snapshot(path: Path, images: list[str]) -> None:
    """Write a minimal reduced-snapshot spec with the given component images."""
    data = {
        "components": [
            {"name": f"comp{i}", "containerImage": img}
            for i, img in enumerate(images)
        ]
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _invoke(runner, snapshot_path, workdir, output_dir, ctx, **extra):
    args = [
        "--snapshot-path",
        str(snapshot_path),
        "--workdir",
        str(workdir),
        "--output-dir",
        str(output_dir),
    ]
    for key, value in extra.items():
        args += [f"--{key.replace('_', '-')}", str(value)]
    return runner.invoke(generate_security_metadata_from_snapshot, args, obj=ctx)


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_generates_osv_for_each_component_with_referrer(
    mock_process_osv: Mock,
    mock_oci: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    osidb_keytab: Path,
    tmp_path: Path,
) -> None:
    """Each component with a referrer is discovered, pulled and processed."""
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(
        snapshot,
        [
            "registry.local/ntplib@sha256:aaa",
            "registry.local/requests@sha256:bbb",
        ],
    )
    workdir = tmp_path / "workdir"
    output_dir = workdir / "security_metadata"

    mock_get_token.return_value = "jwt-token-123"
    mock_osidb_client_cls.return_value.available = True
    mock_oci.discover.return_value = [{"digest": "sha256:ref111"}]
    mock_process_osv.return_value = fake_osv_records

    # Simulate the pulled build-index landing in the index dir.
    def _pull(image, output, **kwargs):
        Path(output).mkdir(parents=True, exist_ok=True)
        (Path(output) / "build-index.json").write_text(
            json.dumps({"buildId": "1", "artifacts": []})
        )

    mock_oci.pull.side_effect = _pull

    runner = CliRunner()
    result = _invoke(
        runner, snapshot, workdir, output_dir, ctx, **_osidb_kwargs(osidb_keytab)
    )

    assert result.exit_code == 0, result.output
    assert mock_oci.discover.call_count == 2
    assert mock_oci.pull.call_count == 2
    assert mock_process_osv.call_count == 2
    assert (output_dir / "x_RHLW-CVE-2024-001-1.0.0.json").exists()


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_pulls_referrer_by_digest_in_component_repository(
    mock_process_osv: Mock,
    mock_oci: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    osidb_keytab: Path,
    tmp_path: Path,
) -> None:
    """The referrer is pulled as <registry>/<repo>@<referrer-digest>."""
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, ["registry.local/ntplib@sha256:aaa"])
    workdir = tmp_path / "workdir"
    output_dir = workdir / "security_metadata"

    mock_get_token.return_value = "jwt-token-123"
    mock_osidb_client_cls.return_value.available = True
    mock_oci.discover.return_value = [{"digest": "sha256:ref999"}]
    mock_process_osv.return_value = fake_osv_records

    def _pull(image, output, **kwargs):
        Path(output).mkdir(parents=True, exist_ok=True)
        (Path(output) / "build-index.json").write_text(json.dumps({}))

    mock_oci.pull.side_effect = _pull

    runner = CliRunner()
    result = _invoke(
        runner, snapshot, workdir, output_dir, ctx, **_osidb_kwargs(osidb_keytab)
    )

    assert result.exit_code == 0, result.output
    pulled_image = mock_oci.pull.call_args.args[0]
    assert str(pulled_image) == "registry.local/ntplib@sha256:ref999"


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_skips_components_without_referrer(
    mock_process_osv: Mock,
    mock_oci: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    osidb_keytab: Path,
    tmp_path: Path,
) -> None:
    """A component with no build-index referrer is skipped, others proceed."""
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(
        snapshot,
        [
            "registry.local/noref@sha256:aaa",
            "registry.local/hasref@sha256:bbb",
        ],
    )
    workdir = tmp_path / "workdir"
    output_dir = workdir / "security_metadata"

    mock_get_token.return_value = "jwt-token-123"
    mock_osidb_client_cls.return_value.available = True
    mock_oci.discover.side_effect = [[], [{"digest": "sha256:ref222"}]]
    mock_process_osv.return_value = fake_osv_records

    def _pull(image, output, **kwargs):
        Path(output).mkdir(parents=True, exist_ok=True)
        (Path(output) / "build-index.json").write_text(json.dumps({}))

    mock_oci.pull.side_effect = _pull

    runner = CliRunner()
    result = _invoke(
        runner, snapshot, workdir, output_dir, ctx, **_osidb_kwargs(osidb_keytab)
    )

    assert result.exit_code == 0, result.output
    assert "No build-index referrer" in result.output
    assert mock_oci.pull.call_count == 1
    assert mock_process_osv.call_count == 1


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_warns_when_no_component_has_a_referrer(
    mock_process_osv: Mock,
    mock_oci: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    ctx: GlobalContext,
    osidb_keytab: Path,
    tmp_path: Path,
) -> None:
    """A zero-referrer run warns loudly but still exits successfully."""
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, ["registry.local/noref@sha256:aaa"])
    workdir = tmp_path / "workdir"
    output_dir = workdir / "security_metadata"

    mock_get_token.return_value = "jwt-token-123"
    mock_osidb_client_cls.return_value.available = True
    mock_oci.discover.return_value = []

    runner = CliRunner()
    result = _invoke(
        runner, snapshot, workdir, output_dir, ctx, **_osidb_kwargs(osidb_keytab)
    )

    assert result.exit_code == 0, result.output
    assert "no build-index referrer found on ANY component" in result.output
    mock_process_osv.assert_not_called()


@patch("fath_cuan.osidb.OsidbClient")
@patch("slan_cuan.tasks.generate_security_metadata._get_osidb_auth_token")
@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_builds_osidb_client_once_across_all_components(
    mock_process_osv: Mock,
    mock_oci: Mock,
    mock_get_token: Mock,
    mock_osidb_client_cls: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """OSIDB auth happens once and the client is reused for every image."""
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(
        snapshot,
        [
            "registry.local/a@sha256:aaa",
            "registry.local/b@sha256:bbb",
        ],
    )
    workdir = tmp_path / "workdir"
    output_dir = workdir / "security_metadata"

    keytab = tmp_path / "test.keytab"
    keytab.write_text("fake-keytab")

    mock_get_token.return_value = "jwt-token-123"
    mock_client = mock_osidb_client_cls.return_value
    mock_client.available = True
    mock_oci.discover.return_value = [{"digest": "sha256:ref"}]
    mock_process_osv.return_value = fake_osv_records

    def _pull(image, output, **kwargs):
        Path(output).mkdir(parents=True, exist_ok=True)
        (Path(output) / "build-index.json").write_text(json.dumps({}))

    mock_oci.pull.side_effect = _pull

    runner = CliRunner()
    result = _invoke(
        runner,
        snapshot,
        workdir,
        output_dir,
        ctx,
        osidb_api_url="https://osidb.example.com/api/v1",
        osidb_kerberos_principal="user@REALM",
        osidb_keytab=keytab,
    )

    assert result.exit_code == 0, result.output
    mock_get_token.assert_called_once()
    assert mock_process_osv.call_count == 2
    for call in mock_process_osv.call_args_list:
        assert call.kwargs["osidb_client"] is mock_client


# ── Fail-closed OSIDB keytab tests ──────────────────────────────────


@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_fails_when_no_keytab_configured(
    mock_process_osv: Mock,
    mock_oci: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """No --osidb-keytab at all aborts the run instead of skipping OSIDB."""
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, ["registry.local/ntplib@sha256:aaa"])
    workdir = tmp_path / "workdir"
    output_dir = workdir / "security_metadata"

    runner = CliRunner()
    result = _invoke(runner, snapshot, workdir, output_dir, ctx)

    assert result.exit_code != 0
    assert "missing or not readable" in result.output
    mock_oci.discover.assert_not_called()
    mock_process_osv.assert_not_called()


@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_fails_when_keytab_file_missing(
    mock_process_osv: Mock,
    mock_oci: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A --osidb-keytab path that doesn't exist on disk aborts the run."""
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, ["registry.local/ntplib@sha256:aaa"])
    workdir = tmp_path / "workdir"
    output_dir = workdir / "security_metadata"

    runner = CliRunner()
    result = _invoke(
        runner,
        snapshot,
        workdir,
        output_dir,
        ctx,
        **_osidb_kwargs(tmp_path / "missing.keytab"),
    )

    assert result.exit_code != 0
    assert "missing or not readable" in result.output
    mock_oci.discover.assert_not_called()
    mock_process_osv.assert_not_called()


@patch("slan_cuan.tasks.generate_security_metadata.oci")
@patch("slan_cuan.tasks.generate_security_metadata.process_osv")
def test_fails_when_keytab_unreadable(
    mock_process_osv: Mock,
    mock_oci: Mock,
    ctx: GlobalContext,
    osidb_keytab: Path,
    tmp_path: Path,
) -> None:
    """A keytab that exists but isn't readable aborts the run."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses file permission bits")

    osidb_keytab.chmod(0o000)
    try:
        snapshot = tmp_path / "snapshot.json"
        _write_snapshot(snapshot, ["registry.local/ntplib@sha256:aaa"])
        workdir = tmp_path / "workdir"
        output_dir = workdir / "security_metadata"

        runner = CliRunner()
        result = _invoke(
            runner,
            snapshot,
            workdir,
            output_dir,
            ctx,
            **_osidb_kwargs(osidb_keytab),
        )

        assert result.exit_code != 0
        assert "missing or not readable" in result.output
        mock_oci.discover.assert_not_called()
        mock_process_osv.assert_not_called()
    finally:
        osidb_keytab.chmod(0o600)
