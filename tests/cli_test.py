"""Tests for CLI group wiring, subcommand reachability, and env-var precedence."""

from __future__ import annotations

from unittest.mock import Mock, patch

from click.testing import CliRunner

from slan_cuan.cli import main


def test_extract_subcommand_is_reachable() -> None:
    """Extract subcommand responds to --help and shows --image option."""
    runner = CliRunner()
    result = runner.invoke(main, ["extract", "--help"])

    assert result.exit_code == 0
    assert "--image" in result.output


def test_help_lists_extract_subcommand() -> None:
    """slan-cuan --help includes extract in subcommand list."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "extract" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
def test_env_var_override_for_global_option(
    mock_manifest_fetch: Mock,
) -> None:
    """SLAN_CUAN_VERBOSE sets --verbose via environment variable."""
    fake_manifest = {
        "layers": [
            {
                "digest": "sha256:abc",
                "mediaType": (
                    "application/vnd.lightwell.build-output.layer.v1+tar"
                ),
                "size": 1000,
            }
        ],
        "annotations": {
            "org.opencontainers.image.title": "TEST-build-output",
        },
    }
    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "--dry-run",
                "extract",
                "--image",
                "quay.io/test/image@sha256:abc123",
                "--output-dir",
                "output",
            ],
            env={"SLAN_CUAN_VERBOSE": "true"},
        )

        assert result.exit_code == 0
        assert "Parsed image reference:" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
def test_env_var_override_for_subcommand_option(
    mock_manifest_fetch: Mock,
) -> None:
    """SLAN_CUAN_EXTRACT_IMAGE sets --image via environment variable."""
    fake_manifest = {
        "layers": [
            {
                "digest": "sha256:abc",
                "mediaType": (
                    "application/vnd.lightwell.build-output.layer.v1+tar"
                ),
                "size": 1000,
            }
        ],
        "annotations": {
            "org.opencontainers.image.title": "TEST-build-output",
        },
    }
    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "--dry-run",
                "extract",
                "--output-dir",
                "output",
            ],
            env={"SLAN_CUAN_EXTRACT_IMAGE": "registry.example.com/image:latest"},
        )

        assert result.exit_code == 0
        assert "registry.example.com/image:latest" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
def test_cli_flag_overrides_env_var(mock_manifest_fetch: Mock) -> None:
    """CLI flag value takes precedence over env var when both are set."""
    fake_manifest = {
        "layers": [
            {
                "digest": "sha256:abc",
                "mediaType": (
                    "application/vnd.lightwell.build-output.layer.v1+tar"
                ),
                "size": 1000,
            }
        ],
        "annotations": {
            "org.opencontainers.image.title": "TEST-build-output",
        },
    }
    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "--dry-run",
                "extract",
                "--image",
                "quay.io/flag/value:latest",
                "--output-dir",
                "output",
            ],
            env={"SLAN_CUAN_EXTRACT_IMAGE": "env-value"},
        )

        assert result.exit_code == 0
        assert "quay.io/flag/value:latest" in result.output
        assert "env-value" not in result.output


def test_extract_shows_new_options_in_help() -> None:
    """Extract help shows --output-dir, --registry-auth-file, --force."""
    runner = CliRunner()
    result = runner.invoke(main, ["extract", "--help"])

    assert result.exit_code == 0
    assert "--output-dir" in result.output
    assert "--registry-auth-file" in result.output
    assert "--force" in result.output


def test_extract_requires_output_dir() -> None:
    """Extract without --output-dir produces error."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["extract", "--image", "quay.io/test/image:latest"],
    )

    assert result.exit_code != 0
    assert "--output-dir" in result.output or "Missing option" in result.output


def test_publish_subcommand_is_reachable() -> None:
    """Publish subcommand responds to --help and shows --pulp-url."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])
    assert result.exit_code == 0
    assert "--pulp-url" in result.output


def test_help_lists_publish_subcommand() -> None:
    """slan-cuan --help includes publish in subcommand list."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "publish" in result.output


def test_ca_cert_shown_in_help() -> None:
    """--ca-cert appears in the top-level --help output."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--ca-cert" in result.output


def test_ca_cert_rejects_nonexistent_path() -> None:
    """--ca-cert with a nonexistent file produces an error."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--ca-cert",
            "/nonexistent/ca.crt",
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


def test_tekton_results_dir_shown_in_help() -> None:
    """--tekton-results-dir appears in the top-level --help output."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "--tekton-results-dir" in result.output


@patch("slan_cuan.java.extract.manifest_fetch")
def test_tekton_results_dir_env_var(mock_manifest_fetch: Mock) -> None:
    """SLAN_CUAN_TEKTON_RESULTS_DIR sets --tekton-results-dir."""
    fake_manifest = {
        "layers": [
            {
                "digest": "sha256:abc",
                "mediaType": (
                    "application/vnd.lightwell.build-output.layer.v1+tar"
                ),
                "size": 1000,
            }
        ],
        "annotations": {
            "org.opencontainers.image.title": "TEST-build-output",
        },
    }
    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "--dry-run",
                "extract",
                "--image",
                "quay.io/test/image@sha256:abc123",
                "--output-dir",
                "output",
            ],
            env={"SLAN_CUAN_TEKTON_RESULTS_DIR": "results"},
        )

        assert result.exit_code == 0
