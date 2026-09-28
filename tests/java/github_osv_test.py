"""Tests for the GitHub OSV client (slan_cuan/java/github_osv.py)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from slan_cuan.java.github_osv import GitHubOsvClient, GitHubOsvError


def _git(cwd: Path, *args: str) -> None:
    """Run a git command in ``cwd``, failing the test on error."""
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def origin_and_client(
    tmp_path: Path,
) -> tuple[Path, GitHubOsvClient]:
    """Create a local bare 'origin' repo and a client pointed at it.

    The client's authenticated URL is patched to the local bare repo path so
    clone/push exercise real git without touching the network.
    """
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "--bare", "--initial-branch", "main", str(origin)],
        check=True,
        capture_output=True,
    )
    # Seed the bare repo with an initial commit on main.
    seed = tmp_path / "seed"
    subprocess.run(
        ["git", "clone", str(origin), str(seed)],
        check=True,
        capture_output=True,
    )
    _git(seed, "config", "user.email", "seed@example.com")
    _git(seed, "config", "user.name", "seed")
    (seed / "README.md").write_text("osv db\n")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-m", "init")
    _git(seed, "push", "origin", "main")

    client = GitHubOsvClient("owner/lightwell-osv", "tok", branch="main")
    # Route the "authenticated" clone URL to the local bare repo.
    with patch.object(
        GitHubOsvClient,
        "_authenticated_url",
        new=property(lambda self: str(origin)),
    ):
        yield origin, client


def _read_origin_files(
    tmp_path: Path, origin: Path, subdir: str = ""
) -> set[str]:
    """Clone origin and return the set of file names under ``subdir``."""
    checkout = tmp_path / "verify"
    subprocess.run(
        ["git", "clone", str(origin), str(checkout)],
        check=True,
        capture_output=True,
    )
    base = checkout / subdir if subdir else checkout
    return {p.name for p in base.iterdir() if p.is_file()}


def test_publish_pushes_records_to_root(
    origin_and_client: tuple[Path, GitHubOsvClient], tmp_path: Path
) -> None:
    """Records are committed and pushed to the repository root."""
    origin, client = origin_and_client
    rec = tmp_path / "x_RHLW-CVE-2025-1.json"
    rec.write_text('{"id": "x_RHLW-CVE-2025-1"}')

    with patch.object(
        GitHubOsvClient,
        "_authenticated_url",
        new=property(lambda self: str(origin)),
    ):
        commit = client.publish([rec], "add record")

    assert commit is not None and len(commit) == 40
    assert "x_RHLW-CVE-2025-1.json" in _read_origin_files(tmp_path, origin)


def test_publish_uses_path_prefix(tmp_path: Path) -> None:
    """Records land under the configured path prefix."""
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "--bare", "--initial-branch", "main", str(origin)],
        check=True,
        capture_output=True,
    )
    seed = tmp_path / "seed"
    subprocess.run(
        ["git", "clone", str(origin), str(seed)],
        check=True,
        capture_output=True,
    )
    _git(seed, "config", "user.email", "seed@example.com")
    _git(seed, "config", "user.name", "seed")
    (seed / "README.md").write_text("osv db\n")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-m", "init")
    _git(seed, "push", "origin", "main")

    client = GitHubOsvClient("owner/repo", "tok", branch="main", path="Maven")
    rec = tmp_path / "x_RHLW-LW-1.json"
    rec.write_text('{"id": "x_RHLW-LW-1"}')

    with patch.object(
        GitHubOsvClient,
        "_authenticated_url",
        new=property(lambda self: str(origin)),
    ):
        commit = client.publish([rec], "add record")

    assert commit is not None
    assert "x_RHLW-LW-1.json" in _read_origin_files(tmp_path, origin, "Maven")


def test_publish_no_files_returns_none() -> None:
    """Publishing an empty record set is a no-op."""
    client = GitHubOsvClient("owner/repo", "tok")
    assert client.publish([], "noop") is None


def test_publish_idempotent_returns_none(
    origin_and_client: tuple[Path, GitHubOsvClient], tmp_path: Path
) -> None:
    """Re-publishing identical records introduces no commit."""
    origin, client = origin_and_client
    rec = tmp_path / "x_RHLW-CVE-2025-2.json"
    rec.write_text('{"id": "x_RHLW-CVE-2025-2"}')

    with patch.object(
        GitHubOsvClient,
        "_authenticated_url",
        new=property(lambda self: str(origin)),
    ):
        first = client.publish([rec], "add")
        second = client.publish([rec], "add again")

    assert first is not None
    assert second is None


def test_publish_raises_on_git_failure(tmp_path: Path) -> None:
    """A failing git command raises GitHubOsvError with redacted token."""
    client = GitHubOsvClient("owner/missing", "supersecret", branch="main")
    rec = tmp_path / "r.json"
    rec.write_text("{}")

    # Clone of a non-existent local path fails.
    with patch.object(
        GitHubOsvClient,
        "_authenticated_url",
        new=property(lambda self: str(tmp_path / "does-not-exist.git")),
    ):
        with pytest.raises(GitHubOsvError) as exc:
            client.publish([rec], "msg")

    assert "supersecret" not in exc.value.stderr
