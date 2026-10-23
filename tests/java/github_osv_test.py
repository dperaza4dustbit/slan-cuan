"""Tests for the GitHub OSV client (slan_cuan/java/github_osv.py)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from slan_cuan.java import github_osv
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


def _land_competing_commit(origin: Path, tmp_path: Path, name: str) -> None:
    """Push a disjoint, net-new file to origin (simulates a concurrent run)."""
    work = tmp_path / f"competitor-{name}"
    subprocess.run(
        ["git", "clone", str(origin), str(work)],
        check=True,
        capture_output=True,
    )
    _git(work, "config", "user.email", "other@example.com")
    _git(work, "config", "user.name", "other")
    (work / name).write_text("{}")
    _git(work, "add", "-A")
    _git(work, "commit", "-m", f"competing {name}")
    _git(work, "push", "origin", "main")


def test_publish_retries_on_concurrent_push(
    origin_and_client: tuple[Path, GitHubOsvClient], tmp_path: Path
) -> None:
    """A non-fast-forward rejection re-clones and retries, then succeeds."""
    origin, _ = origin_and_client
    client = GitHubOsvClient(
        "owner/lightwell-osv",
        "tok",
        branch="main",
        max_attempts=3,
        retry_base_delay=0.0,
    )
    rec = tmp_path / "x_RHLW-CVE-2025-RACE.json"
    rec.write_text('{"id": "x_RHLW-CVE-2025-RACE"}')

    original_run = GitHubOsvClient._run
    state = {"pushed": False}

    def wrapped_run(self, cmd, cwd=None, env=None):
        # Just before the first real push, a competing release lands a commit,
        # making this clone stale and the push non-fast-forward.
        if cmd[:2] == ["git", "push"] and not state["pushed"]:
            state["pushed"] = True
            _land_competing_commit(origin, tmp_path, "competitor.json")
        return original_run(self, cmd, cwd=cwd, env=env)

    with (
        patch.object(
            GitHubOsvClient,
            "_authenticated_url",
            new=property(lambda self: str(origin)),
        ),
        patch.object(GitHubOsvClient, "_run", wrapped_run),
        patch.object(github_osv.time, "sleep"),
    ):
        commit = client.publish([rec], "add record")

    assert commit is not None
    files = _read_origin_files(tmp_path, origin)
    # Both the competing file and our own record are present (disjoint writes).
    assert "competitor.json" in files
    assert "x_RHLW-CVE-2025-RACE.json" in files


def test_publish_timeout_raises(
    origin_and_client: tuple[Path, GitHubOsvClient], tmp_path: Path
) -> None:
    """A git command exceeding the timeout raises GitHubOsvError."""
    origin, _ = origin_and_client
    client = GitHubOsvClient("owner/lightwell-osv", "tok", branch="main")
    rec = tmp_path / "x_RHLW-CVE-2025-TO.json"
    rec.write_text("{}")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1)

    with (
        patch.object(
            GitHubOsvClient,
            "_authenticated_url",
            new=property(lambda self: str(origin)),
        ),
        patch("subprocess.run", side_effect=fake_run),
    ):
        with pytest.raises(GitHubOsvError) as exc:
            client.publish([rec], "msg")

    assert "timed out" in exc.value.message


def test_publish_warns_on_content_change(
    origin_and_client: tuple[Path, GitHubOsvClient],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Overwriting an existing record with different bytes warns loudly."""
    origin, client = origin_and_client
    rec = tmp_path / "x_RHLW-CVE-2025-3.json"

    with patch.object(
        GitHubOsvClient,
        "_authenticated_url",
        new=property(lambda self: str(origin)),
    ):
        rec.write_text('{"id": "x_RHLW-CVE-2025-3", "v": 1}')
        client.publish([rec], "add")
        rec.write_text('{"id": "x_RHLW-CVE-2025-3", "v": 2}')
        client.publish([rec], "update")

    err = capsys.readouterr().err
    assert "overwriting existing record with changed content" in err
    assert "x_RHLW-CVE-2025-3.json" in err


def test_token_not_passed_as_argument(
    origin_and_client: tuple[Path, GitHubOsvClient], tmp_path: Path
) -> None:
    """The token never appears in any git command line (only via env)."""
    origin, _ = origin_and_client
    client = GitHubOsvClient("owner/lightwell-osv", "supersecret", branch="main")
    rec = tmp_path / "x_RHLW-CVE-2025-4.json"
    rec.write_text("{}")

    seen_cmds: list[list[str]] = []
    real_run = subprocess.run

    def recording_run(cmd, *args, **kwargs):
        seen_cmds.append(list(cmd))
        return real_run(cmd, *args, **kwargs)

    with (
        patch.object(
            GitHubOsvClient,
            "_authenticated_url",
            new=property(lambda self: str(origin)),
        ),
        patch("subprocess.run", side_effect=recording_run),
    ):
        client.publish([rec], "msg")

    assert seen_cmds  # sanity: git actually ran
    assert not any("supersecret" in arg for cmd in seen_cmds for arg in cmd)
