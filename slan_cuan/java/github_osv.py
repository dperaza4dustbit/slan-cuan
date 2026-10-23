"""Publish OSV records to a GitHub repository using the git CLI.

The OSV destination on GitHub is an ordinary git repository of OSV JSON
documents (one file per vulnerability record). Publication is therefore a
shallow clone, a copy of the generated records into the configured path, a
single commit, and a push -- distinct from the Pulp File upload path in
``slan_cuan.publish``. Both sinks consume the same filtered record set.

Concurrency: because the records are written one file per CVE ID, concurrent
releases write net-new, disjoint files. On a non-fast-forward push rejection
the client re-clones from a fresh HEAD and replays the copy/commit/push --
it never rebases, so the retry relies only on the re-clone picking up the
competing commit. Retries use exponential backoff with jitter so a burst of
concurrent releases does not lockstep-retry against each other.

Credentials: the token is never passed as a command-line argument (which would
expose it via ``/proc/<pid>/cmdline``). Instead the clone URL carries only the
non-secret username and the token is supplied through a ``GIT_ASKPASS`` helper
that reads it from the subprocess environment.
"""

from __future__ import annotations

import os
import random
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

import click

_GITHUB_HOST = "github.com"
_DEFAULT_GIT_USER_NAME = "slan-cuan"
_DEFAULT_GIT_USER_EMAIL = "slan-cuan@redhat.com"
_GIT_USERNAME = "x-access-token"

# Default per-command timeout (seconds) for git network operations, matching
# the bounded-timeout convention of the rest of the publish command.
_DEFAULT_TIMEOUT = 300
_DEFAULT_MAX_ATTEMPTS = 3
_DEFAULT_RETRY_BASE_DELAY = 1.0

# Env var used to hand the token to the GIT_ASKPASS helper out of band.
_ASKPASS_TOKEN_ENV = "SLAN_CUAN_OSV_GIT_TOKEN"

# Substrings that identify a non-fast-forward push rejection (a concurrent
# release landed a commit first). These -- and only these -- are retriable.
_NON_FAST_FORWARD_MARKERS = (
    "non-fast-forward",
    "[rejected]",
    "fetch first",
    "updates were rejected",
)


class GitHubOsvError(Exception):
    """Exception raised when a git operation for OSV publication fails."""

    def __init__(self, message: str, stderr: str, returncode: int) -> None:
        """Initialize GitHubOsvError.

        Args:
            message: Human-readable error message.
            stderr: Raw stderr from the git command (token already redacted).
            returncode: Exit code from the git command.

        """
        super().__init__(message)
        self.message = message
        self.stderr = stderr
        self.returncode = returncode

    @property
    def is_non_fast_forward(self) -> bool:
        """Whether this failure is a retriable non-fast-forward rejection."""
        haystack = f"{self.message}\n{self.stderr}".lower()
        return any(marker in haystack for marker in _NON_FAST_FORWARD_MARKERS)


class GitHubOsvClient:
    """Publishes OSV JSON records to a GitHub repository via the git CLI."""

    def __init__(
        self,
        repo: str,
        token: str,
        *,
        branch: str = "main",
        path: str = "",
        user_name: str = _DEFAULT_GIT_USER_NAME,
        user_email: str = _DEFAULT_GIT_USER_EMAIL,
        verbose: bool = False,
        timeout: int = _DEFAULT_TIMEOUT,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
        retry_base_delay: float = _DEFAULT_RETRY_BASE_DELAY,
    ) -> None:
        """Initialize the client.

        Args:
            repo: Repository in ``owner/name`` form (e.g.
                ``project-lightwell/lightwell-osv``).
            token: Personal access / bot token with write access.
            branch: Branch to commit records onto.
            path: Directory prefix inside the repository for records; empty
                means the repository root.
            user_name: git commit author/committer name.
            user_email: git commit author/committer email.
            verbose: Whether to log the (token-free) git commands.
            timeout: Per-command timeout in seconds for git operations.
            max_attempts: Total push attempts before giving up on a
                non-fast-forward rejection (re-clone-and-retry).
            retry_base_delay: Base delay (seconds) for exponential backoff
                between retry attempts.

        """
        self.repo = repo.strip().strip("/")
        self._token = token
        self.branch = branch
        self.path = path.strip().strip("/")
        self.user_name = user_name
        self.user_email = user_email
        self.verbose = verbose
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.retry_base_delay = retry_base_delay

    @property
    def _authenticated_url(self) -> str:
        """Return the HTTPS clone URL.

        The URL carries only the non-secret username; the token is supplied
        separately via ``GIT_ASKPASS`` and never appears on the command line.
        """
        return f"https://{_GIT_USERNAME}@{_GITHUB_HOST}/{self.repo}.git"

    def _display(self, cmd: Sequence[str]) -> str:
        """Render a command for logs/errors, defensively redacting the token."""
        return " ".join(cmd).replace(self._token, "***")

    def _run(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> str:
        """Run a git command, redacting the token from any error output."""
        if self.verbose:
            click.echo(f"Running: {self._display(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise GitHubOsvError(
                f"git command timed out after {self.timeout}s: "
                f"{self._display(cmd)}",
                "",
                -1,
            ) from e
        if result.returncode != 0:
            stderr = result.stderr.strip().replace(self._token, "***")
            raise GitHubOsvError(
                f"git command failed: {self._display(cmd)}",
                stderr,
                result.returncode,
            )
        return result.stdout

    def _build_git_env(self, tmp: Path) -> dict[str, str]:
        """Create a GIT_ASKPASS helper and return the git subprocess env.

        The helper echoes the token read from ``_ASKPASS_TOKEN_ENV`` so the
        secret lives only in the subprocess environment, never in argv.
        """
        askpass = tmp / "askpass.sh"
        askpass.write_text(f'#!/bin/sh\nprintf "%s" "${_ASKPASS_TOKEN_ENV}"\n')
        askpass.chmod(askpass.stat().st_mode | stat.S_IRWXU)

        env = os.environ.copy()
        env["GIT_ASKPASS"] = str(askpass)
        env[_ASKPASS_TOKEN_ENV] = self._token
        # Never fall back to an interactive prompt that would hang the step.
        env["GIT_TERMINAL_PROMPT"] = "0"
        return env

    def _warn_on_content_changes(
        self, files: Sequence[Path], dest_dir: Path
    ) -> None:
        """Warn loudly when an existing record is about to change content.

        Re-publication is last-writer-wins: records with a name already present
        are overwritten. For deterministic generation this never fires; when it
        does, surface it rather than silently overwriting.
        """
        for src in files:
            dest = dest_dir / src.name
            if dest.exists() and dest.read_bytes() != src.read_bytes():
                click.echo(
                    f"GitHub OSV: overwriting existing record with changed "
                    f"content: {src.name}",
                    err=True,
                )

    def publish(self, files: Sequence[Path], commit_message: str) -> str | None:
        """Publish OSV records to the repository.

        Clones the repository shallowly, copies ``files`` into the configured
        path, and commits and pushes them as a single commit. Records with a
        name already present are overwritten (idempotent re-publication). On a
        non-fast-forward push rejection -- a concurrent release landed a commit
        first -- the whole clone/copy/commit/push is retried against a fresh
        clone, with exponential backoff and jitter between attempts.

        Args:
            files: OSV JSON files to publish.
            commit_message: Message for the single commit.

        Returns:
            The pushed commit SHA, or ``None`` when the records introduced no
            change (nothing to commit).

        Raises:
            GitHubOsvError: If any git operation fails (non-retriably, or after
                exhausting retries on a non-fast-forward rejection).

        """
        if not files:
            return None

        with tempfile.TemporaryDirectory(prefix="slan-cuan-osv-") as tmp:
            tmp_path = Path(tmp)
            env = self._build_git_env(tmp_path)

            for attempt in range(self.max_attempts):
                clone_dir = tmp_path / f"repo-{attempt}"
                try:
                    return self._publish_once(
                        files, commit_message, clone_dir, env
                    )
                except GitHubOsvError as e:
                    last_attempt = attempt == self.max_attempts - 1
                    if last_attempt or not e.is_non_fast_forward:
                        raise
                    delay = self.retry_base_delay * 2**attempt
                    delay += random.uniform(0, 1)
                    click.echo(
                        f"GitHub OSV: push rejected (non-fast-forward), "
                        f"re-cloning and retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{self.max_attempts})",
                        err=True,
                    )
                    time.sleep(delay)

        # Unreachable: the loop either returns or raises.
        return None

    def _publish_once(
        self,
        files: Sequence[Path],
        commit_message: str,
        clone_dir: Path,
        env: dict[str, str],
    ) -> str | None:
        """Perform a single clone/copy/commit/push cycle.

        The retry loop in :meth:`publish` relies on this re-cloning from HEAD
        on every call (``--depth 1`` is sufficient since we replay rather than
        rebase).
        """
        self._run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                self.branch,
                self._authenticated_url,
                str(clone_dir),
            ],
            env=env,
        )
        self._run(["git", "config", "user.name", self.user_name], cwd=clone_dir)
        self._run(["git", "config", "user.email", self.user_email], cwd=clone_dir)

        dest_dir = clone_dir / self.path if self.path else clone_dir
        dest_dir.mkdir(parents=True, exist_ok=True)
        self._warn_on_content_changes(files, dest_dir)
        for src in files:
            shutil.copy2(src, dest_dir / src.name)

        self._run(["git", "add", "-A"], cwd=clone_dir)

        status = self._run(["git", "status", "--porcelain"], cwd=clone_dir)
        if not status.strip():
            # Records already match the repository contents.
            return None

        self._run(["git", "commit", "-m", commit_message], cwd=clone_dir)
        self._run(
            ["git", "push", "origin", f"HEAD:{self.branch}"],
            cwd=clone_dir,
            env=env,
        )
        return self._run(["git", "rev-parse", "HEAD"], cwd=clone_dir).strip()
