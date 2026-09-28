"""Publish OSV records to a GitHub repository using the git CLI.

The OSV destination on GitHub is an ordinary git repository of OSV JSON
documents (one file per vulnerability record). Publication is therefore a
shallow clone, a copy of the generated records into the configured path, a
single commit, and a push -- distinct from the Pulp File upload path in
``slan_cuan.publish``. Both sinks consume the same filtered record set.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path

_GITHUB_HOST = "github.com"
_DEFAULT_GIT_USER_NAME = "slan-cuan"
_DEFAULT_GIT_USER_EMAIL = "slan-cuan@redhat.com"


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
            verbose: Whether to log the (token-redacted) git commands.

        """
        self.repo = repo.strip().strip("/")
        self._token = token
        self.branch = branch
        self.path = path.strip().strip("/")
        self.user_name = user_name
        self.user_email = user_email
        self.verbose = verbose

    @property
    def _authenticated_url(self) -> str:
        """Return the HTTPS clone URL with the token embedded."""
        return (
            f"https://x-access-token:{self._token}@{_GITHUB_HOST}/{self.repo}.git"
        )

    @property
    def _redacted_url(self) -> str:
        """Return the clone URL with the token redacted, for logging."""
        return f"https://x-access-token:***@{_GITHUB_HOST}/{self.repo}.git"

    def _run(self, cmd: list[str], cwd: Path | None = None) -> str:
        """Run a git command, redacting the token from any error output."""
        if self.verbose:
            printable = [
                self._redacted_url if arg == self._authenticated_url else arg
                for arg in cmd
            ]
            print(f"Running: {' '.join(printable)}")

        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip().replace(self._token, "***")
            raise GitHubOsvError(
                f"git command failed: {' '.join(cmd[:2])}",
                stderr,
                result.returncode,
            )
        return result.stdout

    def publish(self, files: Sequence[Path], commit_message: str) -> str | None:
        """Publish OSV records to the repository.

        Clones the repository shallowly, copies ``files`` into the configured
        path, and commits and pushes them as a single commit. Records with a
        name already present are overwritten (idempotent re-publication).

        Args:
            files: OSV JSON files to publish.
            commit_message: Message for the single commit.

        Returns:
            The pushed commit SHA, or ``None`` when the records introduced no
            change (nothing to commit).

        Raises:
            GitHubOsvError: If any git operation fails.

        """
        if not files:
            return None

        with tempfile.TemporaryDirectory(prefix="slan-cuan-osv-") as tmp:
            clone_dir = Path(tmp) / "repo"
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
                ]
            )
            self._run(
                ["git", "config", "user.name", self.user_name], cwd=clone_dir
            )
            self._run(
                ["git", "config", "user.email", self.user_email], cwd=clone_dir
            )

            dest_dir = clone_dir / self.path if self.path else clone_dir
            dest_dir.mkdir(parents=True, exist_ok=True)
            for src in files:
                shutil.copy2(src, dest_dir / src.name)

            self._run(["git", "add", "-A"], cwd=clone_dir)

            status = self._run(["git", "status", "--porcelain"], cwd=clone_dir)
            if not status.strip():
                # Records already match the repository contents.
                return None

            self._run(["git", "commit", "-m", commit_message], cwd=clone_dir)
            self._run(
                ["git", "push", "origin", f"HEAD:{self.branch}"], cwd=clone_dir
            )
            return self._run(["git", "rev-parse", "HEAD"], cwd=clone_dir).strip()
