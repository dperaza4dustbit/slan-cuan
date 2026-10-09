#!/usr/bin/env python3
"""Refresh the vendored release-service-catalog pipeline fixture.

Pulls the current `slan-cuan-release.yaml` pipeline from
`release-service-catalog` and overwrites the vendored, pinned copy at
`tests/integrity/fixtures/release-service-catalog/...` used by
`pipeline_contract_test.py`, stamping the new header with the source
branch and commit. See tests/integrity/README.md for when and why to
refresh this fixture.

Usage:
    python3 scripts/update_pipeline_fixture.py
    python3 scripts/update_pipeline_fixture.py --branch some-feature-branch
    python3 scripts/update_pipeline_fixture.py --dry-run
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_pipeline_fixture_freshness import (  # noqa: E402
    FIXTURE_PATH,
    _strip_header_comment,
)

REPO = "konflux-lightwell/release-service-catalog"
FIXTURE_REPO_PATH = "pipelines/managed/slan-cuan-release/slan-cuan-release.yaml"


def _github_request(url: str) -> bytes:
    """GET a GitHub URL, authenticating with GITHUB_TOKEN if set."""
    request = urllib.request.Request(url)  # noqa: S310
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return response.read()


def fetch_live_yaml(branch: str) -> str:
    """Fetch the raw pipeline YAML from release-service-catalog@branch."""
    url = f"https://raw.githubusercontent.com/{REPO}/{branch}/{FIXTURE_REPO_PATH}"
    return _github_request(url).decode("utf-8")


def fetch_latest_commit(branch: str) -> str:
    """Return the short SHA of the latest commit touching the fixture path."""
    url = (
        f"https://api.github.com/repos/{REPO}/commits"
        f"?path={FIXTURE_REPO_PATH}&sha={branch}&per_page=1"
    )
    commits = json.loads(_github_request(url))
    if not commits:
        raise RuntimeError(
            f"No commits found for {FIXTURE_REPO_PATH} on branch {branch!r}"
        )
    return commits[0]["sha"][:7]


_PROVENANCE_RE = re.compile(r"Copied from branch (\S+) at commit ([0-9a-f]+),")


def _header_provenance(content: str) -> tuple[str, str] | None:
    """Extract (branch, commit) from a fixture's vendoring header, if any.

    Deliberately ignores the header's refresh date -- that always differs
    run to run and isn't meaningful provenance to diff on.
    """
    header = content[: len(content) - len(_strip_header_comment(content))]
    match = _PROVENANCE_RE.search(header)
    return (match.group(1), match.group(2)) if match else None


def build_header(branch: str, commit: str) -> str:
    """Build the vendoring header comment stamped with branch/commit/date."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return (
        "# VENDORED FIXTURE -- pinned, not live-fetched.\n"
        f"# Source: https://github.com/{REPO}/blob/{branch}/{FIXTURE_REPO_PATH}\n"
        f"# Copied from branch {branch} at commit {commit}, refreshed via\n"
        f"# scripts/update_pipeline_fixture.py on {today}.\n"
        "# See tests/integrity/README.md for how to refresh this fixture and\n"
        "# what a test failure here means (real break vs. stale fixture).\n"
    )


def main() -> int:
    """Fetch the live pipeline YAML and rewrite the vendored fixture."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--branch",
        default="development",
        help="release-service-catalog branch to pull from (default: development)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show the diff without writing the fixture file",
    )
    args = parser.parse_args()

    live_content = fetch_live_yaml(args.branch)
    commit = fetch_latest_commit(args.branch)
    new_content = build_header(args.branch, commit) + live_content

    old_content = FIXTURE_PATH.read_text() if FIXTURE_PATH.exists() else ""
    body_diff = list(
        difflib.unified_diff(
            _strip_header_comment(old_content).splitlines(keepends=True)
            if old_content
            else [],
            _strip_header_comment(new_content).splitlines(keepends=True),
            fromfile="current fixture",
            tofile=f"release-service-catalog@{args.branch}",
        )
    )
    provenance_changed = _header_provenance(old_content) != (args.branch, commit)

    if not body_diff and not provenance_changed:
        print("Fixture is already up to date with the live content.")
        return 0

    if body_diff:
        print(
            f"Pulling {FIXTURE_REPO_PATH} from {REPO}@{args.branch} ({commit}):"
        )
        print("".join(body_diff))
    else:
        print(
            f"Pipeline body is unchanged, but the vendored header's "
            f"branch/commit is stale -- refreshing provenance to "
            f"{args.branch!r} at {commit}."
        )

    if args.dry_run:
        if body_diff:
            print("\nDry run -- fixture not written.")
        else:
            print("\nDry run -- header-only update not written.")
        return 0

    FIXTURE_PATH.write_text(new_content)
    print(f"\nFixture updated: {FIXTURE_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
