#!/usr/bin/env python3
"""Check whether the vendored release-service-catalog pipeline fixture is fresh.

Check whether the vendored release-service-catalog pipeline fixture
used by tests/integrity/pipeline_contract_test.py has drifted from the
live file on GitHub.

Non-blocking by design: run on a schedule (see
.github/workflows/pipeline-fixture-freshness.yml), never as part of the
PR-blocking test suite. A failure here means "refresh the fixture," not
"a contract broke" -- see tests/integrity/README.md.
"""

from __future__ import annotations

import difflib
import sys
import urllib.request
from pathlib import Path

LIVE_URL = (
    "https://raw.githubusercontent.com/konflux-lightwell/"
    "release-service-catalog/development/pipelines/managed/"
    "slan-cuan-release/slan-cuan-release.yaml"
)

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "tests"
    / "integrity"
    / "fixtures"
    / "release-service-catalog"
    / "pipelines"
    / "managed"
    / "slan-cuan-release"
    / "slan-cuan-release.yaml"
)


def _strip_header_comment(text: str) -> str:
    """Drop the vendoring header comment before diffing.

    Drop this repo's own vendoring header comment before diffing,
    since it legitimately differs from the live file by design.
    """
    lines = text.splitlines(keepends=True)
    first_doc_start = next(
        i for i, line in enumerate(lines) if line.startswith("---")
    )
    return "".join(lines[first_doc_start:])


def main() -> int:
    """Fetch the live pipeline YAML and diff it against the vendored copy."""
    with urllib.request.urlopen(LIVE_URL, timeout=30) as response:  # noqa: S310
        live_content = response.read().decode("utf-8")

    vendored_content = _strip_header_comment(FIXTURE_PATH.read_text())

    diff = list(
        difflib.unified_diff(
            vendored_content.splitlines(keepends=True),
            live_content.splitlines(keepends=True),
            fromfile="vendored fixture",
            tofile="live release-service-catalog@development",
        )
    )
    if diff:
        print("Vendored pipeline fixture has drifted from the live file:")
        print("".join(diff))
        print(
            "\nRefresh the fixture -- see tests/integrity/README.md "
            "('pipeline_contract_test.py caveats')."
        )
        return 1

    print("Vendored pipeline fixture is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
