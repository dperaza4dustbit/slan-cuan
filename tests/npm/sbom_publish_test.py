"""Run bash checks for npm CycloneDX SBOM publish."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests" / "npm" / "test_npm_sbom_publish.sh"


def test_npm_sbom_publish() -> None:
    """Execute the shell checks for referrer discovery, push, and labels."""
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
