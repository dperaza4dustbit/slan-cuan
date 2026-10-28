"""Run bash helper checks for npm attestation label helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests" / "npm" / "test_npm_attestation_helpers.sh"


def test_npm_attestation_helpers() -> None:
    """Execute the shell assertions for OCI base and attestation tags."""
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
