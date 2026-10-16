"""Snapshot spec parsing.

A snapshot spec lists the component images of a release; the
``components[].containerImage`` entries are digest-pinned image
references. Parsing is ecosystem-agnostic.
"""

from __future__ import annotations

import json
from pathlib import Path

import click


def snapshot_component_images(snapshot_path: Path) -> list[str]:
    """Read the container image references from a snapshot spec.

    Fails closed when the file is missing, unparsable, or carries no
    component images.
    """
    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise click.ClickException(
            f"Failed to parse snapshot spec {snapshot_path}: {e}"
        ) from e

    images = [
        c.get("containerImage")
        for c in snapshot.get("components", [])
        if isinstance(c, dict) and c.get("containerImage")
    ]
    if not images:
        raise click.ClickException(
            f"No component containerImage entries in snapshot {snapshot_path}"
        )
    return images
