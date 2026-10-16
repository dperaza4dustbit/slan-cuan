"""Snapshot spec parsing.

A snapshot spec lists the component images of a release; the
``components[].containerImage`` entries are digest-pinned image
references. Parsing is ecosystem-agnostic.
"""

from __future__ import annotations

from pathlib import Path

import click

from slan_cuan.utils import safe_json_load


def snapshot_component_images(snapshot_path: Path) -> list[str]:
    """Read the container image references from a snapshot spec.

    Fails closed when the file is missing, unparsable, or carries no
    component images.
    """
    snapshot = safe_json_load(
        snapshot_path,
        parse_err_msg=f"Failed to parse snapshot spec {snapshot_path}",
        expected_type=dict,
        type_err_msg=f"Snapshot spec {snapshot_path} is not a JSON object",
        raise_type=click.ClickException,
    )

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
