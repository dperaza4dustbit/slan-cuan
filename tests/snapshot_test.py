"""Tests for snapshot spec parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slan_cuan.snapshot import snapshot_component_images

IMAGE = "quay.io/repo/wheels@sha256:1111"


def _make_snapshot(tmp_path: Path, images: list[str]) -> Path:
    snapshot = tmp_path / "snapshot_spec.json"
    snapshot.write_text(
        json.dumps({"components": [{"containerImage": i} for i in images]})
    )
    return snapshot


class TestSnapshotComponentImages:
    """Tests for snapshot spec parsing."""

    def test_reads_component_images(self, tmp_path: Path) -> None:
        """Read component images from a snapshot."""
        snapshot = _make_snapshot(tmp_path, [IMAGE])
        assert snapshot_component_images(snapshot) == [IMAGE]

    def test_no_components_fails_closed(self, tmp_path: Path) -> None:
        """Fail closed when the snapshot has no components."""
        snapshot = tmp_path / "empty.json"
        snapshot.write_text(json.dumps({"components": []}))
        with pytest.raises(Exception, match="No component containerImage"):
            snapshot_component_images(snapshot)

    def test_missing_file_fails_closed(self, tmp_path: Path) -> None:
        """Fail closed when the snapshot file is missing."""
        with pytest.raises(Exception, match="Failed to parse snapshot"):
            snapshot_component_images(tmp_path / "nope.json")

    def test_bad_json_fails_closed(self, tmp_path: Path) -> None:
        """Fail closed when the snapshot is not valid JSON."""
        snapshot = tmp_path / "bad.json"
        snapshot.write_text("{not json")
        with pytest.raises(Exception, match="Failed to parse snapshot"):
            snapshot_component_images(snapshot)
