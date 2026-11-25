"""Tests for reading npm package metadata from tarballs."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import click
import pytest

from slan_cuan.javascript.metadata import (
    assert_tar_member_size,
    read_package_metadata,
)


@pytest.fixture
def simple_tgz(tmp_path: Path) -> Path:
    """Create a minimal npm package tarball with package/package.json."""
    tgz_path = tmp_path / "simple.tgz"
    package_json_content = json.dumps(
        {"name": "test-package", "version": "1.0.0"}
    ).encode()

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json_content)
        tar.addfile(info, io.BytesIO(package_json_content))

    return tgz_path


@pytest.fixture
def scoped_package_tgz(tmp_path: Path) -> Path:
    """Create a npm package tarball with scoped package name."""
    tgz_path = tmp_path / "scoped.tgz"
    package_json_content = json.dumps(
        {"name": "@scope/test-package", "version": "2.0.0"}
    ).encode()

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json_content)
        tar.addfile(info, io.BytesIO(package_json_content))

    return tgz_path


@pytest.fixture
def oversized_tgz(tmp_path: Path) -> Path:
    """Create a tgz with package.json larger than typical limits."""
    tgz_path = tmp_path / "oversized.tgz"
    large_content = b"x" * 2_000_000  # 2MB, well over 1MB default limit

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(large_content)
        tar.addfile(info, io.BytesIO(large_content))

    return tgz_path


@pytest.fixture
def empty_member_tgz(tmp_path: Path) -> Path:
    """Create a tgz with an empty package.json."""
    tgz_path = tmp_path / "empty.tgz"

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = 0
        tar.addfile(info, io.BytesIO(b""))

    return tgz_path


@pytest.fixture
def missing_member_tgz(tmp_path: Path) -> Path:
    """Create a tgz without package/package.json."""
    tgz_path = tmp_path / "missing.tgz"

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/other-file.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))

    return tgz_path


@pytest.fixture
def malformed_json_tgz(tmp_path: Path) -> Path:
    """Create a tgz with malformed JSON in package.json."""
    tgz_path = tmp_path / "malformed.tgz"
    bad_json = b'{"name": "test", "version": "1.0.0"'  # Missing closing brace

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(bad_json)
        tar.addfile(info, io.BytesIO(bad_json))

    return tgz_path


@pytest.fixture
def missing_name_tgz(tmp_path: Path) -> Path:
    """Create a tgz with valid JSON but missing 'name' field."""
    tgz_path = tmp_path / "missing_name.tgz"
    package_json_content = json.dumps({"version": "1.0.0"}).encode()

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json_content)
        tar.addfile(info, io.BytesIO(package_json_content))

    return tgz_path


@pytest.fixture
def missing_version_tgz(tmp_path: Path) -> Path:
    """Create a tgz with valid JSON but missing 'version' field."""
    tgz_path = tmp_path / "missing_version.tgz"
    package_json_content = json.dumps({"name": "test-package"}).encode()

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json_content)
        tar.addfile(info, io.BytesIO(package_json_content))

    return tgz_path


@pytest.fixture
def empty_name_tgz(tmp_path: Path) -> Path:
    """Create a tgz with 'name' field that is empty string."""
    tgz_path = tmp_path / "empty_name.tgz"
    package_json_content = json.dumps({"name": "", "version": "1.0.0"}).encode()

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json_content)
        tar.addfile(info, io.BytesIO(package_json_content))

    return tgz_path


@pytest.fixture
def empty_version_tgz(tmp_path: Path) -> Path:
    """Create a tgz with 'version' field that is empty string."""
    tgz_path = tmp_path / "empty_version.tgz"
    package_json_content = json.dumps(
        {"name": "test-package", "version": ""}
    ).encode()

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json_content)
        tar.addfile(info, io.BytesIO(package_json_content))

    return tgz_path


@pytest.fixture
def not_a_gzip_tgz(tmp_path: Path) -> Path:
    """Create a file with a .tgz extension that isn't gzip at all."""
    tgz_path = tmp_path / "not_a_gzip.tgz"
    tgz_path.write_bytes(b"this is definitely not a tarball" * 5)
    return tgz_path


@pytest.fixture
def truncated_tgz(tmp_path: Path) -> Path:
    """Create a valid tgz, then truncate it to simulate a partial download."""
    tgz_path = tmp_path / "truncated.tgz"
    package_json_content = json.dumps(
        {"name": "test-package", "version": "1.0.0"}
    ).encode()

    with tarfile.open(tgz_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(package_json_content)
        tar.addfile(info, io.BytesIO(package_json_content))

    data = tgz_path.read_bytes()
    tgz_path.write_bytes(data[: len(data) // 2])
    return tgz_path


class TestAssertTarMemberSize:
    """Tests for the assert_tar_member_size function."""

    def test_passes_for_small_member(self, simple_tgz: Path) -> None:
        """Should not raise for a small member within limits."""
        assert_tar_member_size(simple_tgz, "package/package.json", 1_000_000)

    def test_raises_for_missing_member(self, missing_member_tgz: Path) -> None:
        """Should raise ClickException for missing member."""
        with pytest.raises(click.ClickException):
            assert_tar_member_size(
                missing_member_tgz, "package/package.json", 1_000_000
            )

    def test_raises_for_empty_member(self, empty_member_tgz: Path) -> None:
        """Should raise ClickException for empty member."""
        with pytest.raises(click.ClickException):
            assert_tar_member_size(
                empty_member_tgz, "package/package.json", 1_000_000
            )

    def test_raises_for_oversized_member(self, oversized_tgz: Path) -> None:
        """Should raise ClickException when member exceeds max_bytes."""
        with pytest.raises(click.ClickException):
            assert_tar_member_size(oversized_tgz, "package/package.json", 100)

    def test_raises_for_non_gzip_archive(self, not_a_gzip_tgz: Path) -> None:
        """Should raise ClickException for a non-gzip/tar file."""
        with pytest.raises(click.ClickException):
            assert_tar_member_size(
                not_a_gzip_tgz, "package/package.json", 1_000_000
            )

    def test_raises_for_truncated_archive(self, truncated_tgz: Path) -> None:
        """Should raise ClickException for a truncated archive."""
        with pytest.raises(click.ClickException):
            assert_tar_member_size(
                truncated_tgz, "package/package.json", 1_000_000
            )


class TestReadPackageMetadata:
    """Tests for the read_package_metadata function."""

    def test_returns_name_and_version(self, simple_tgz: Path) -> None:
        """Should return (name, version) tuple from package.json."""
        name, version = read_package_metadata(simple_tgz)
        assert name == "test-package"
        assert version == "1.0.0"

    def test_handles_scoped_package_name(self, scoped_package_tgz: Path) -> None:
        """Should preserve scoped package names like @scope/pkg."""
        name, version = read_package_metadata(scoped_package_tgz)
        assert name == "@scope/test-package"
        assert version == "2.0.0"

    def test_raises_on_missing_package_json(
        self, missing_member_tgz: Path
    ) -> None:
        """Should raise ClickException when package.json is missing."""
        with pytest.raises(click.ClickException):
            read_package_metadata(missing_member_tgz)

    def test_raises_on_malformed_json(self, malformed_json_tgz: Path) -> None:
        """Should raise ClickException for invalid JSON."""
        with pytest.raises(click.ClickException):
            read_package_metadata(malformed_json_tgz)

    def test_raises_on_missing_name(self, missing_name_tgz: Path) -> None:
        """Should raise ClickException when 'name' field is missing."""
        with pytest.raises(click.ClickException):
            read_package_metadata(missing_name_tgz)

    def test_raises_on_missing_version(self, missing_version_tgz: Path) -> None:
        """Should raise ClickException when 'version' field is missing."""
        with pytest.raises(click.ClickException):
            read_package_metadata(missing_version_tgz)

    def test_raises_on_empty_name(self, empty_name_tgz: Path) -> None:
        """Should raise ClickException when 'name' field is empty string."""
        with pytest.raises(click.ClickException):
            read_package_metadata(empty_name_tgz)

    def test_raises_on_empty_version(self, empty_version_tgz: Path) -> None:
        """Should raise ClickException when 'version' field is empty."""
        with pytest.raises(click.ClickException):
            read_package_metadata(empty_version_tgz)

    def test_respects_max_package_json_bytes(self, oversized_tgz: Path) -> None:
        """Should respect the max_package_json_bytes parameter."""
        with pytest.raises(click.ClickException):
            read_package_metadata(oversized_tgz, max_package_json_bytes=100)

    def test_raises_on_non_gzip_archive(self, not_a_gzip_tgz: Path) -> None:
        """Should raise ClickException for a non-gzip/tar file."""
        with pytest.raises(click.ClickException):
            read_package_metadata(not_a_gzip_tgz)

    def test_raises_on_truncated_archive(self, truncated_tgz: Path) -> None:
        """Should raise ClickException for a truncated archive."""
        with pytest.raises(click.ClickException):
            read_package_metadata(truncated_tgz)
