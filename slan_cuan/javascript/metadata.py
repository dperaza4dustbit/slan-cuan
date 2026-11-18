"""npm package metadata reader.

Reads name and version from package/package.json inside an npm .tgz
tarball, with size guards to avoid buffering maliciously large files.
Replaces duplicated bash patterns from npm-pulp-upload and
npm-attestation-publish.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import click


def assert_tar_member_size(archive: Path, member: str, max_bytes: int) -> None:
    """Verify a tar member exists, is non-empty, and doesn't exceed size.

    Raises click.ClickException if the member is missing, empty, or
    exceeds max_bytes. Reads at most max_bytes + 1 bytes from the
    extracted member to decide oversized without buffering the whole file.

    Args:
        archive: Path to the .tgz tarball.
        member: Name of the member within the archive.
        max_bytes: Maximum allowed size in bytes.

    Raises:
        click.ClickException: If the member is missing, empty, or too large.

    """
    try:
        with tarfile.open(archive, "r:gz") as tar:
            tar_member = tar.getmember(member)
            # Member exists; check if it's empty.
            if tar_member.size == 0:
                raise click.ClickException(f"Member '{member}' is empty")
            # Decide oversized by reading at most max_bytes + 1 bytes.
            f = tar.extractfile(member)
            if f is None:
                raise click.ClickException(
                    f"Cannot extract member '{member}' from archive"
                ) from None
            content = f.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise click.ClickException(
                    f"Member '{member}' exceeds {max_bytes} bytes"
                )
    except KeyError as e:
        raise click.ClickException(
            f"Member '{member}' not found in archive {archive}"
        ) from e


def read_package_metadata(
    tgz_path: Path, *, max_package_json_bytes: int = 1_048_576
) -> tuple[str, str]:
    """Read name and version from package/package.json in a .tgz.

    Args:
        tgz_path: Path to the npm .tgz tarball.
        max_package_json_bytes: Maximum size of package.json (default 1 MB).

    Returns:
        Tuple of (name, version) strings.

    Raises:
        click.ClickException: If the tarball lacks package.json, the JSON
            is malformed, or required fields (name, version) are missing
            or empty.

    """
    # Open tarball once: check size, extract, and parse JSON in one pass.
    try:
        with tarfile.open(tgz_path, "r:gz") as tar:
            tar_member = tar.getmember("package/package.json")
            # Check if the member is empty.
            if tar_member.size == 0:
                raise click.ClickException(
                    "Member 'package/package.json' is empty"
                )
            # Extract member; decide oversized by reading bounded amount.
            f = tar.extractfile("package/package.json")
            if f is None:
                raise click.ClickException(
                    "Cannot extract package/package.json from archive"
                ) from None
            content_bytes = f.read(max_package_json_bytes + 1)
            if len(content_bytes) > max_package_json_bytes:
                raise click.ClickException(
                    f"Member 'package/package.json' exceeds "
                    f"{max_package_json_bytes} bytes"
                )
            # Parse the JSON.
            try:
                content = json.loads(content_bytes)
            except json.JSONDecodeError as e:
                raise click.ClickException(
                    f"Invalid JSON in package.json: {e}"
                ) from e
    except KeyError as e:
        raise click.ClickException(
            f"Member 'package/package.json' not found in archive {tgz_path}"
        ) from e

    # Validate required fields.
    name = content.get("name")
    version = content.get("version")

    if not name:
        raise click.ClickException(
            "package.json is missing or empty 'name' field"
        )

    if not version:
        raise click.ClickException(
            "package.json is missing or empty 'version' field"
        )

    return name, version
