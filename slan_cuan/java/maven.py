"""Maven repository processing, signature handling, and metadata generation."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import defusedxml.ElementTree as ET

from slan_cuan.utils import (
    compute_checksum,
    extract_zip_safely,
    write_checksum_sidecars,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_SIGN_IGNORES",
    "STANDARD_GENERATED_IGNORES",
    "VersionCompareKey",
    "apply_signatures",
    "compute_checksum",
    "ensure_artifact_checksums",
    "extract_repository",
    "format_maven_metadata",
    "generate_maven_metadata",
    "is_ignored",
    "parse_pom_xml",
    "sign_individual_artifacts",
    "write_checksum_sidecars",
]

DEFAULT_SIGN_IGNORES: tuple[str, ...] = (
    r".*\.md5$",
    r".*\.sha1$",
    r".*\.sha256$",
    r".*\.sha512$",
    r".*\.asc$",
)

STANDARD_GENERATED_IGNORES: tuple[str, ...] = (
    "maven-metadata.xml",
    "archetype-catalog.xml",
)


class VersionCompareKey:
    """Key function for sorting Maven version strings."""

    def __init__(self, version: str) -> None:
        """Initialize with a version string."""
        self.version = version

    def __lt__(self, other: VersionCompareKey) -> bool:
        """Check less than."""
        return self._compare(other) < 0

    def __gt__(self, other: VersionCompareKey) -> bool:
        """Check greater than."""
        return self._compare(other) > 0

    def __le__(self, other: VersionCompareKey) -> bool:
        """Check less than or equal."""
        return self._compare(other) <= 0

    def __ge__(self, other: VersionCompareKey) -> bool:
        """Check greater than or equal."""
        return self._compare(other) >= 0

    def __eq__(self, other: object) -> bool:
        """Check equality (consistent with the ordering in _compare)."""
        if not isinstance(other, VersionCompareKey):
            return NotImplemented
        return self._normalized_key() == other._normalized_key()

    def __hash__(self) -> int:
        """Return a hash consistent with __eq__.

        Two versions that _compare treats as equal (e.g. ``1.0`` and
        ``1.00``) must hash identically, otherwise ``set()``/``dict`` would
        keep them as distinct entries and produce duplicate ``<version>``
        elements in maven-metadata.xml.
        """
        return hash(self._normalized_key())

    def _normalized_key(self) -> tuple[tuple[int, object], ...]:
        """Canonical key whose equality mirrors ``_compare() == 0``.

        Each version segment becomes ``(1, int_value)`` when numeric or
        ``(0, text)`` otherwise. Numeric segments compare by integer value so
        leading-zero variants collapse; the leading tag keeps numeric and
        string segments from ever comparing equal, matching _compare's rule
        that a numeric segment never equals a non-numeric one.
        """
        items = self.version.split(".")
        if items and "-" in items[-1]:
            items = items[:-1] + items[-1].split("-")
        key: list[tuple[int, object]] = []
        for item in items:
            if item.isnumeric():
                key.append((1, int(item)))
            else:
                key.append((0, item))
        return tuple(key)

    def _compare(self, other: VersionCompareKey) -> int:
        xitems = self.version.split(".")
        if "-" in xitems[-1]:
            xitems = xitems[:-1] + xitems[-1].split("-")
        yitems = other.version.split(".")
        if "-" in yitems[-1]:
            yitems = yitems[:-1] + yitems[-1].split("-")
        big = max(len(xitems), len(yitems))
        for i in range(big):
            try:
                xitem: str | int = xitems[i]
            except IndexError:
                return -1
            try:
                yitem: str | int = yitems[i]
            except IndexError:
                return 1
            if xitem.isnumeric() and yitem.isnumeric():
                xitem = int(xitem)
                yitem = int(yitem)
            elif xitem.isnumeric() and not yitem.isnumeric():
                return 1
            elif yitem.isnumeric() and not xitem.isnumeric():
                return -1
            if isinstance(xitem, int) and isinstance(yitem, int):
                if xitem > yitem:
                    return 1
                if xitem < yitem:
                    return -1
            elif isinstance(xitem, str) and isinstance(yitem, str):
                if xitem > yitem:
                    return 1
                if xitem < yitem:
                    return -1
        return 0


def is_ignored(
    filename: str, ignore_patterns: tuple[str, ...] | list[str] = ()
) -> bool:
    """Check if filename matches standard or custom ignore patterns."""
    for standard in STANDARD_GENERATED_IGNORES:
        if filename == standard or filename.startswith(f"{standard}."):
            return True
    for pattern in DEFAULT_SIGN_IGNORES:
        if re.match(pattern, filename):
            return True
    for pattern in ignore_patterns:
        if pattern and re.match(pattern, filename):
            return True
    return False


def extract_repository(
    repo_path: str | Path,
    dest_dir: Path,
    zip_root_path: str = "repository",
) -> Path:
    """Extract a repo zip (with zip-slip safety) or copy directory to dest_dir.

    Returns the top_level directory corresponding to zip_root_path or dest_dir.
    """
    repo = Path(repo_path)
    if not repo.exists():
        raise FileNotFoundError(f"Repository source does not exist: {repo}")

    if repo.is_dir():
        shutil.copytree(repo, dest_dir, dirs_exist_ok=True)
    elif zipfile.is_zipfile(repo):
        extract_zip_safely(repo, dest_dir)
    else:
        raise ValueError(
            f"Repository path is neither a directory nor a zip file: {repo}"
        )

    # Locate top_level (the directory corresponding to zip_root_path)
    candidate = dest_dir / zip_root_path
    if candidate.is_dir():
        return candidate

    for root_dir, dirs, _ in os.walk(dest_dir):
        if zip_root_path in dirs:
            found = Path(root_dir) / zip_root_path
            if found.is_dir():
                return found

    return dest_dir


def apply_signatures(
    top_level: Path,
    sign_result_file: str | Path,
    zip_root_path: str = "repository",
) -> list[Path]:
    """Read signed JSON results and write .asc files next to each artifact.

    Returns a list of generated .asc signature file Paths.
    """
    sign_file = Path(sign_result_file)
    if not sign_file.is_file():
        raise FileNotFoundError(f"Sign result file does not exist: {sign_file}")

    with open(sign_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        entries = data.get("results", [])
    elif isinstance(data, list):
        entries = data
    else:
        entries = []

    generated_asc: list[Path] = []

    resolved_top = top_level.resolve()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rel_file = entry.get("file", "")
        signature = entry.get("signature", "")
        if not rel_file or not signature:
            continue

        # Strip the zip root prefix, anchored to the start of the path. A
        # substring/containment check mis-splits entries whose GAV happens to
        # contain the root token (e.g. root "repository" inside
        # ".../repository-utils/..."), dropping the signature.
        normalized = rel_file.lstrip("/")
        root_prefix = zip_root_path.strip("/")
        if root_prefix and normalized.startswith(f"{root_prefix}/"):
            stripped = normalized[len(root_prefix) + 1 :]
        elif root_prefix and normalized == root_prefix:
            stripped = ""
        else:
            stripped = normalized

        target = (top_level / stripped).resolve()
        if not (target == resolved_top or target.is_relative_to(resolved_top)):
            logger.warning("Path traversal attempt in sign results: %s", rel_file)
            continue

        if not target.is_file():
            # Try raw relative path
            raw_target = (top_level / rel_file.lstrip("/")).resolve()
            if raw_target.is_relative_to(resolved_top) and raw_target.is_file():
                target = raw_target
            else:
                # Search by filename within top_level. Only accept an
                # unambiguous single match: two artifacts can share a basename
                # across different GAVs, and signing an arbitrary matches[0]
                # would write the .asc next to the wrong artifact.
                basename = Path(stripped).name
                matches = list(top_level.rglob(basename))
                if len(matches) == 1:
                    candidate = matches[0].resolve()
                    if not (
                        candidate == resolved_top
                        or candidate.is_relative_to(resolved_top)
                    ):
                        continue
                    target = candidate
                elif len(matches) > 1:
                    logger.warning(
                        "Ambiguous basename %s (%d matches) in %s, "
                        "skipping signature to avoid mis-signing",
                        basename,
                        len(matches),
                        top_level,
                    )
                    continue
                else:
                    logger.warning(
                        "Artifact %s not found in %s, skipping signature",
                        stripped,
                        top_level,
                    )
                    continue

        asc_path = target.with_name(f"{target.name}.asc")
        asc_path.parent.mkdir(parents=True, exist_ok=True)
        asc_path.write_text(signature, encoding="utf-8")
        generated_asc.append(asc_path)

    if not generated_asc:
        raise RuntimeError(
            "No signature files were generated from sign result file"
        )

    return generated_asc


def parse_pom_xml(pom_path: Path) -> tuple[str, str, str] | None:
    """Parse groupId, artifactId, and version from a POM XML file."""
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        def find_text(elem: ET.Element, tag: str) -> str | None:
            child = elem.find(f"{ns}{tag}")
            return (
                child.text.strip() if child is not None and child.text else None
            )

        group_id = find_text(root, "groupId")
        artifact_id = find_text(root, "artifactId")
        version = find_text(root, "version")

        # Fall back to <parent> for groupId / version if missing
        parent = root.find(f"{ns}parent")
        if parent is not None:
            if not group_id:
                group_id = find_text(parent, "groupId")
            if not version:
                version = find_text(parent, "version")

        if group_id and artifact_id and version:
            return group_id, artifact_id, version
    except Exception as e:
        logger.debug("Failed to parse POM XML %s: %s", pom_path, e)
    return None


def format_maven_metadata(
    group_id: str,
    artifact_id: str,
    versions: list[str] | set[str],
    last_updated: str | None = None,
) -> str:
    """Format maven-metadata.xml content string."""
    if last_updated is None:
        last_updated = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    # Dedup on the comparison form (not the raw string) so comparator-equal
    # variants like "1.0"/"1.00" collapse to a single <version> entry.
    unique_versions = {VersionCompareKey(v): v for v in versions}
    sorted_versions = [unique_versions[k] for k in sorted(unique_versions)]
    latest_version = sorted_versions[-1]
    non_snapshot = [v for v in sorted_versions if not v.endswith("-SNAPSHOT")]
    release_version = non_snapshot[-1] if non_snapshot else latest_version

    versions_xml = "\n".join(
        f"      <version>{v}</version>" for v in sorted_versions
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<metadata>\n"
        f"  <groupId>{group_id}</groupId>\n"
        f"  <artifactId>{artifact_id}</artifactId>\n"
        "  <versioning>\n"
        f"    <latest>{latest_version}</latest>\n"
        f"    <release>{release_version}</release>\n"
        "    <versions>\n"
        f"{versions_xml}\n"
        "    </versions>\n"
        f"    <lastUpdated>{last_updated}</lastUpdated>\n"
        "  </versioning>\n"
        "</metadata>\n"
    )


def _merge_existing_metadata_versions(
    meta_path: Path,
    top_level: Path,
    gav_map: dict[str, dict[str, set[str]]],
) -> None:
    try:
        tree = ET.parse(meta_path)
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        group_id = root.findtext(f"{ns}groupId") or root.findtext("groupId")
        artifact_id = root.findtext(f"{ns}artifactId") or root.findtext(
            "artifactId"
        )
        if not group_id or not artifact_id:
            rel_parts = meta_path.parent.relative_to(top_level).parts
            if len(rel_parts) >= 2:
                artifact_id = rel_parts[-1]
                group_id = ".".join(rel_parts[:-1])
        if group_id and artifact_id:
            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag == "version" and elem.text and elem.text.strip():
                    gav_map.setdefault(group_id, {}).setdefault(
                        artifact_id, set()
                    ).add(elem.text.strip())
    except Exception as e:
        logger.warning("Could not parse existing metadata %s: %s", meta_path, e)


def generate_maven_metadata(
    top_level: Path,
    ignore_patterns: tuple[str, ...] | list[str] = (),
) -> list[Path]:
    """Scan POM files, determine GAVs, generate maven-metadata.xml and checksums.

    Returns a list of all created metadata and checksum file paths.
    """
    pom_files: list[Path] = []
    for root_dir, _, files in os.walk(top_level):
        for f in files:
            if f.endswith(".pom"):
                if not is_ignored(f, ignore_patterns):
                    pom_files.append(Path(root_dir) / f)

    gav_map: dict[str, dict[str, set[str]]] = {}

    for pom in pom_files:
        rel_parts = pom.relative_to(top_level).parts
        if len(rel_parts) >= 4:
            version = rel_parts[-2]
            artifact_id = rel_parts[-3]
            group_id = ".".join(rel_parts[:-3])
        else:
            parsed = parse_pom_xml(pom)
            if not parsed:
                continue
            group_id, artifact_id, version = parsed

        gav_map.setdefault(group_id, {}).setdefault(artifact_id, set()).add(
            version
        )

    for root_dir, _, files in os.walk(top_level):
        if "maven-metadata.xml" in files:
            meta_path = Path(root_dir) / "maven-metadata.xml"
            _merge_existing_metadata_versions(meta_path, top_level, gav_map)

    created_files: list[Path] = []
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    for group_id, artifacts in gav_map.items():
        for artifact_id, versions in artifacts.items():
            if not versions:
                continue
            ga_dir = top_level.joinpath(*group_id.split(".")).joinpath(
                artifact_id
            )
            ga_dir.mkdir(parents=True, exist_ok=True)
            meta_file = ga_dir / "maven-metadata.xml"
            xml_content = format_maven_metadata(
                group_id, artifact_id, versions, timestamp
            )
            meta_file.write_text(xml_content, encoding="utf-8")
            created_files.append(meta_file)

            checksum_files = write_checksum_sidecars(meta_file)
            created_files.extend(checksum_files)

    return created_files


def ensure_artifact_checksums(
    top_level: Path,
    ignore_patterns: tuple[str, ...] | list[str] = (),
) -> list[Path]:
    """Ensure all artifacts have .md5, .sha1, .sha256, .sha512 sidecars.

    Excludes sidecar files, signatures, and metadata files.
    Returns list of created/updated checksum paths.
    """
    created: list[Path] = []
    for root_dir, _, files in os.walk(top_level):
        for f in files:
            file_path = Path(root_dir) / f
            if f.endswith((".md5", ".sha1", ".sha256", ".sha512", ".asc")):
                continue
            if f in STANDARD_GENERATED_IGNORES or f.endswith(".txt"):
                continue
            if is_ignored(f, ignore_patterns):
                continue

            created.extend(write_checksum_sidecars(file_path))
    return created


def sign_individual_artifacts(
    repo_path: str | Path | list[str | Path],
    sign_result_file: str | Path,
    destination_dir: str | Path,
    root_path: str = "repository",
    product_key: str = "slan-cuan",
    ignore_patterns: tuple[str, ...] | list[str] = (),
    temp_dir: str | Path | None = None,
) -> None:
    """Native replacement for novabucks sign_individual_artifacts_workflow.

    Unpacks repository, applies .asc signatures from direct signing JSON,
    generates/refreshes maven-metadata.xml, creates .md5, .sha1, .sha256,
    .sha512 checksums for metadata and artifacts, and copies everything to
    destination_dir.
    """
    work_ctx: tempfile.TemporaryDirectory[str] | None = None
    if temp_dir is None:
        work_ctx = tempfile.TemporaryDirectory(prefix="slan-cuan-mvn-")
        work_dir = Path(work_ctx.name)
    else:
        work_dir = Path(temp_dir)

    try:
        extract_dest = work_dir / "extracted"
        extract_dest.mkdir(parents=True, exist_ok=True)

        repos = (
            [repo_path] if isinstance(repo_path, (str, Path)) else list(repo_path)
        )
        top_level = extract_dest
        for r in repos:
            top_level = extract_repository(
                r, extract_dest, zip_root_path=root_path
            )

        apply_signatures(top_level, sign_result_file, zip_root_path=root_path)

        generate_maven_metadata(top_level, ignore_patterns=ignore_patterns)

        archetype_catalog = top_level / "archetype-catalog.xml"
        if archetype_catalog.is_file():
            write_checksum_sidecars(archetype_catalog)

        ensure_artifact_checksums(top_level, ignore_patterns=ignore_patterns)

        # Write manifest file
        valid_artifacts: list[str] = []
        for root_dir, _, files in os.walk(top_level):
            for f in sorted(files):
                if not f.endswith(
                    (".md5", ".sha1", ".sha256", ".sha512", ".asc")
                ):
                    if f not in STANDARD_GENERATED_IGNORES and not is_ignored(
                        f, ignore_patterns
                    ):
                        file_p = Path(root_dir) / f
                        valid_artifacts.append(str(file_p.relative_to(top_level)))
        manifest_path = top_level / f"{product_key}.txt"
        manifest_content = "\n".join(valid_artifacts) + "\n"
        manifest_path.write_text(manifest_content, encoding="utf-8")

        dest = Path(destination_dir)
        dest.mkdir(parents=True, exist_ok=True)
        for root_dir, _, files in os.walk(top_level):
            for f in files:
                src_file = Path(root_dir) / f
                rel_path = src_file.relative_to(top_level)
                target_file = dest / rel_path
                if src_file.resolve() != target_file.resolve():
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, target_file)

    finally:
        if work_ctx is not None:
            work_ctx.cleanup()
