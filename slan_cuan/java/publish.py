"""Publish subcommand for uploading Maven artifacts to Pulp."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from slan_cuan.http import parse_custom_headers
from slan_cuan.java.github_osv import GitHubOsvClient, GitHubOsvError
from slan_cuan.models import (
    EXTRACT_RESULT_FILENAME,
    PUBLISH_RESULT_FILENAME,
    BuildOutput,
    ExtractResult,
    GlobalContext,
    MavenArtifact,
    PublishResult,
)
from slan_cuan.pulp import (
    TASK_POLL_TIMEOUT_SECONDS,
    ContentUnit,
    PulpConfig,
    PulpError,
    PulpFileClient,
    PulpMavenClient,
)
from slan_cuan.utils import safe_json_load, write_tekton_result

_DEFAULT_SUPPLIER = {"name": "Red Hat Lightwell"}
_OSV_ID_PREFIX = "x_RHLW-"
_DIAG_MAX_ENTRIES = 50
_ERROR_RESPONSE_MAX = 500
DEFAULT_UPLOAD_WORKERS = 4
GAV_INDEX_FILENAME = "gav-index.json"
MAVEN_PREDISCLOSURE_BASE_PATH = "java/predisclosure"
# A File (OSV/VEX) distribution is a predisclosure destination when its
# base path has this segment (e.g. ``osv/java/predisclosure``).
FILE_PREDISCLOSURE_PATH_SEGMENT = "predisclosure"


def _load_upstream_sbom(
    repo_dir: Path,
    group_id: str,
    artifact_id: str,
    version: str,
) -> tuple[dict | None, Path | None]:
    """Load the upstream SBOM from the repository directory.

    Searches for ``.bom.json`` (new PNC convention) then
    ``.cyclonedx.json`` (legacy). Returns ``(parsed_dict, source_path)``
    or ``(None, None)`` when no upstream SBOM is found.
    """
    gav_dir = repo_dir / group_id.replace(".", "/") / artifact_id / version
    for suffix in (".bom.json", ".cyclonedx.json"):
        candidate = gav_dir / f"{artifact_id}-{version}{suffix}"
        if not candidate.exists():
            continue
        try:
            with open(candidate) as f:
                return json.load(f), candidate
        except (json.JSONDecodeError, OSError):
            continue
    return None, None


def _verify_gav_index_attachment(attachment_files: list[str]) -> None:
    """Verify the GAV index attachment list is present and valid."""
    if not isinstance(attachment_files, list) or not all(
        isinstance(relative_path, str) for relative_path in attachment_files
    ):
        raise ValueError("Unable to verify the required GAV index attachment.")


def _resolve_gav_index_attachment(
    relative_path: str, artifact_dir: Path, artifact_root: Path
) -> Path:
    """Resolve the GAV index attachment to a file path."""
    candidate = artifact_dir / relative_path
    try:
        candidate.resolve().relative_to(artifact_root)
    except ValueError:
        raise ValueError(
            "Unable to verify the required GAV index attachment."
        ) from None
    return candidate


def _validate_parse_gav_index_data(data: dict[str, Any]) -> tuple[str, ...]:
    """Validate the GAV index data is present and valid."""
    if not isinstance(data, dict) or not isinstance(data.get("vulns"), list):
        raise ValueError("The required GAV index has invalid vulnerability data.")
    if any(
        not isinstance(vuln, str) or not vuln.strip() for vuln in data["vulns"]
    ):
        raise ValueError("The required GAV index has invalid vulnerability data.")
    return tuple(data["vulns"])


def _gav_index_vulnerabilities(
    attachment_files: list[str], artifact_dir: Path
) -> tuple[str, ...]:
    """Load and validate the GAV index from its declared attachment.

    The GAV index is release security input.  Consequently, uncertainty about
    its presence or contents is an error rather than evidence of a clean
    release.  Only an attachment is accepted: an identically named Maven file
    must not be mistaken for the build index.
    """
    _verify_gav_index_attachment(attachment_files)
    index_paths: list[Path] = []
    artifact_root = artifact_dir.resolve()
    for relative_path in attachment_files:
        candidate = _resolve_gav_index_attachment(
            relative_path, artifact_dir, artifact_root
        )
        if candidate.name == GAV_INDEX_FILENAME:
            index_paths.append(candidate)

    if len(index_paths) != 1 or not index_paths[0].is_file():
        raise ValueError("Unable to verify the required GAV index attachment.")

    data = safe_json_load(
        index_paths[0], parse_err_msg="Unable to parse the required GAV index."
    )
    return _validate_parse_gav_index_data(data)


def _validate_load_json_security_metadata(path: Path) -> dict[str, Any]:
    """Validate and load the JSON security metadata from the given file path.

    Accepts OSV (.json) and VEX (.bom.json) files. CycloneDX SBOMs are not
    security metadata: they are injected next to the artifact in the Maven
    repository and are rejected by ``_validate_security_metadata``.
    """
    if path.suffix != ".json":
        raise ValueError("Generated security metadata is not OSV or VEX JSON.")
    return safe_json_load(
        path,
        parse_err_msg="Generated security metadata is malformed.",
        expected_type=dict,
        type_err_msg="Generated security metadata is not OSV or VEX JSON.",
    )


def _validate_security_metadata(
    security_metadata_files: tuple[Path, ...], vulns: tuple[str, ...]
) -> None:
    """Validate generated OSV/VEX metadata and its GAV-index relationship.

    Only OSV records and VEX documents are publishable security metadata.
    Any other CycloneDX document (an SBOM, or an SBOM carrying
    ``vulnerabilities``) fails validation instead of being routed to the
    OSV repository: SBOMs belong next to the artifact in the Maven
    repository (``enriched-sboms/`` is injected and excluded here).

    The OSV coverage check also applies to builds with ``LW-`` IDs: those
    builds produce OSV and VEX for the novel fix, published only to
    predisclosure distributions (see ``_verify_embargo_destinations``).
    """
    osv_vulnerability_ids: set[str] = set()
    for path in security_metadata_files:
        record = _validate_load_json_security_metadata(path)

        if record.get("bomFormat") == "CycloneDX":
            if not _record_is_vex(record):
                raise ValueError(
                    f"CycloneDX document {path.name} is not VEX "
                    f"(VEX needs a non-empty vulnerabilities[] and no "
                    f"components[]); only OSV records and CycloneDX VEX are "
                    f"published as security metadata."
                )
            osv_vulnerability_ids.update(
                vuln_id for vuln_id in _vex_vulnerability_ids(record) if vuln_id
            )
            continue

        osv_id = record.get("id")
        affected = record.get("affected")
        aliases = record.get("aliases") or []
        upstream = record.get("upstream") or []
        has_vuln_ids = (
            isinstance(aliases, list)
            and bool(aliases)
            and all(isinstance(a, str) and a.strip() for a in aliases)
        ) or (
            isinstance(upstream, list)
            and bool(upstream)
            and all(isinstance(u, str) and u.strip() for u in upstream)
        )
        is_osv = (
            isinstance(osv_id, str)
            and bool(osv_id.strip())
            and isinstance(affected, list)
            and bool(affected)
            and has_vuln_ids
        )
        is_vex = isinstance(record.get("statements"), list) and (
            "@context" in record or "document" in record
        )
        if not is_osv and not is_vex:
            raise ValueError(
                "Generated security metadata is not OSV or VEX JSON."
            )
        if is_osv:
            osv_vulnerability_ids.update((osv_id, *aliases, *upstream))

    if vulns and not osv_vulnerability_ids:
        raise ValueError("Vulnerable GAV index has no generated OSV metadata.")
    if not vulns and security_metadata_files:
        raise ValueError(
            "Generated security metadata does not match the clean GAV index."
        )

    uncovered = set(vulns) - osv_vulnerability_ids
    if uncovered:
        raise ValueError(
            "Generated OSV metadata does not cover all GAV index vulnerabilities."
        )


def _expected_source_for_repo(repo_name: str) -> str | None:
    """Infer the OSV record source a repo accepts from its name.

    Returns ``"pnc-build"`` for backport repos, ``"novel-pipeline"`` for novel
    repos, or ``None`` when the name matches neither (routing is then skipped
    and all records upload, preserving legacy behavior).

    NOTE: this inference is name-based by design (it keeps the single
    ``--pulp-file-repository`` interface with no new params/catalog/RPA
    changes). It therefore depends on the repo name carrying the
    ``backport``/``novel`` keyword. A future rename that drops the keyword
    would fall back to the unrecognized-repo path (upload-all + a warning),
    silently disabling filtering rather than erroring. This is safe for the
    current inventory (``osv-java-backport``/``osv-java-novel``); revisit if
    the naming scheme changes.
    """
    lowered = repo_name.lower()
    if "backport" in lowered:
        return "pnc-build"
    if "novel" in lowered:
        return "novel-pipeline"
    return None


def _source_from_osv_id(osv_id: str) -> str | None:
    """Classify an OSV id by its prefix.

    Two id formats coexist:

    * **Advisory** ``RHLW-{YYYY}-{16hex}`` — per-release advisory record.
      Routed to the backport repository (``pnc-build``).
    * **Per-CVE** ``x_RHLW-{vuln_id}-{base_ver}`` — legacy per-CVE record.
      ``CVE-`` vulnerabilities route to backport (``pnc-build``);
      ``LW-`` vulnerabilities route to novel (``novel-pipeline``).

    The ``x_RHLW-`` prefix is stripped before inspecting the vulnerability
    id so the ``LW`` inside ``RHLW`` is never mistaken for a novel record.
    """
    if osv_id.startswith("RHLW-"):
        return "pnc-build"
    if not osv_id.startswith(_OSV_ID_PREFIX):
        return None
    remainder = osv_id[len(_OSV_ID_PREFIX) :]
    if remainder.startswith("CVE-"):
        return "pnc-build"
    if remainder.startswith("LW-"):
        return "novel-pipeline"
    return None


def _classify_osv_source(
    file_path: Path, record: dict[str, Any] | None = None
) -> str | None:
    """Determine an OSV record's source: authoritative field, then id prefix.

    Returns ``"pnc-build"``, ``"novel-pipeline"``, or ``None`` when the record
    cannot be classified (malformed, non-OSV, or an unrecognized id).

    ``record`` is an already-parsed document. When it is omitted, the file
    is loaded.
    """
    if record is None:
        loaded = safe_json_load(file_path, raise_on_err=False)
        if not isinstance(loaded, dict):
            return None
        record = loaded

    database_specific = record.get("database_specific")
    lightwell = (
        database_specific.get("lightwell")
        if isinstance(database_specific, dict)
        else None
    )
    source = lightwell.get("source") if isinstance(lightwell, dict) else None
    if source in ("pnc-build", "novel-pipeline"):
        return source

    # Per-affected source (per-CVE path carries source there).
    for aff in record.get("affected", []):
        aff_db = aff.get("database_specific")
        aff_lw = aff_db.get("lightwell") if isinstance(aff_db, dict) else None
        aff_source = aff_lw.get("source") if isinstance(aff_lw, dict) else None
        if aff_source in ("pnc-build", "novel-pipeline"):
            return aff_source

    osv_id = record.get("id")
    if isinstance(osv_id, str) and osv_id:
        by_id = _source_from_osv_id(osv_id)
        if by_id is not None:
            return by_id

    return _source_from_osv_id(file_path.stem)


def _source_from_vuln_id(vuln_id: str) -> str | None:
    """Classify a raw vulnerability ID by prefix.

    Handles both OSV-format IDs (``RHLW-*``, ``x_RHLW-*``) and raw
    CVE/LW IDs found in CycloneDX documents.
    """
    osv_result = _source_from_osv_id(vuln_id)
    if osv_result is not None:
        return osv_result
    if vuln_id.startswith("CVE-"):
        return "pnc-build"
    if vuln_id.startswith("LW-"):
        return "novel-pipeline"
    return None


def _source_from_vuln_id_has_embargo(vulns: tuple[str, ...] | list[str]) -> bool:
    """Return True if any vulnerability ID indicates embargoed content."""
    return any(v.startswith("LW-") for v in vulns)


def _classify_cdx_source(record: dict[str, Any], file_path: Path) -> str | None:
    """Classify a CycloneDX SBOM or VEX by its vulnerability content.

    VEX: extracts vuln IDs from ``vulnerabilities[].id``.
    SBOM: extracts vuln IDs from ``pedigree.patches[].resolves[].id``.
    Classifies using ``_source_from_vuln_id`` (CVE- -> pnc-build,
    LW- -> novel-pipeline). Returns None when no IDs are found.
    """
    ids: list[str] = []

    for vuln in record.get("vulnerabilities", []):
        if isinstance(vuln, dict):
            vid = vuln.get("id", "")
            if vid:
                ids.append(vid)

    for comp in record.get("components", []):
        if not isinstance(comp, dict):
            continue
        pedigree = comp.get("pedigree", {})
        if not isinstance(pedigree, dict):
            continue
        for patch in pedigree.get("patches", []):
            if not isinstance(patch, dict):
                continue
            for resolve in patch.get("resolves", []):
                if isinstance(resolve, dict):
                    rid = resolve.get("id", "")
                    if rid:
                        ids.append(rid)

    if not ids:
        stem = file_path.stem
        if stem.endswith(".bom"):
            stem = stem[: -len(".bom")]
        by_stem = _source_from_vuln_id(stem)
        if by_stem:
            return by_stem
        return None

    sources = {_source_from_vuln_id(i) for i in ids} - {None}
    if len(sources) == 1:
        return sources.pop()
    if not sources:
        return None
    # Mixed sources — any novel-pipeline presence contaminates
    # the document (embargo rule: LW- takes precedence).
    if "novel-pipeline" in sources:
        return "novel-pipeline"
    return "pnc-build"


def _list_entries(path: Path, recursive: bool = False) -> None:
    """List directory contents for diagnostics, capped."""
    try:
        if recursive:
            entries = sorted(e for e in path.rglob("*") if e.is_file())
            for entry in entries[:_DIAG_MAX_ENTRIES]:
                click.echo(f"    {entry.relative_to(path)}")
        else:
            entries = sorted(path.iterdir())
            for entry in entries[:_DIAG_MAX_ENTRIES]:
                kind = "dir" if entry.is_dir() else "file"
                click.echo(f"    {entry.name} ({kind})")
        if len(entries) > _DIAG_MAX_ENTRIES:
            click.echo(f"    ... and {len(entries) - _DIAG_MAX_ENTRIES} more")
    except (PermissionError, OSError) as e:
        click.echo(f"    (error reading directory: {e})")


def _diagnose_empty_build(artifact_dir: Path, deliverable_dir: str) -> None:
    """Print diagnostics when no artifacts are discovered."""
    deliverable_path = artifact_dir / deliverable_dir
    repo_dir = deliverable_path / "repository"

    if not deliverable_path.exists():
        click.echo(
            f"  WARNING: deliverable path does not exist: {deliverable_path}"
        )
        click.echo(f"  Contents of {artifact_dir}:")
        _list_entries(artifact_dir)
        return

    if deliverable_path.is_file():
        click.echo(
            f"  WARNING: deliverable path is a file, not a directory: "
            f"{deliverable_path}"
        )
        return

    if not repo_dir.exists():
        click.echo(
            f"  WARNING: repository/ subdirectory not found in: "
            f"{deliverable_path}"
        )
        click.echo(f"  Contents of {deliverable_path}:")
        _list_entries(deliverable_path)
        return

    click.echo("  WARNING: repository/ exists but contains no Maven artifacts")
    click.echo(f"  Contents of {repo_dir}:")
    _list_entries(repo_dir, recursive=True)


def _validate_load_extract_result(
    ctx: GlobalContext, artifact_dir: Path
) -> ExtractResult:
    """Validate and load the extract result."""
    result_path = artifact_dir / EXTRACT_RESULT_FILENAME
    if ctx.verbose:
        click.echo(f"Inspecting result path: {result_path}")
    if not result_path.exists():
        raise click.ClickException(f"Extract result not found: {result_path}")

    extract_result = ExtractResult.from_file(result_path)
    if ctx.verbose:
        click.echo(f"Extract result file: {result_path}")
        click.echo(f"Artifact directory: {artifact_dir.resolve()}")
        click.echo(f"Deliverable directory: {extract_result.deliverable_dir}")
    return extract_result


def _verify_requires_file_repository(
    vulns: tuple[str, ...],
    security_metadata_files: tuple[Path, ...],
    pulp_file_repository: str | None,
) -> bool:
    """Require the OSV File repository for any vulnerable build.

    Builds with ``LW-`` IDs are not exempt: they produce OSV records too.
    """
    requires_file_repository = bool(vulns or security_metadata_files)
    if requires_file_repository and not pulp_file_repository:
        raise click.UsageError(
            "--pulp-file-repository is required for OSV publication."
        )
    return requires_file_repository


def _record_is_vex(record: dict[str, Any]) -> bool:
    """Return True for a CycloneDX VEX or OpenVEX document.

    A CycloneDX document is VEX only when ``vulnerabilities`` is a
    non-empty list and ``components`` is absent. An SBOM that carries
    ``"vulnerabilities": []`` stays on the OSV repository.
    """
    if record.get("bomFormat") == "CycloneDX":
        vulnerabilities = record.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            return False
        if "components" in record:
            return False
        return True
    return isinstance(record.get("statements"), list) and (
        "@context" in record or "document" in record
    )


def _is_legacy_osv_record(path: Path, record: dict[str, Any] | None) -> bool:
    """Return True for a legacy per-CVE ``x_RHLW-<vuln>-<base>`` OSV record."""
    osv_id = record.get("id") if isinstance(record, dict) else None
    if isinstance(osv_id, str) and osv_id:
        return osv_id.startswith(_OSV_ID_PREFIX)
    return path.stem.startswith(_OSV_ID_PREFIX)


def _drop_legacy_osv_records(
    osv_files: tuple[Path, ...],
    records: dict[Path, dict[str, Any]],
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Split off legacy per-CVE ``x_RHLW-`` records; they are never published.

    Only the per-release ``RHLW-`` advisory is published (LWLP-5093). The
    legacy records were removed from the Pulp OSV repositories and must not
    reach them, or the public GitHub OSV repository, again. Returns
    ``(kept, dropped)``.
    """
    kept: list[Path] = []
    dropped: list[Path] = []
    for path in osv_files:
        if _is_legacy_osv_record(path, records.get(path)):
            click.echo(
                f"Skipping legacy per-CVE OSV record {path.name}: only "
                f"per-release RHLW- advisories are published."
            )
            dropped.append(path)
        else:
            kept.append(path)
    return tuple(kept), tuple(dropped)


def _partition_security_metadata(
    security_metadata_files: tuple[Path, ...],
) -> tuple[tuple[Path, ...], tuple[Path, ...], dict[Path, dict[str, Any]]]:
    """Split security metadata into OSV records and VEX documents.

    OSV records publish to the OSV File repository and VEX documents to the
    VEX File repository. Other CycloneDX documents (SBOMs) never get here:
    ``_validate_security_metadata`` rejects them first.

    The returned mapping holds one parse of each JSON object so later
    routing does not read the file again.
    """
    records: dict[Path, dict[str, Any]] = {}
    osv_files: list[Path] = []
    vex_files: list[Path] = []
    for path in security_metadata_files:
        loaded = safe_json_load(path, raise_on_err=False)
        record = loaded if isinstance(loaded, dict) else None
        if record is not None:
            records[path] = record
        if record is not None and _record_is_vex(record):
            vex_files.append(path)
        else:
            osv_files.append(path)
    return tuple(osv_files), tuple(vex_files), records


def _record_vulnerability_ids(record: dict[str, Any] | None) -> list[str]:
    """Return every vulnerability ID a security-metadata record names.

    OSV: ``id``, ``aliases`` and ``upstream`` (the ``x_RHLW-`` prefix of a
    legacy per-CVE ID is stripped, so ``x_RHLW-LW-…`` yields ``LW-…``).
    VEX: ``vulnerabilities[].id``.
    """
    if not isinstance(record, dict):
        return []
    ids = _vex_vulnerability_ids(record)
    osv_id = record.get("id")
    if isinstance(osv_id, str):
        ids.append(osv_id.removeprefix(_OSV_ID_PREFIX))
    for key in ("aliases", "upstream"):
        values = record.get(key)
        if isinstance(values, list):
            ids.extend(v for v in values if isinstance(v, str))
    return ids


def _metadata_has_embargo(records: dict[Path, dict[str, Any]]) -> bool:
    """Return True when any security-metadata record names an ``LW-`` ID."""
    return any(
        _source_from_vuln_id_has_embargo(_record_vulnerability_ids(record))
        for record in records.values()
    )


def _vex_vulnerability_ids(record: dict[str, Any] | None) -> list[str]:
    """Return the vulnerability IDs named by a VEX document.

    CycloneDX VEX: ``vulnerabilities[].id``. OpenVEX (recognized by
    ``_record_is_vex`` via its ``statements[]`` shape): each statement's
    ``vulnerability.name``.
    """
    if not isinstance(record, dict):
        return []
    if isinstance(record.get("statements"), list):
        ids: list[str] = []
        for statement in record["statements"]:
            vulnerability = (
                statement.get("vulnerability")
                if isinstance(statement, dict)
                else None
            )
            name = (
                vulnerability.get("name")
                if isinstance(vulnerability, dict)
                else None
            )
            if isinstance(name, str):
                ids.append(name)
        return ids
    return [
        vuln["id"]
        for vuln in record.get("vulnerabilities") or []
        if isinstance(vuln, dict) and isinstance(vuln.get("id"), str)
    ]


def _verify_requires_vex_repository(
    vex_files: tuple[Path, ...],
    pulp_vex_repository: str | None,
    pulp_file_repository: str | None = None,
    records: dict[Path, dict[str, Any]] | None = None,
) -> bool:
    """Fail closed unless VEX has a dedicated, recognized, safe repository.

    Checked before anything is uploaded. When VEX documents are present the
    run aborts if the VEX repository is:

    * missing, or the same as the OSV File repository (VEX never falls back
      to the OSV repository);
    * not recognizable as a backport/novel repository by name (VEX would
      otherwise upload without source filtering).

    VEX naming an ``LW-`` ID makes the whole build embargoed
    (``_metadata_has_embargo``); its VEX repository is then verified against
    its Pulp distribution by ``_verify_embargo_destinations``.
    """
    if not vex_files:
        return False
    if not pulp_vex_repository:
        raise click.UsageError(
            f"--pulp-vex-repository is required to publish {len(vex_files)} "
            f"VEX document(s); VEX is never published to the OSV repository."
        )
    if pulp_file_repository and pulp_vex_repository == pulp_file_repository:
        raise click.UsageError(
            f"--pulp-vex-repository '{pulp_vex_repository}' must differ from "
            f"--pulp-file-repository; VEX is never published to the OSV "
            f"repository."
        )
    if _expected_source_for_repo(pulp_vex_repository) is None:
        raise click.UsageError(
            f"--pulp-vex-repository '{pulp_vex_repository}' is not recognized "
            f"as a backport or novel VEX repository (its name must contain "
            f"'backport' or 'novel'); refusing to upload VEX unfiltered."
        )
    return True


def _validate_file_predisclosure_distribution(
    config: PulpConfig, repository_name: str, option: str
) -> None:
    """Fail closed unless a File repository is served at a predisclosure path.

    The distribution is looked up by the repository name (the same name
    ``_publish_file_records`` publishes to) and its ``base_path`` must have a
    ``predisclosure`` segment, e.g. ``osv/java/predisclosure``. This checks
    where the content is actually served, not how the repository is named.
    """
    try:
        click.echo(f"Resolving {option} distribution: {repository_name}")
        with PulpFileClient(config, repository_name) as client:
            base_path = client.get_distribution_base_path(repository_name)
    except PulpError as e:
        raise click.ClickException(
            f"Unable to verify the predisclosure distribution of {option} "
            f"'{repository_name}' for an embargoed build."
        ) from e
    segments = (base_path or "").strip("/").split("/")
    if FILE_PREDISCLOSURE_PATH_SEGMENT not in segments:
        served = f"'{base_path}'" if base_path is not None else "no distribution"
        raise click.ClickException(
            f"Build contains embargoed (LW-) vulnerabilities but {option} "
            f"'{repository_name}' is served at {served}, not a predisclosure "
            f"distribution. Aborting to prevent disclosure of embargoed "
            f"content."
        )


def _verify_embargo_destinations(
    config: PulpConfig,
    has_lw: bool,
    requires_file_repository: bool,
    pulp_file_repository: str | None,
    requires_vex_repository: bool,
    pulp_vex_repository: str | None,
) -> None:
    """Build-level LW- gate for the OSV and VEX File repositories.

    When the build has any ``LW-`` ID, every OSV and VEX file of the build
    is embargoed content, whatever the IDs or source inside individual files
    say. Before any upload (and in dry-run mode), fail closed unless each
    File repository that receives files is served by a predisclosure
    distribution in Pulp, checked the same way as the Maven
    ``java/predisclosure`` distribution. GitHub OSV publication is refused
    for such builds separately.
    """
    if not has_lw:
        return
    if requires_file_repository:
        assert pulp_file_repository is not None
        _validate_file_predisclosure_distribution(
            config, pulp_file_repository, "--pulp-file-repository"
        )
    if requires_vex_repository:
        assert pulp_vex_repository is not None
        _validate_file_predisclosure_distribution(
            config, pulp_vex_repository, "--pulp-vex-repository"
        )


def _retrieve_uploadable_metadata(
    security_metadata_files: tuple[Path, ...],
    expected_source: str | None,
    pulp_file_repository: str | None,
    records: dict[Path, dict[str, Any]],
    record_kind: str = "OSV",
    embargoed_build: bool = False,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Retrieve uploadable metadata.

    For a build with ``LW-`` IDs (``embargoed_build``) every file is kept:
    all of them are embargoed content and go to the (already verified)
    predisclosure repository. A CVE-only file of such a build is not
    dropped as ``pnc-build``, so the predisclosure repository has the
    complete set.
    """
    if not security_metadata_files:
        return security_metadata_files, ()
    if embargoed_build:
        click.echo(
            f"Embargoed build: uploading all "
            f"{len(security_metadata_files)} {record_kind} record(s) to "
            f"predisclosure repository '{pulp_file_repository}' without "
            f"source filtering."
        )
        return security_metadata_files, ()
    if expected_source is None:
        if pulp_file_repository:
            click.echo(
                f"Warning: {record_kind} repository '{pulp_file_repository}' "
                f"is not a recognized backport/novel repository; uploading "
                f"all {len(security_metadata_files)} record(s) without type "
                f"filtering."
            )
        return security_metadata_files, ()

    # Mismatched records are dropped (warned, not errored) under the
    # disjoint-repo model: each record type is published to its own
    # stream by the RPA that owns it. A CVE OSV belongs to the backport
    # stream, which publishes it independently; the copy riding along a
    # novel-only release is therefore either redundant (already in the
    # backport repo) or an orphan pointing at an artifact absent from
    # the novel repo. Neither justifies writing it here, so a
    # novel-only release that carried CVE backports correctly drops
    # them rather than failing. (RPA composition ensuring CVEs reach
    # the backport stream is out of scope for this task.)
    kept: list[Path] = []
    dropped: list[Path] = []
    for metadata_file in security_metadata_files:
        # CycloneDX SBOM/VEX: classify by CVE content, not by
        # database_specific (which CycloneDX files lack).
        cdx_record = records.get(metadata_file)
        if (
            isinstance(cdx_record, dict)
            and cdx_record.get("bomFormat") == "CycloneDX"
        ):
            cdx_source = _classify_cdx_source(cdx_record, metadata_file)
            if cdx_source == expected_source or cdx_source is None:
                kept.append(metadata_file)
            else:
                dropped.append(metadata_file)
                click.echo(
                    f"Warning: skipping CycloneDX "
                    f"{metadata_file.name} "
                    f"(source={cdx_source}); does not "
                    f"belong in {expected_source} repo "
                    f"'{pulp_file_repository}'."
                )
            continue

        record_source = _classify_osv_source(metadata_file, cdx_record)
        if record_source == expected_source:
            kept.append(metadata_file)
        else:
            dropped.append(metadata_file)
            click.echo(
                f"Warning: skipping {record_kind} record "
                f"{metadata_file.name} "
                f"(source={record_source or 'unknown'}); it does not "
                f"belong in the {expected_source} repository "
                f"'{pulp_file_repository}'."
            )
    uploadable_metadata = tuple(kept)
    skipped_metadata = tuple(dropped)
    return uploadable_metadata, skipped_metadata


def _select_github_osv_records(
    security_metadata_files: tuple[Path, ...],
    records: dict[Path, dict[str, Any]] | None = None,
) -> tuple[Path, ...]:
    """Select the records to publish to the GitHub OSV repository.

    Built independently of the Pulp-derived set: the GitHub repository is a
    public OSV feed ingested by osv.dev, so it carries remediated
    (``pnc-build``) OSV records only. CycloneDX SBOM/VEX documents and
    ``novel-pipeline`` records are excluded, and an OSV record that cannot
    be classified fails the run closed rather than being published.

    Raises:
        ValueError: If any OSV record cannot be classified.

    """
    selected: list[Path] = []
    for metadata_file in security_metadata_files:
        record = None if records is None else records.get(metadata_file)
        if record is None:
            loaded = safe_json_load(metadata_file, raise_on_err=False)
            record = loaded if isinstance(loaded, dict) else None
        if isinstance(record, dict) and record.get("bomFormat") == "CycloneDX":
            continue
        source = _classify_osv_source(metadata_file, record)
        if source is None:
            raise ValueError(
                f"GitHub OSV: cannot classify the source of "
                f"{metadata_file.name}; refusing to publish it to the "
                f"public OSV repository."
            )
        if source == "pnc-build":
            selected.append(metadata_file)
        else:
            click.echo(
                f"GitHub OSV: skipping {metadata_file.name} "
                f"(source={source}); only pnc-build records are published."
            )
    return tuple(selected)


def _upload_one(
    client: PulpMavenClient,
    artifact: MavenArtifact,
    labels: dict[str, str],
    verbose: bool,
) -> ContentUnit:
    """Upload a single artifact. Runs in a worker thread."""
    if verbose:
        click.echo(f"Uploading: {artifact.relative_path}")
    upload = (
        client.upload_metadata if artifact.is_metadata else client.upload_content
    )
    content_unit = upload(
        file_path=artifact.file_path,
        relative_path=artifact.relative_path,
        group_id=artifact.group_id,
        artifact_id=artifact.artifact_id,
        version=artifact.version,
        filename=artifact.file_path.name,
        labels=labels,
    )
    if verbose:
        click.echo(f"  -> {content_unit.pulp_href}")
    return content_unit


def _verify_autopublish_distribution(
    file_client: PulpFileClient,
    repository_name: str,
    repository_href: str,
    purpose: str,
) -> None:
    """Fail closed unless the distribution serves this repo with autopublish.

    The metadata file repositories are managed by pulp-config as
    repository-backed distributions with autopublish enabled: every new
    repository version is published automatically and the distribution
    always serves the latest version. A distribution pinned to a
    publication (its repository link cleared) would stop serving new
    uploads entirely, so refuse to upload rather than write content that
    no distribution serves (LWLP-4823).
    """
    dist_repository = file_client.get_distribution_repository(repository_name)
    if dist_repository != repository_href:
        raise click.ClickException(
            f"{purpose} distribution '{repository_name}' does not serve "
            f"repository '{repository_name}'"
            + (
                " (it is pinned to a publication)"
                if dist_repository is None
                else ""
            )
            + ". Re-apply the pulp-config environment to restore the "
            "repository-backed distribution."
        )
    if not file_client.get_repository_autopublish(repository_href):
        raise click.ClickException(
            f"{purpose} repository '{repository_name}' does not have "
            "autopublish enabled. Re-apply the pulp-config environment "
            "before publishing."
        )


def _resolve_file_repository(
    clients: ExitStack,
    config: PulpConfig,
    repository_name: str,
    purpose: str,
) -> tuple[PulpFileClient, str]:
    """Open a File client and verify the repository before any upload."""
    try:
        file_client = clients.enter_context(
            PulpFileClient(config, repository_name)
        )
        file_repo_href = file_client.resolve_repository(repository_name)
        _verify_autopublish_distribution(
            file_client, repository_name, file_repo_href, purpose
        )
    except PulpError as e:
        raise click.ClickException(
            f"Unable to verify the required {purpose} publication repository."
        ) from e
    return file_client, file_repo_href


def _publish_file_records(
    file_client: PulpFileClient,
    repository_href: str,
    files: tuple[Path, ...],
    purpose: str,
) -> int:
    """Upload files; the repository-backed distribution auto-publishes them."""
    uploaded = 0
    try:
        for file_path in files:
            sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
            file_client.upload_content(
                file_path=file_path,
                relative_path=file_path.name,
                sha256=sha256,
                repository_href=repository_href,
            )
            uploaded += 1
    except PulpError as e:
        raise click.ClickException(
            f"Required {purpose} upload did not complete."
        ) from e
    return uploaded


def _repository_has_predisclosure_distribution(
    client: PulpMavenClient, repository_href: str
) -> bool:
    """Check whether a repository is served by the predisclosure route."""
    distributions = client.list_distributions(repository_href)
    return any(
        distribution.repository == repository_href
        and distribution.base_path.strip("/") == MAVEN_PREDISCLOSURE_BASE_PATH
        for distribution in distributions
    )


def _validate_predisclosure_distribution(
    client: PulpMavenClient, repository_name: str
) -> str:
    """Resolve and validate the repository's predisclosure distribution."""
    try:
        click.echo(f"Resolving repository: {repository_name}")
        repository_href = client.resolve_repository(repository_name)
        if not _repository_has_predisclosure_distribution(
            client, repository_href
        ):
            raise click.ClickException(
                f"Build contains embargoed (LW-) vulnerabilities but "
                f"repository '{repository_name}' is not associated "
                f"with a predisclosure distribution. Aborting to "
                f"prevent disclosure of embargoed content."
            )
    except PulpError as e:
        raise click.ClickException(
            "Unable to verify the predisclosure distribution for an "
            "embargoed build."
        ) from e

    return repository_href


def _print_dry_run(
    *,
    build: BuildOutput,
    uploadable_metadata: tuple[Path, ...],
    uploadable_vex: tuple[Path, ...],
    file_skipped: int,
    github_records: tuple[Path, ...],
    github_osv_repo: str | None,
    github_osv_branch: str,
    github_osv_path: str,
    pulp_repository: str,
    pulp_url: str,
    pulp_auth_type: str,
    upload_workers: int,
) -> None:
    """Print the actions a dry run would take."""
    click.echo(f"Distribution: {pulp_repository}")
    click.echo(f"Pulp URL: {pulp_url}")
    click.echo(f"Auth type: {pulp_auth_type}")
    click.echo(f"Artifacts: {len(build.artifacts)}")
    click.echo(f"Coordinates: {len(build.coordinates)}")
    click.echo(f"Upload workers: {upload_workers}")
    for artifact in build.artifacts:
        click.echo(f"  {artifact.relative_path}")
    if uploadable_metadata:
        click.echo(f"Security metadata: {len(uploadable_metadata)} file(s)")
        for metadata_file in uploadable_metadata:
            click.echo(f"  {metadata_file.name}")
    if uploadable_vex:
        click.echo(f"VEX metadata: {len(uploadable_vex)} file(s)")
        for metadata_file in uploadable_vex:
            click.echo(f"  {metadata_file.name}")
    if file_skipped:
        click.echo(f"Security metadata skipped (wrong type): {file_skipped}")
    if github_records:
        click.echo(
            f"GitHub OSV: would push {len(github_records)} "
            f"record(s) to {github_osv_repo} "
            f"(branch {github_osv_branch}, "
            f"path {github_osv_path or '/'})"
        )
        for metadata_file in github_records:
            click.echo(f"  {metadata_file.name}")
    click.echo(
        f"\ndry-run: would upload "
        f"{len(build.artifacts)} artifact(s) "
        f"to {pulp_url}"
    )


def _upload_to_pulp(
    ctx: GlobalContext,
    config: PulpConfig,
    build: BuildOutput,
    uploadable_metadata: tuple[Path, ...],
    uploadable_vex: tuple[Path, ...],
    pulp_url: str,
    pulp_file_repository: str | None,
    pulp_vex_repository: str | None,
    pulp_repository: str,
    pulp_labels: dict[str, str],
    requires_file_repository: bool,
    requires_vex_repository: bool,
    file_skipped: int,
    upload_workers: int,
    repository_href: str | None = None,
    skip_associate: bool = False,
) -> tuple[PublishResult, int, int, int, int]:
    """Upload artifacts to Pulp.

    With *skip_associate* the Maven content is uploaded and labelled as usual
    but not added to the repository (no ``add_and_remove`` modify), so a later
    batch step can associate it (LWLP-6026). OSV/VEX file records are
    published as usual.
    """
    uploaded = 0
    skipped = 0
    file_uploaded = 0
    vex_uploaded = 0
    repository_version = None
    content_unit_hrefs: list[str] = []

    with ExitStack() as clients:
        file_client: PulpFileClient | None = None
        file_repo_href: str | None = None
        if requires_file_repository:
            assert pulp_file_repository is not None
            file_client, file_repo_href = _resolve_file_repository(
                clients, config, pulp_file_repository, "OSV"
            )
        vex_client: PulpFileClient | None = None
        vex_repo_href: str | None = None
        if requires_vex_repository:
            assert pulp_vex_repository is not None
            vex_client, vex_repo_href = _resolve_file_repository(
                clients, config, pulp_vex_repository, "VEX"
            )

        client = clients.enter_context(PulpMavenClient(config, pulp_repository))
        uploadable: list[MavenArtifact] = []
        for artifact in build.artifacts:
            if not artifact.file_path.exists():
                click.echo(
                    f"Warning: skipping missing file: {artifact.relative_path}"
                )
                skipped += 1
            else:
                uploadable.append(artifact)

        with ThreadPoolExecutor(max_workers=upload_workers) as executor:
            future_to_artifact: dict[Future[ContentUnit], MavenArtifact] = {
                executor.submit(
                    _upload_one, client, artifact, pulp_labels, ctx.verbose
                ): artifact
                for artifact in uploadable
            }

            for future in as_completed(future_to_artifact):
                artifact = future_to_artifact[future]
                try:
                    content_unit = future.result()
                except PulpError as e:
                    if e.status_code != 503:
                        raise
                    click.echo(
                        f"Warning: Pulp returned recoverable HTTP 503 for "
                        f"{artifact.relative_path}; continuing with the "
                        "publish loop."
                    )
                    continue
                content_unit_hrefs.append(content_unit.pulp_href)
                uploaded += 1

        if content_unit_hrefs and skip_associate:
            click.echo(
                f"Skipping association: {len(content_unit_hrefs)} content "
                "unit(s) uploaded but not added to the repository "
                "(--skip-associate)"
            )
        elif content_unit_hrefs:
            if repository_href is None:
                click.echo(f"Resolving repository: {pulp_repository}")
                repository_href = client.resolve_repository(pulp_repository)

            click.echo(
                f"Adding {len(content_unit_hrefs)} content unit(s) to repository"
            )
            modify_result = client.modify_repository(
                repository_href, content_unit_hrefs
            )
            repository_version = modify_result.repository_version

            if ctx.verbose:
                click.echo(f"  -> repository version: {repository_version}")

        if file_client and file_repo_href and pulp_file_repository:
            file_uploaded = _publish_file_records(
                file_client,
                file_repo_href,
                uploadable_metadata,
                "OSV",
            )
        if vex_client and vex_repo_href and pulp_vex_repository:
            vex_uploaded = _publish_file_records(
                vex_client,
                vex_repo_href,
                uploadable_vex,
                "VEX",
            )

    if file_uploaded:
        click.echo(f"Security metadata: {file_uploaded} file(s) uploaded")
    if vex_uploaded:
        click.echo(f"VEX metadata: {vex_uploaded} file(s) uploaded")

    publish_result = PublishResult(
        pulp_url=pulp_url,
        distribution=pulp_repository,
        artifacts_uploaded=uploaded,
        artifacts_skipped=skipped,
        coordinates=tuple(build.coordinates),
        published_at=datetime.now(timezone.utc).isoformat(),
        repository_version=repository_version,
        content_unit_hrefs=tuple(content_unit_hrefs),
        pulp_labels=pulp_labels,
        file_repository=pulp_file_repository if file_uploaded else None,
        security_metadata_uploaded=file_uploaded,
        security_metadata_skipped=file_skipped,
        vex_repository=pulp_vex_repository if vex_uploaded else None,
        vex_uploaded=vex_uploaded,
    )
    return publish_result, uploaded, skipped, file_uploaded, vex_uploaded


def _print_verbose_pulp_info(
    ctx: GlobalContext,
    pulp_url: str,
    pulp_repository: str,
    pulp_auth_type: str,
    insecure: bool,
    ca_cert: Path | None,
    pulp_domain: str,
    pulp_client_cert: Path | None,
    pulp_client_key: Path | None,
    config: PulpConfig,
    upload_workers: int,
    pulp_task_timeout: float,
    pulp_max_total_task_timeout: float | None,
) -> None:
    """Print verbose Pulp information."""
    if ctx.verbose:
        click.echo(f"Pulp URL: {pulp_url}")
        click.echo(f"Distribution: {pulp_repository}")
        click.echo(f"Auth type: {pulp_auth_type}")
        click.echo(f"TLS verification: {not insecure}")
        if ca_cert:
            click.echo(f"CA certificate: {ca_cert}")
        if pulp_domain:
            click.echo(f"Pulp domain: {pulp_domain}")
        if pulp_client_cert:
            click.echo(f"Client certificate: {pulp_client_cert}")
        if pulp_client_key:
            click.echo(f"Client key: {pulp_client_key}")
        if config.custom_headers:
            click.echo(f"Custom headers: {config.custom_headers}")
        click.echo(f"Upload workers: {upload_workers}")
        click.echo(f"Task timeout: {pulp_task_timeout}s")
        max_timeout = pulp_max_total_task_timeout
        if max_timeout is None:
            max_timeout = 2.0 * pulp_task_timeout
        click.echo(f"Maximum total task timeout: {max_timeout}s")


def _print_verbose_artifact_info(
    ctx: GlobalContext,
    build: BuildOutput,
    artifact_dir: Path,
    extract_result: ExtractResult,
) -> None:
    """Print verbose artifact information."""
    if ctx.verbose:
        click.echo(
            f"Discovered {len(build.artifacts)} "
            f"artifact(s) across "
            f"{len(build.coordinates)} "
            f"coordinate(s)"
        )
        click.echo(f"Repository root: {build.deliverable_dir}")
        if not build.artifacts:
            _diagnose_empty_build(artifact_dir, extract_result.deliverable_dir)
        for artifact in build.artifacts:
            size = (
                artifact.file_path.stat().st_size
                if artifact.file_path.exists()
                else -1
            )
            click.echo(f"  {artifact.relative_path} ({size} bytes)")
        coords = [
            f"{c.group_id}:{c.artifact_id}:{c.version}" for c in build.coordinates
        ]
        click.echo(f"Coordinates: {', '.join(coords)}")


@click.command()
@click.option(
    "--pulp-url",
    required=True,
    type=str,
    help=("Pulp instance base URL (e.g. https://pulp.example.com)."),
)
@click.option(
    "--pulp-repository",
    required=True,
    type=str,
    help=("Pulp Maven distribution name for artifact upload."),
)
@click.option(
    "--artifact-dir",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "Directory containing extracted artifacts (output of the extract stage)."
    ),
)
@click.option(
    "--insecure",
    is_flag=True,
    default=False,
    help="Disable TLS certificate verification.",
)
@click.option(
    "--pulp-auth-type",
    type=click.Choice(["tbr", "cert"], case_sensitive=False),
    default="tbr",
    help="Pulp authentication method.",
)
@click.option(
    "--pulp-username",
    type=str,
    default=None,
    help="Username for TBR basic auth.",
)
@click.option(
    "--pulp-password",
    type=str,
    default=None,
    help="Password for TBR basic auth.",
)
@click.option(
    "--pulp-client-cert",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Client certificate path for entitlement cert auth.",
)
@click.option(
    "--pulp-client-key",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Client key path for entitlement cert auth.",
)
@click.option(
    "--pulp-domain",
    envvar="SLAN_CUAN_PUBLISH_PULP_DOMAIN",
    required=True,
    type=str,
    help="Pulp domain for hosted content API (e.g. 'lightwell').",
)
@click.option(
    "--upload-workers",
    type=click.IntRange(min=1),
    default=DEFAULT_UPLOAD_WORKERS,
    show_default=True,
    help="Number of concurrent upload threads.",
)
@click.option(
    "--require-supply-chain-metadata",
    is_flag=True,
    default=False,
    show_default=True,
    help=(
        "Require supply chain metadata (SBOMs) to be present "
        "in the artifact directory."
    ),
)
@click.option(
    "--skip-associate",
    is_flag=True,
    default=False,
    show_default=True,
    help=(
        "Upload and label the Maven content but don't add it to the "
        "repository; a later batch step associates it. OSV/VEX records "
        "are still published."
    ),
)
@click.option(
    "--pulp-file-repository",
    envvar="SLAN_CUAN_PUBLISH_PULP_FILE_REPOSITORY",
    type=str,
    default=None,
    help="Pulp File repository name for OSV upload.",
)
@click.option(
    "--pulp-vex-repository",
    envvar="SLAN_CUAN_PUBLISH_PULP_VEX_REPOSITORY",
    type=str,
    default=None,
    help=(
        "Pulp File repository name for VEX upload. Required when VEX is "
        "present; must differ from --pulp-file-repository, contain "
        "'backport' or 'novel'. For LW- builds it must be served by a "
        "predisclosure distribution."
    ),
)
@click.option(
    "--pulp-task-timeout",
    envvar="SLAN_CUAN_PUBLISH_PULP_TASK_TIMEOUT",
    type=click.FloatRange(min=1.0),
    default=TASK_POLL_TIMEOUT_SECONDS,
    show_default=True,
    help="Maximum time in seconds to wait for asynchronous Pulp tasks.",
)
@click.option(
    "--pulp-max-total-task-timeout",
    envvar="SLAN_CUAN_PUBLISH_PULP_MAX_TOTAL_TASK_TIMEOUT",
    type=click.FloatRange(min=1.0),
    default=None,
    help=(
        "Absolute maximum time in seconds across all Pulp task state "
        "and blocker timeout resets. Defaults to twice the task timeout."
    ),
)
@click.option(
    "--pulp-custom-headers",
    envvar="SLAN_CUAN_PUBLISH_PULP_CUSTOM_HEADERS",
    default="",
    help=(
        "Custom HTTP headers to send on repository modify "
        "(CRLF/newline-delimited 'Key: Value' or JSON)."
    ),
)
@click.option(
    "--github-osv-repo",
    envvar="SLAN_CUAN_PUBLISH_GITHUB_OSV_REPO",
    type=str,
    default=None,
    help=(
        "GitHub repository (owner/name) to publish OSV records to, in "
        "addition to Pulp. Enables GitHub publication when set together with "
        "--github-osv-token."
    ),
)
@click.option(
    "--github-osv-token",
    envvar="SLAN_CUAN_PUBLISH_GITHUB_OSV_TOKEN",
    type=str,
    default=None,
    help="Personal access / bot token with write access to the OSV repo.",
)
@click.option(
    "--github-osv-branch",
    envvar="SLAN_CUAN_PUBLISH_GITHUB_OSV_BRANCH",
    type=str,
    default="main",
    show_default=True,
    help="Branch of the OSV repository to commit records onto.",
)
@click.option(
    "--github-osv-path",
    envvar="SLAN_CUAN_PUBLISH_GITHUB_OSV_PATH",
    type=str,
    default="advisories",
    show_default=True,
    help=(
        "Directory prefix inside the OSV repository for records; osv.dev "
        "ingests only this directory. Empty means the repository root."
    ),
)
@click.pass_obj
def publish(
    ctx: GlobalContext,
    pulp_url: str,
    pulp_repository: str,
    artifact_dir: Path,
    insecure: bool,
    pulp_auth_type: str,
    pulp_username: str | None,
    pulp_password: str | None,
    pulp_client_cert: Path | None,
    pulp_client_key: Path | None,
    pulp_domain: str,
    upload_workers: int,
    require_supply_chain_metadata: bool,
    skip_associate: bool,
    pulp_file_repository: str | None,
    pulp_vex_repository: str | None,
    pulp_task_timeout: float,
    pulp_max_total_task_timeout: float | None,
    pulp_custom_headers: str,
    github_osv_repo: str | None,
    github_osv_token: str | None,
    github_osv_branch: str,
    github_osv_path: str,
) -> None:
    """Publish Maven artifacts to Pulp."""
    pulp_file_repository = (
        pulp_file_repository.strip() or None if pulp_file_repository else None
    )
    pulp_vex_repository = (
        pulp_vex_repository.strip() or None if pulp_vex_repository else None
    )
    github_osv_repo = github_osv_repo.strip() or None if github_osv_repo else None
    github_osv_token = (
        github_osv_token.strip() or None if github_osv_token else None
    )
    try:
        extract_result = _validate_load_extract_result(ctx, artifact_dir)

        build = BuildOutput.from_extract_result(
            extract_result, artifact_dir, require_supply_chain_metadata
        )
        _print_verbose_artifact_info(ctx, build, artifact_dir, extract_result)

        vulns = _gav_index_vulnerabilities(
            extract_result.attachment_files, artifact_dir
        )

        has_lw = _source_from_vuln_id_has_embargo(vulns)

        security_metadata_files = (
            tuple(
                f
                for f in build.security_metadata_dir.rglob("*")
                if f.is_file()
                and not f.name.endswith(".pedigree.json")
                and "enriched-sboms"
                not in f.relative_to(build.security_metadata_dir).parts
            )
            if build.security_metadata_dir
            else ()
        )
        _validate_security_metadata(security_metadata_files, vulns)
        osv_files, vex_files, metadata_records = _partition_security_metadata(
            security_metadata_files
        )
        # Fail closed: LW- content in any generated file makes the build
        # embargoed even if the GAV index does not list the LW- ID.
        if not has_lw and _metadata_has_embargo(metadata_records):
            click.echo(
                "Security metadata contains embargoed (LW-) IDs not listed in "
                "the GAV index; treating the build as embargoed."
            )
            has_lw = True
        # After the embargo check, so an LW- ID in a legacy record still
        # marks the build as embargoed (fail closed).
        osv_files, legacy_osv_files = _drop_legacy_osv_records(
            osv_files, metadata_records
        )
        requires_file_repository = _verify_requires_file_repository(
            vulns, osv_files, pulp_file_repository
        )
        requires_vex_repository = _verify_requires_vex_repository(
            vex_files, pulp_vex_repository, pulp_file_repository, metadata_records
        )
        if github_osv_repo and not github_osv_token:
            raise click.UsageError(
                f"GitHub OSV publication to {github_osv_repo} was requested "
                "but the token is empty (--github-osv-token / "
                "SLAN_CUAN_PUBLISH_GITHUB_OSV_TOKEN). In Tekton, check that "
                "the Secret named by GITHUB_OSV_TOKEN_SECRET exists and has "
                "a 'token' key."
            )
        if github_osv_token and not github_osv_repo:
            raise click.UsageError(
                "--github-osv-token was provided but --github-osv-repo is "
                "empty; set both to enable GitHub OSV publication."
            )
        github_osv_enabled = bool(github_osv_repo and github_osv_token)

        expected_source = (
            _expected_source_for_repo(pulp_file_repository)
            if pulp_file_repository
            else None
        )
        uploadable_metadata, skipped_metadata = _retrieve_uploadable_metadata(
            osv_files,
            expected_source,
            pulp_file_repository,
            metadata_records,
            embargoed_build=has_lw,
        )
        vex_expected_source = (
            _expected_source_for_repo(pulp_vex_repository)
            if pulp_vex_repository
            else None
        )
        uploadable_vex, skipped_vex = _retrieve_uploadable_metadata(
            vex_files,
            vex_expected_source,
            pulp_vex_repository,
            metadata_records,
            record_kind="VEX",
            embargoed_build=has_lw,
        )
        file_skipped = (
            len(skipped_metadata) + len(skipped_vex) + len(legacy_osv_files)
        )

        # Validate GitHub OSV publication up front so a misconfiguration fails
        # before anything is written to Pulp.
        gh_client: GitHubOsvClient | None = None
        github_records: tuple[Path, ...] = ()
        if github_osv_enabled and has_lw:
            # Never publish anything from a build with LW- IDs to the public
            # GitHub OSV repository, whatever per-record classification says
            # (the per-release RHLW- advisory would classify as pnc-build).
            click.echo(
                f"GitHub OSV: build contains embargoed (LW-) vulnerabilities; "
                f"not publishing to the public repository {github_osv_repo}."
            )
        elif github_osv_enabled:
            assert github_osv_repo is not None
            assert github_osv_token is not None
            # Fail closed: only the backport stream may feed the public OSV
            # repository, and repo-name inference must positively identify it.
            if osv_files and expected_source != "pnc-build":
                raise click.UsageError(
                    "GitHub OSV publication requires --pulp-file-repository "
                    "to be the backport OSV repository; "
                    f"'{pulp_file_repository}' is not recognized as one."
                )
            github_records = _select_github_osv_records(
                osv_files, metadata_records
            )
            gh_client = GitHubOsvClient(
                github_osv_repo,
                github_osv_token,
                branch=github_osv_branch,
                path=github_osv_path,
                verbose=ctx.verbose,
            )

        if ctx.dry_run and not has_lw:
            _print_dry_run(
                build=build,
                uploadable_metadata=uploadable_metadata,
                uploadable_vex=uploadable_vex,
                file_skipped=file_skipped,
                github_records=github_records,
                github_osv_repo=github_osv_repo,
                github_osv_branch=github_osv_branch,
                github_osv_path=github_osv_path,
                pulp_repository=pulp_repository,
                pulp_url=pulp_url,
                pulp_auth_type=pulp_auth_type,
                upload_workers=upload_workers,
            )
            return

        ca_cert = ctx.ca_cert if ctx.ca_cert and ctx.ca_cert.exists() else None
        if pulp_client_cert is not None and not pulp_client_cert.exists():
            pulp_client_cert = None
        if pulp_client_key is not None and not pulp_client_key.exists():
            pulp_client_key = None

        if pulp_auth_type == "tbr" and (not pulp_username or not pulp_password):
            raise click.UsageError(
                "--pulp-username and --pulp-password are required "
                "when --pulp-auth-type is 'tbr'."
            )
        if pulp_auth_type == "cert" and (
            pulp_client_cert is None or pulp_client_key is None
        ):
            raise click.UsageError(
                "--pulp-client-cert and --pulp-client-key are required "
                "when --pulp-auth-type is 'cert'."
            )

        config = PulpConfig(
            base_url=pulp_url,
            verify_ssl=not insecure,
            ca_cert=ca_cert,
            domain=pulp_domain,
            auth_type=pulp_auth_type,
            username=pulp_username,
            password=pulp_password,
            client_cert=pulp_client_cert,
            client_key=pulp_client_key,
            task_timeout=pulp_task_timeout,
            max_total_task_timeout=pulp_max_total_task_timeout,
            custom_headers=parse_custom_headers(pulp_custom_headers),
            verbose=ctx.verbose,
        )

        _print_verbose_pulp_info(
            ctx=ctx,
            pulp_url=pulp_url,
            pulp_repository=pulp_repository,
            pulp_auth_type=pulp_auth_type,
            insecure=insecure,
            ca_cert=ca_cert,
            pulp_domain=pulp_domain,
            pulp_client_cert=pulp_client_cert,
            pulp_client_key=pulp_client_key,
            config=config,
            upload_workers=upload_workers,
            pulp_task_timeout=pulp_task_timeout,
            pulp_max_total_task_timeout=pulp_max_total_task_timeout,
        )

        repository_href: str | None = None
        if has_lw:
            with PulpMavenClient(config, pulp_repository) as client:
                repository_href = _validate_predisclosure_distribution(
                    client, pulp_repository
                )
            _verify_embargo_destinations(
                config,
                has_lw,
                requires_file_repository,
                pulp_file_repository,
                requires_vex_repository,
                pulp_vex_repository,
            )

        if ctx.dry_run:
            _print_dry_run(
                build=build,
                uploadable_metadata=uploadable_metadata,
                uploadable_vex=uploadable_vex,
                file_skipped=file_skipped,
                github_records=github_records,
                github_osv_repo=github_osv_repo,
                github_osv_branch=github_osv_branch,
                github_osv_path=github_osv_path,
                pulp_repository=pulp_repository,
                pulp_url=pulp_url,
                pulp_auth_type=pulp_auth_type,
                upload_workers=upload_workers,
            )
            return

        pulp_labels: dict[str, str] = {
            "source_image": str(extract_result.image),
        }
        click.echo(f"Pulp labels: {json.dumps(pulp_labels)}")

        (
            publish_result,
            uploaded,
            skipped,
            file_uploaded,
            vex_uploaded,
        ) = _upload_to_pulp(
            ctx=ctx,
            config=config,
            build=build,
            uploadable_metadata=uploadable_metadata,
            uploadable_vex=uploadable_vex,
            pulp_url=pulp_url,
            pulp_file_repository=pulp_file_repository,
            pulp_vex_repository=pulp_vex_repository,
            pulp_repository=pulp_repository,
            pulp_labels=pulp_labels,
            requires_file_repository=requires_file_repository,
            requires_vex_repository=requires_vex_repository,
            file_skipped=file_skipped,
            upload_workers=upload_workers,
            repository_href=repository_href,
            skip_associate=skip_associate,
        )

        github_osv_uploaded = 0
        github_osv_commit: str | None = None
        if gh_client is not None and github_records:
            commit_message = (
                f"Publish {len(github_records)} OSV record(s) "
                f"from {extract_result.image}"
            )
            try:
                github_osv_commit = gh_client.publish(
                    github_records, commit_message
                )
            except GitHubOsvError as e:
                raise click.ClickException(
                    f"GitHub OSV publication failed: {e.message}\n{e.stderr}"
                ) from e
            if github_osv_commit is not None:
                github_osv_uploaded = len(github_records)
                click.echo(
                    f"GitHub OSV: pushed {github_osv_uploaded} record(s) to "
                    f"{github_osv_repo} @ {github_osv_commit}"
                )
            else:
                click.echo(
                    f"GitHub OSV: no changes to publish to {github_osv_repo}"
                )

        publish_result = replace(
            publish_result,
            github_osv_configured=github_osv_enabled,
            github_osv_repo=github_osv_repo if github_osv_enabled else None,
            github_osv_commit=github_osv_commit,
            github_osv_uploaded=github_osv_uploaded,
        )

        publish_result_path = artifact_dir / PUBLISH_RESULT_FILENAME
        publish_result.save(publish_result_path)
        if ctx.verbose:
            click.echo(f"Publish result saved: {publish_result_path}")

        write_tekton_result(
            ctx.tekton_results_dir, "ARTIFACTS_UPLOADED", str(uploaded)
        )
        write_tekton_result(
            ctx.tekton_results_dir, "ARTIFACTS_SKIPPED", str(skipped)
        )
        artifact_outputs = {
            "uri": f"{pulp_url}/pulp/maven/{pulp_repository}/",
            "digest": "",
        }
        write_tekton_result(
            ctx.tekton_results_dir,
            "PUBLISHED_ARTIFACT_OUTPUTS",
            json.dumps(artifact_outputs),
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "PULP_LABELS",
            json.dumps(pulp_labels),
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "SECURITY_METADATA_UPLOADED",
            str(file_uploaded),
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "VEX_UPLOADED",
            str(vex_uploaded),
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "SECURITY_METADATA_SKIPPED",
            str(file_skipped),
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "GITHUB_OSV_CONFIGURED",
            "true" if github_osv_enabled else "false",
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "GITHUB_OSV_UPLOADED",
            str(github_osv_uploaded),
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "GITHUB_OSV_COMMIT",
            github_osv_commit or "",
        )

        click.echo(
            f"Published: {uploaded} artifact(s) "
            f"uploaded, {skipped} skipped, "
            f"{len(build.coordinates)} coordinate(s)"
        )

    except PulpError as e:
        parts = [f"Pulp error: {e.message}"]
        if e.status_code:
            parts.append(f"  HTTP status: {e.status_code}")
        if e.response_body:
            body = e.response_body[:_ERROR_RESPONSE_MAX]
            if len(e.response_body) > _ERROR_RESPONSE_MAX:
                body += "... (truncated)"
            parts.append(f"  Response body: {body}")
        raise click.ClickException("\n".join(parts)) from e
    except ValueError as e:
        raise click.ClickException(str(e)) from e
