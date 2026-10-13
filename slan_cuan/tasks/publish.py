"""Publish subcommand for uploading Maven artifacts to Pulp."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from slan_cuan.http import parse_custom_headers
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

_OSV_ID_PREFIX = "x_RHLW-"
_DIAG_MAX_ENTRIES = 50
_ERROR_RESPONSE_MAX = 500
DEFAULT_UPLOAD_WORKERS = 4
GAV_INDEX_FILENAME = "gav-index.json"


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

    Accepts OSV (.json), CycloneDX SBOM (.bom.json), and CycloneDX VEX
    (.bom.json) files.
    """
    if path.suffix != ".json":
        raise ValueError(
            "Generated security metadata is not OSV, VEX, or SBOM JSON."
        )
    return safe_json_load(
        path,
        parse_err_msg="Generated security metadata is malformed.",
        expected_type=dict,
        type_err_msg="Generated security metadata is not OSV, VEX, or SBOM JSON.",
    )


def _validate_security_metadata(
    security_metadata_files: tuple[Path, ...], vulns: tuple[str, ...]
) -> None:
    """Validate generated OSV/VEX/SBOM metadata and its GAV-index relationship."""
    osv_vulnerability_ids: set[str] = set()
    for path in security_metadata_files:
        record = _validate_load_json_security_metadata(path)

        # CycloneDX document: SBOM has components[], VEX has vulnerabilities[]
        is_cyclonedx = record.get("bomFormat") == "CycloneDX"
        is_cdx_vex = is_cyclonedx and isinstance(
            record.get("vulnerabilities"), list
        )
        is_cdx_sbom = is_cyclonedx and isinstance(record.get("components"), list)
        if is_cdx_vex or is_cdx_sbom:
            # CycloneDX SBOM and VEX are valid security metadata
            if is_cdx_vex:
                for vuln in record["vulnerabilities"]:
                    vuln_id = vuln.get("id", "")
                    if vuln_id:
                        osv_vulnerability_ids.add(vuln_id)
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
                "Generated security metadata is not OSV, VEX, or SBOM JSON."
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


def _classify_osv_source(file_path: Path) -> str | None:
    """Determine an OSV record's source: authoritative field, then id prefix.

    Returns ``"pnc-build"``, ``"novel-pipeline"``, or ``None`` when the record
    cannot be classified (malformed, non-OSV, or an unrecognized id).
    """
    record = safe_json_load(file_path, raise_on_err=False)
    if record is None:
        return None

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
    vulns: tuple[Path, ...],
    security_metadata_files: tuple[Path, ...],
    pulp_file_repository: str | None,
) -> bool:
    requires_file_repository = bool(vulns or security_metadata_files)
    if requires_file_repository and not pulp_file_repository:
        raise click.UsageError(
            "--pulp-file-repository is required for OSV publication."
        )
    return requires_file_repository


def _retrieve_uploadable_metadata(
    security_metadata_files: tuple[Path, ...],
    expected_source: str | None,
    pulp_file_repository: str | None,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Retrieve uploadable metadata."""
    if not security_metadata_files or expected_source is None:
        uploadable_metadata = security_metadata_files
        skipped_metadata: tuple[Path, ...] = ()
        if security_metadata_files and pulp_file_repository:
            click.echo(
                f"Warning: OSV repository '{pulp_file_repository}' is not "
                f"a recognized backport/novel repository; uploading all "
                f"{len(security_metadata_files)} record(s) without type "
                f"filtering."
            )
        return uploadable_metadata, skipped_metadata

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
        # CycloneDX SBOM/VEX files (bomFormat == "CycloneDX") inherit
        # the routing of the OSV records they accompany — they are not
        # source-routed independently. Keep them with the batch.
        cdx_record = safe_json_load(metadata_file, raise_on_err=False)
        if (
            isinstance(cdx_record, dict)
            and cdx_record.get("bomFormat") == "CycloneDX"
        ):
            kept.append(metadata_file)
            continue

        record_source = _classify_osv_source(metadata_file)
        if record_source == expected_source:
            kept.append(metadata_file)
        else:
            dropped.append(metadata_file)
            click.echo(
                f"Warning: skipping OSV record {metadata_file.name} "
                f"(source={record_source or 'unknown'}); it does not "
                f"belong in the {expected_source} repository "
                f"'{pulp_file_repository}'."
            )
    uploadable_metadata = tuple(kept)
    skipped_metadata = tuple(dropped)
    return uploadable_metadata, skipped_metadata


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


def _upload_to_pulp(
    ctx: GlobalContext,
    config: PulpConfig,
    build: BuildOutput,
    uploadable_metadata: tuple[Path, ...],
    pulp_url: str,
    pulp_file_repository: str | None,
    pulp_repository: str,
    pulp_labels: dict[str, str],
    requires_file_repository: bool,
    file_skipped: int,
    upload_workers: int,
) -> tuple[PublishResult, int, int, int]:
    """Upload artifacts to Pulp."""
    uploaded = 0
    skipped = 0
    file_uploaded = 0
    repository_version = None
    content_unit_hrefs: list[str] = []

    with ExitStack() as clients:
        file_client: PulpFileClient | None = None
        file_repo_href: str | None = None
        if requires_file_repository:
            try:
                file_client = clients.enter_context(
                    PulpFileClient(config, pulp_file_repository)
                )
                file_repo_href = file_client.resolve_repository(
                    pulp_file_repository
                )
            except PulpError as e:
                raise click.ClickException(
                    "Unable to verify the required OSV publication repository."
                ) from e

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

        if content_unit_hrefs:
            click.echo(f"Resolving repository: {pulp_repository}")
            repo_href = client.resolve_repository(pulp_repository)

            click.echo(
                f"Adding {len(content_unit_hrefs)} content unit(s) to repository"
            )
            modify_result = client.modify_repository(
                repo_href, content_unit_hrefs
            )
            repository_version = modify_result.repository_version

            if ctx.verbose:
                click.echo(f"  -> repository version: {repository_version}")

        if file_client and file_repo_href:
            try:
                for file_path in uploadable_metadata:
                    sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
                    file_client.upload_content(
                        file_path=file_path,
                        relative_path=file_path.name,
                        sha256=sha256,
                        repository_href=file_repo_href,
                    )
                    file_uploaded += 1

                if file_uploaded > 0:
                    pub_href = file_client.create_publication(file_repo_href)
                    dist_href = file_client.resolve_distribution(
                        pulp_file_repository
                    )
                    file_client.update_distribution(dist_href, pub_href)
            except PulpError as e:
                raise click.ClickException(
                    "Required OSV publication did not complete."
                ) from e

    if file_uploaded:
        click.echo(f"Security metadata: {file_uploaded} file(s) uploaded")

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
    )
    return publish_result, uploaded, skipped, file_uploaded


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
    "--pulp-file-repository",
    envvar="SLAN_CUAN_PUBLISH_PULP_FILE_REPOSITORY",
    type=str,
    default=None,
    help="Pulp File repository name for security metadata upload.",
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
    pulp_file_repository: str | None,
    pulp_task_timeout: float,
    pulp_max_total_task_timeout: float | None,
    pulp_custom_headers: str,
) -> None:
    """Publish Maven artifacts to Pulp."""
    pulp_file_repository = (
        pulp_file_repository.strip() or None if pulp_file_repository else None
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
        security_metadata_files = (
            tuple(
                f for f in build.security_metadata_dir.rglob("*") if f.is_file()
            )
            if build.security_metadata_dir
            else ()
        )
        _validate_security_metadata(security_metadata_files, vulns)
        requires_file_repository = _verify_requires_file_repository(
            vulns, security_metadata_files, pulp_file_repository
        )

        expected_source = (
            _expected_source_for_repo(pulp_file_repository)
            if pulp_file_repository
            else None
        )
        uploadable_metadata, skipped_metadata = _retrieve_uploadable_metadata(
            security_metadata_files, expected_source, pulp_file_repository
        )
        file_skipped = len(skipped_metadata)

        if ctx.dry_run:
            click.echo(f"Distribution: {pulp_repository}")
            click.echo(f"Pulp URL: {pulp_url}")
            click.echo(f"Auth type: {pulp_auth_type}")
            click.echo(f"Artifacts: {len(build.artifacts)}")
            click.echo(f"Coordinates: {len(build.coordinates)}")
            click.echo(f"Upload workers: {upload_workers}")
            for artifact in build.artifacts:
                click.echo(f"  {artifact.relative_path}")
            if uploadable_metadata:
                click.echo(
                    f"Security metadata: {len(uploadable_metadata)} file(s)"
                )
                for f in uploadable_metadata:
                    click.echo(f"  {f.name}")
            if file_skipped:
                click.echo(
                    f"Security metadata skipped (wrong type): {file_skipped}"
                )
            click.echo(
                f"\ndry-run: would upload "
                f"{len(build.artifacts)} artifact(s) "
                f"to {pulp_url}"
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

        pulp_labels: dict[str, str] = {
            "source_image": str(extract_result.image),
        }
        click.echo(f"Pulp labels: {json.dumps(pulp_labels)}")

        publish_result, uploaded, skipped, file_uploaded = _upload_to_pulp(
            ctx=ctx,
            config=config,
            build=build,
            uploadable_metadata=uploadable_metadata,
            pulp_url=pulp_url,
            pulp_file_repository=pulp_file_repository,
            pulp_repository=pulp_repository,
            pulp_labels=pulp_labels,
            requires_file_repository=requires_file_repository,
            file_skipped=file_skipped,
            upload_workers=upload_workers,
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
            "SECURITY_METADATA_SKIPPED",
            str(file_skipped),
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
