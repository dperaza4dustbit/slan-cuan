"""Generate OSV, CycloneDX SBOM, and VEX attestations."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import socket
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from uuid import uuid4

import click
import mmh3
from fath_cuan.ecosystems import _OSV_ECOSYSTEM, coordinate_from_purl
from fath_cuan.workflow import process_osv, process_vex

from slan_cuan import oci
from slan_cuan.models import (
    EXTRACT_RESULT_FILENAME,
    ExtractResult,
    GlobalContext,
    ImageReference,
)
from slan_cuan.utils import write_tekton_result

if TYPE_CHECKING:
    from fath_cuan.osidb import OsidbClient

_MURMURHASH_SEED = 42
_LOWER_64_MASK = 0xFFFF_FFFF_FFFF_FFFF
_ADVISORY_ID_RE = re.compile(r"^RHLW-\d{4}-[0-9a-f]{16}$")


def _is_build_index(index_data: dict) -> bool:
    """Check whether the index is a unified build-index."""
    return "purls" in index_data or "ecosystem" in index_data


def _derive_advisory_id(index_data: dict) -> str | None:
    """Derive a MurmurHash3-based advisory ID from the build index.

    Format: ``RHLW-{YYYY}-{lower64hex}``

    Returns None only when the index has no vulnerabilities (no advisory
    needed). All other derivation failures are hard errors.
    """
    if not index_data.get("vulns"):
        return None

    if _is_build_index(index_data):
        raw_eco = index_data.get("ecosystem", "").lower()
        ecosystem = _OSV_ECOSYSTEM.get(raw_eco)
        if not ecosystem:
            supported = ", ".join(sorted(_OSV_ECOSYSTEM))
            raise click.ClickException(
                f"build-index ecosystem '{raw_eco}' is not supported; "
                f"expected one of: {supported} "
                f"(defined in fath_cuan.ecosystems._OSV_ECOSYSTEM)"
            )
        primary = index_data.get("primaryPurl", "")
        if not primary:
            purls = index_data.get("purls", [])
            primary = purls[0] if purls else ""
        if not primary:
            raise click.ClickException(
                "Build index has vulns but no primaryPurl or purls;"
                " cannot derive advisory ID"
            )
        from packageurl import PackageURL

        try:
            parsed = PackageURL.from_string(primary)
        except ValueError as exc:
            raise click.ClickException(
                f"Build index has unparseable purl {primary!r};"
                f" cannot derive advisory ID"
            ) from exc
        name = (
            f"{parsed.namespace}:{parsed.name}"
            if parsed.namespace
            else parsed.name
        )
        version = parsed.version or ""
    else:
        primary_gav = index_data.get("primaryGav", "")
        if not primary_gav:
            raise click.ClickException(
                "Build index has vulns but no primaryGav;"
                " cannot derive advisory ID"
            )
        parts = primary_gav.split(":")
        if len(parts) != 3:
            raise click.ClickException(
                f"Build index has malformed GAV {primary_gav!r};"
                f" cannot derive advisory ID"
            )
        ecosystem = "Maven"
        name = f"{parts[0]}:{parts[1]}"
        version = parts[2]

    if not version:
        raise click.ClickException(
            "Build index has vulns but empty version; cannot derive advisory ID"
        )

    combo_key = f"{ecosystem}::{name}::{version}"
    hash128 = mmh3.hash128(combo_key, seed=_MURMURHASH_SEED)
    lower64 = hash128 & _LOWER_64_MASK
    click.echo(
        f"Advisory ID derivation: key={combo_key!r} "
        f"hash128={hash128:032x} lower64={lower64:016x}"
    )

    created = index_data.get("created", "")
    if created and len(created) >= 4:
        year = created[:4]
    else:
        from datetime import UTC, datetime

        year = str(datetime.now(UTC).year)

    return f"RHLW-{year}-{lower64:016x}"


def _validate_advisory_id(ctx, param, value):
    """Reject IDs that do not match the MurmurHash format."""
    if value:
        if not _ADVISORY_ID_RE.match(value):
            raise click.BadParameter(
                f"must match RHLW-YYYY-{{16 hex chars}}, got {value!r}"
            )
        if "/" in value or "\\" in value:
            raise click.BadParameter(
                f"must not contain path separators, got {value!r}"
            )
    return value


def _combo_key_summary(index_data: dict) -> list[str]:
    """Return a short description of the combo-key inputs for logging."""
    if _is_build_index(index_data):
        raw_eco = index_data.get("ecosystem", "").lower()
        eco = _OSV_ECOSYSTEM.get(raw_eco, raw_eco)
        primary = index_data.get(
            "primaryPurl",
            (index_data.get("purls") or [""])[0],
        )
        return [eco, primary]
    return ["Maven", index_data.get("primaryGav", "")]


def _warn_override_divergence(override_id: str, index_data: dict) -> None:
    """Warn when --advisory-id differs from the derived value."""
    derived = _derive_advisory_id(index_data)
    if derived and derived != override_id:
        parts = _combo_key_summary(index_data)
        click.echo(
            f"Warning: --advisory-id {override_id} overrides "
            f"derived {derived}; input was {parts}"
        )


_MAVEN_REPO_URL = os.environ.get(
    "SLAN_CUAN_REPOSITORY_URL_MAVEN",
    "https://packages.redhat.com/lightwell/java/remediated/",
)


def _read_sha256_sidecar(repo_dir: Path, relative_path: str) -> str | None:
    """Read SHA-256 from a checksum sidecar file (.sha256).

    ``repo_dir`` is the repository root (e.g.
    ``workdir/<deliverable_dir>/repository``) so the sidecar is looked
    up at the same Maven layout path as the artifact itself.
    """
    sidecar = repo_dir / f"{relative_path}.sha256"
    if sidecar.exists():
        content = sidecar.read_text().strip()
        if content:
            parts = content.split()
            return parts[0] if parts else None
    return None


def _generate_sbom(
    group_id: str,
    artifact_id: str,
    version: str,
    base_version: str,
    cve_ids: list[str],
    sha256_hash: str | None,
    timestamp: str,
) -> tuple[str, dict]:
    """Generate a per-artifact CycloneDX 1.7 SBOM.

    Returns (serial_number, sbom_dict) so the caller can pass the
    serial number to VEX generation for cross-referencing.
    """
    serial_number = f"urn:uuid:{uuid4()}"
    purl_qualified = (
        f"pkg:maven/{group_id}/{artifact_id}@{version}"
        f"?type=jar&repository_url={_MAVEN_REPO_URL}"
    )
    purl_bare = f"pkg:maven/{group_id}/{artifact_id}@{version}"
    ancestor_purl = f"pkg:maven/{group_id}/{artifact_id}@{base_version}"

    hashes = []
    if sha256_hash:
        hashes.append({"alg": "SHA-256", "content": sha256_hash})

    patches = []
    for cve_id in cve_ids:
        # LW- novel-fix IDs are not CVEs — skip them in pedigree
        # patches (no NVD entry, and type is not "backport").
        if cve_id.startswith("LW-"):
            continue
        patches.append(
            {
                "type": "backport",
                "resolves": [
                    {
                        "type": "security",
                        "id": cve_id,
                        "source": {
                            "name": "NVD",
                            "url": (f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
                        },
                    }
                ],
            }
        )

    component = {
        "type": "library",
        "bom-ref": purl_bare,
        "group": group_id,
        "name": artifact_id,
        "version": version,
        "purl": purl_qualified,
        "hashes": hashes,
        "licenses": [],
        "pedigree": {
            "ancestors": [
                {
                    "type": "library",
                    "group": group_id,
                    "name": artifact_id,
                    "version": base_version,
                    "purl": ancestor_purl,
                }
            ],
            "patches": patches,
            "notes": (
                f"Lightwell remediation: backported security fixes to "
                f"{artifact_id} {base_version}. Build {version}."
            ),
        },
    }

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {"timestamp": timestamp},
        "components": [component],
    }

    return serial_number, sbom


def _generate_sboms_from_index(
    index_data: dict,
    workdir: Path,
    output_dir: Path,
    timestamp: str,
) -> dict[str, str]:
    """Generate per-artifact CycloneDX SBOMs from build-index data.

    Returns a dict mapping PURL -> SBOM serialNumber for VEX
    cross-referencing.
    """
    sbom_serial_numbers: dict[str, str] = {}
    vulns = index_data.get("vulns", [])
    purls = index_data.get("purls", [])
    ecosystem = index_data.get("ecosystem", "").lower()

    if ecosystem != "maven" or not purls:
        return sbom_serial_numbers

    # Resolve the repository root for checksum sidecar lookup.
    # The extract stage writes artifacts under
    # <workdir>/<deliverable_dir>/repository/.
    repo_dir: Path | None = None
    result_path = workdir / EXTRACT_RESULT_FILENAME
    if result_path.exists():
        er = ExtractResult.from_file(result_path)
        candidate = workdir / er.deliverable_dir / "repository"
        if candidate.is_dir():
            repo_dir = candidate

    version_info = index_data.get("version", {})
    upstream_version = version_info.get("upstream", "")

    for purl in purls:
        try:
            coord = coordinate_from_purl(
                purl,
                ecosystem=ecosystem,
                upstream_version=upstream_version,
            )
        except ValueError:
            click.echo(f"Skipping unparseable purl {purl}")
            continue

        parts = coord.name.split(":")
        if len(parts) != 2:
            continue
        group_id, artifact_id = parts
        version = coord.version
        base_version = coord.base_version

        # Read SHA-256 from sidecar if available
        jar_relative = (
            f"{group_id.replace('.', '/')}/{artifact_id}"
            f"/{version}/{artifact_id}-{version}.jar"
        )
        sha256_hash = (
            _read_sha256_sidecar(repo_dir, jar_relative) if repo_dir else None
        )

        serial_number, sbom = _generate_sbom(
            group_id,
            artifact_id,
            version,
            base_version,
            vulns,
            sha256_hash,
            timestamp,
        )
        sbom_serial_numbers[purl] = serial_number

        # Write SBOM file (include groupId to avoid collisions)
        sbom_filename = f"{group_id}.{artifact_id}-{version}.bom.json"
        sbom_path = output_dir / sbom_filename
        click.echo(f"Writing SBOM to {sbom_path}")
        with open(sbom_path, "w") as f:
            json.dump(sbom, f, indent=2)

    return sbom_serial_numbers


def _generate_vex_from_index(
    index_data: dict,
    output_dir: Path,
    osidb_client: "OsidbClient | None",
    sbom_serial_numbers: dict[str, str],
    timestamp: str,
) -> None:
    """Generate per-CVE and multi-CVE CycloneDX VEX documents."""
    vex_result = process_vex(
        index_data,
        osidb_client=osidb_client,
        sbom_serial_numbers=sbom_serial_numbers,
    )

    # Write per-CVE VEX files
    for cve_id, doc in vex_result.per_cve:
        filename = f"{cve_id}-{timestamp}.bom.json"
        path = output_dir / filename
        click.echo(f"Writing per-CVE VEX to {path}")
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)

    # Write multi-CVE VEX file
    if vex_result.multi_cve:
        filename = f"{timestamp}.bom.json"
        path = output_dir / filename
        click.echo(f"Writing multi-CVE VEX to {path}")
        with open(path, "w") as f:
            json.dump(vex_result.multi_cve, f, indent=2)

    click.echo(
        f"VEX generation complete: {len(vex_result.per_cve)} per-CVE, "
        f"{'1' if vex_result.multi_cve else '0'} multi-CVE"
    )


_OSIDB_TOKEN_REQUEST_TIMEOUT = float(
    os.getenv("OSIDB_TOKEN_REQUEST_TIMEOUT", "10.0")
)
_OSIDB_TOKEN_MAX_RETRIES = int(os.getenv("OSIDB_TOKEN_MAX_RETRIES", "3"))
_OSIDB_TOKEN_RETRY_BACKOFF = float(os.getenv("OSIDB_TOKEN_RETRY_BACKOFF", "2.0"))


def _get_osidb_auth_token(
    api_url: str, principal: str, keytab: str, *, verbose: bool = False
) -> str:
    # Lazy imports: these come from the optional "kerberos" extra and must not
    # break importing this module (and hence the CLI) when it is not installed.
    import requests
    from krbticket import KrbTicket
    from requests_gssapi import OPTIONAL, HTTPSPNEGOAuth

    parsed = urlparse(api_url)
    token_url = f"{parsed.scheme}://{parsed.netloc}/auth/token"
    if verbose:
        click.echo(f"OSIDB token endpoint: {token_url}")
        try:
            addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        parsed.hostname,
                        parsed.port or 443,
                        type=socket.SOCK_STREAM,
                    )
                }
            )
            click.echo(f"OSIDB resolved addresses: {addresses}")
        except socket.gaierror as error:
            click.echo(f"OSIDB DNS resolution failed: {error}")

    # Use a file-based ccache — keyring/API ccache backends are not
    # available in Konflux container environments.
    ccache_path = os.path.join(tempfile.gettempdir(), "osidb_krb5cc")
    os.environ["KRB5CCNAME"] = f"FILE:{ccache_path}"
    if verbose:
        os.environ["KRB5_TRACE"] = "/dev/stderr"
        click.echo(f"Initializing Kerberos credentials for principal {principal}")
    KrbTicket.init(principal, keytab=keytab, ccache_name=ccache_path)

    session = requests.Session()
    auth = HTTPSPNEGOAuth(
        mutual_authentication=OPTIONAL, opportunistic_auth=False
    )

    last_error: Exception | None = None
    for attempt in range(1, _OSIDB_TOKEN_MAX_RETRIES + 1):
        try:
            response = session.get(
                token_url,
                timeout=_OSIDB_TOKEN_REQUEST_TIMEOUT,
                auth=auth,
            )
            response.raise_for_status()
            payload = response.json()
            token = payload.get("access")
            if not token:
                raise ValueError(
                    "OSIDB token response is missing the 'access' key "
                    f"(got keys: {sorted(payload)})"
                )
            return token
        except (requests.exceptions.RequestException, ValueError) as e:
            last_error = e
            click.echo(
                f"OSIDB token request attempt {attempt}/"
                f"{_OSIDB_TOKEN_MAX_RETRIES} failed "
                f"({type(e).__name__}): {e}"
            )
            if attempt < _OSIDB_TOKEN_MAX_RETRIES:
                time.sleep(_OSIDB_TOKEN_RETRY_BACKOFF * attempt)

    raise click.ClickException(
        f"Failed to retrieve OSIDB auth token after "
        f"{_OSIDB_TOKEN_MAX_RETRIES} attempts: {last_error}"
    )


@click.command()
@click.option(
    "--index-basedir",
    type=str,
    required=True,
    help="The base directory of the build index JSON file.",
)
@click.option(
    "--index-filename",
    type=str,
    required=True,
    help="The filename of the build index JSON file "
    "relative to the base directory.",
    default="gav-index.json",
)
@click.option(
    "--osidb-api-url",
    type=str,
    default="",
    show_default=True,
    help="The URL of the OSIDB API to use for authentication on OSIDB.",
)
@click.option(
    "--osidb-keytab",
    type=str,
    default="",
    show_default=True,
    help="The path to the OSIDB keytab file to use for authentication on OSIDB.",
)
@click.option(
    "--osidb-kerberos-principal",
    type=str,
    default="",
    show_default=True,
    help="The Kerberos principal to use for authentication on OSIDB.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to output the attestations to.",
)
@click.option(
    "--advisory-id",
    type=str,
    default="",
    show_default=True,
    callback=_validate_advisory_id,
    expose_value=True,
    is_eager=False,
    help=(
        "Optional advisory ID (e.g. RHLW-2026-00042) for per-release OSV records."
    ),
)
@click.option(
    "--workdir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to work in, which is the extracted directory.",
)
@click.pass_obj
def generate_security_metadata(
    ctx: GlobalContext,
    index_basedir: str,
    index_filename: str,
    osidb_api_url: str,
    osidb_keytab: str,
    osidb_kerberos_principal: str,
    output_dir: Path,
    advisory_id: str,
    workdir: Path,
) -> None:
    """Generate the OSV and VEX attestations for a given build index."""
    index_full_path = workdir / index_basedir / index_filename
    if not index_full_path.exists():
        click.echo(
            f"Index file not found at {index_full_path}, "
            "skipping security metadata generation."
        )
        return

    click.echo(f"Processing {index_full_path} to generate OSV and VEX...")
    with open(index_full_path, "r") as f:
        index_data = json.load(f)

    vulns = index_data.get("vulns", [])
    osidb_client = None
    if not vulns:
        click.echo(
            "No vulnerabilities found in index, skipping OSIDB client setup."
        )
    elif osidb_keytab and Path(osidb_keytab).is_file():
        # Lazy import: fath_cuan.osidb only exists in newer fath-cuan and is
        # only needed when a keytab is supplied.
        from fath_cuan.osidb import OsidbClient

        click.echo(
            f"Creating OSIDB client on {osidb_api_url} "
            f"with keytab file {osidb_keytab}"
        )
        auth_token = _get_osidb_auth_token(
            osidb_api_url,
            osidb_kerberos_principal,
            osidb_keytab,
            verbose=ctx.verbose,
        )
        # OsidbClient appends /osidb/api/v1/... paths itself, so pass only
        # the base URL (scheme + host) — not the full API path.
        _parsed = urlparse(osidb_api_url)
        osidb_base_url = f"{_parsed.scheme}://{_parsed.netloc}"
        osidb_client = OsidbClient(base_url=osidb_base_url, token=auth_token)
        if not osidb_client.available:
            click.echo("Failed to create OSIDB client, exiting.")
            raise click.Abort()
    else:
        click.echo("No OSIDB keytab file found, skipping OSIDB fetching.")

    if not advisory_id:
        advisory_id = _derive_advisory_id(index_data)
        if advisory_id and not _ADVISORY_ID_RE.match(advisory_id):
            raise click.ClickException(
                f"Derived advisory ID is malformed: {advisory_id!r}"
            )
    else:
        _warn_override_divergence(advisory_id, index_data)
    if advisory_id:
        index_data["advisory_id"] = advisory_id

    osv_records = process_osv(index_data, osidb_client=osidb_client)
    output_dir.mkdir(parents=True, exist_ok=True)
    for record in osv_records:
        osv_output_path = output_dir / f"{record['id']}.json"
        click.echo(f"Writing OSV record to {osv_output_path}")
        with open(osv_output_path, "w") as f:
            json.dump(record, f, indent=2)

    # Generate per-artifact CycloneDX SBOMs and VEX (build-index only,
    # gated on vulns: clean builds have no pedigree patches to document).
    sbom_serial_numbers: dict[str, str] = {}
    if _is_build_index(index_data) and index_data.get("vulns"):
        from datetime import UTC, datetime

        ts_now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        sbom_serial_numbers = _generate_sboms_from_index(
            index_data,
            workdir,
            output_dir,
            ts_now,
        )

        _generate_vex_from_index(
            index_data,
            output_dir,
            osidb_client,
            sbom_serial_numbers,
            ts_now,
        )

    # Save the updated extract result
    result = ExtractResult.from_file(workdir / EXTRACT_RESULT_FILENAME)
    result = dataclasses.replace(
        result, security_metadata_dir=str(output_dir.relative_to(workdir))
    )
    result.save(workdir / EXTRACT_RESULT_FILENAME)

    write_tekton_result(
        ctx.tekton_results_dir,
        "SECURITY_METADATA_DIR",
        str(output_dir),
    )
    click.echo("Security metadata generation completed successfully.")


def _build_osidb_client(
    osidb_api_url: str,
    osidb_keytab: str,
    osidb_kerberos_principal: str,
    *,
    verbose: bool = False,
) -> OsidbClient | None:
    """Build an OSIDB client, or None when no keytab is available.

    Unlike the per-index command, this does not gate on the presence of
    vulnerabilities in an index: the snapshot command builds the client
    once, up front, before any index has been read.
    """
    if not (osidb_keytab and Path(osidb_keytab).is_file()):
        click.echo("No OSIDB keytab file found, skipping OSIDB fetching.")
        return None

    # Lazy import: fath_cuan.osidb only exists in newer fath-cuan and is
    # only needed when a keytab is supplied.
    from fath_cuan.osidb import OsidbClient

    click.echo(
        f"Creating OSIDB client on {osidb_api_url} "
        f"with keytab file {osidb_keytab}"
    )
    auth_token = _get_osidb_auth_token(
        osidb_api_url,
        osidb_kerberos_principal,
        osidb_keytab,
        verbose=verbose,
    )
    # OsidbClient appends /osidb/api/v1/... paths itself, so pass only the
    # base URL (scheme + host) — not the full API path.
    _parsed = urlparse(osidb_api_url)
    osidb_base_url = f"{_parsed.scheme}://{_parsed.netloc}"
    osidb_client = OsidbClient(base_url=osidb_base_url, token=auth_token)
    if not osidb_client.available:
        click.echo("Failed to create OSIDB client, exiting.")
        raise click.Abort()
    return osidb_client


def _generate_osv_for_index(
    index_full_path: Path,
    output_dir: Path,
    osidb_client: OsidbClient | None,
) -> int:
    """Generate OSV records for a single build index; return the count.

    Writes one JSON file per record to output_dir. Unlike the per-index
    command, this does not touch extract-result.json — the snapshot flow
    (e.g. the calunga Python pipeline) has no such file.
    """
    click.echo(f"Processing {index_full_path} to generate OSV...")
    with open(index_full_path, "r") as f:
        index_data = json.load(f)

    advisory_id = _derive_advisory_id(index_data)
    if advisory_id:
        index_data["advisory_id"] = advisory_id

    osv_records = process_osv(index_data, osidb_client=osidb_client)
    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for record in osv_records:
        osv_output_path = output_dir / f"{record['id']}.json"
        click.echo(f"Writing OSV record to {osv_output_path}")
        with open(osv_output_path, "w") as f:
            json.dump(record, f, indent=2)
        count += 1
    return count


@click.command(name="generate-security-metadata-from-snapshot")
@click.option(
    "--snapshot-path",
    type=click.Path(path_type=Path),
    required=True,
    help="Path to the reduced snapshot spec JSON listing component images.",
)
@click.option(
    "--workdir",
    type=click.Path(path_type=Path),
    required=True,
    help="Working directory beneath which build-index artifacts are pulled.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to output the OSV documents to.",
)
@click.option(
    "--build-index-media-type",
    type=str,
    default="application/vnd.lightwell.build-index.v1+json",
    show_default=True,
    help="OCI artifact type used to discover the build-index referrer.",
)
@click.option(
    "--index-basedir",
    type=str,
    default="build-index",
    show_default=True,
    help="Directory (under workdir) the build index is pulled into.",
)
@click.option(
    "--index-filename",
    type=str,
    default="build-index.json",
    show_default=True,
    help="Filename of the build index within the index base directory.",
)
@click.option(
    "--osidb-api-url",
    type=str,
    default="",
    show_default=True,
    help="The URL of the OSIDB API to use for authentication on OSIDB.",
)
@click.option(
    "--osidb-keytab",
    type=str,
    default="",
    show_default=True,
    help="The path to the OSIDB keytab file to use for OSIDB auth.",
)
@click.option(
    "--osidb-kerberos-principal",
    type=str,
    default="",
    show_default=True,
    help="The Kerberos principal to use for authentication on OSIDB.",
)
@click.option(
    "--registry-config",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional oras registry auth file for discover/pull.",
)
@click.pass_obj
def generate_security_metadata_from_snapshot(
    ctx: GlobalContext,
    snapshot_path: Path,
    workdir: Path,
    output_dir: Path,
    build_index_media_type: str,
    index_basedir: str,
    index_filename: str,
    osidb_api_url: str,
    osidb_keytab: str,
    osidb_kerberos_principal: str,
    registry_config: Path | None,
) -> None:
    """Generate OSV metadata for every component image in a snapshot.

    For each component image, the build-index OCI referrer is discovered
    and pulled, then OSV records are generated. A single OSIDB client is
    built up front and reused across every component image.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    index_dir = workdir / index_basedir
    index_dir.mkdir(parents=True, exist_ok=True)

    with open(snapshot_path, "r") as f:
        snapshot = json.load(f)
    images = [c["containerImage"] for c in snapshot.get("components", [])]

    osidb_client = _build_osidb_client(
        osidb_api_url,
        osidb_keytab,
        osidb_kerberos_principal,
        verbose=ctx.verbose,
    )

    referrer_count = 0
    for image in images:
        image_ref = ImageReference.parse(image)
        click.echo(f"Discovering build-index referrer on {image_ref}")
        referrers = oci.discover(
            image,
            build_index_media_type,
            auth_file=registry_config,
            verbose=ctx.verbose,
        )
        if not referrers:
            click.echo(f"No build-index referrer on {image_ref}; skipping.")
            continue

        referrer_count += 1
        referrer = ImageReference(
            registry=image_ref.registry,
            repository=image_ref.repository,
            tag=None,
            digest=referrers[0]["digest"],
        )
        oci.pull(
            referrer,
            index_dir,
            auth_file=registry_config,
            verbose=ctx.verbose,
        )
        _generate_osv_for_index(
            index_dir / index_filename, output_dir, osidb_client
        )

    if referrer_count == 0:
        click.echo(
            "WARNING: no build-index referrer found on ANY component image.",
            err=True,
        )
        click.echo(
            "WARNING: verify the build-side 'fath-cuan index create "
            "--attach-to' step ran and attached a referrer of type "
            f"{build_index_media_type}.",
            err=True,
        )

    write_tekton_result(
        ctx.tekton_results_dir,
        "SECURITY_METADATA_DIR",
        str(output_dir),
    )
    click.echo(f"Generated OSV metadata for {referrer_count} component(s).")
