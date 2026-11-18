"""Generate OSV, CycloneDX SBOM, and VEX attestations."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import socket
import tempfile
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from uuid import UUID, uuid4, uuid5

import click
import mmh3
from fath_cuan.ecosystems import _OSV_ECOSYSTEM, coordinate_from_purl
from fath_cuan.index_builder import migrate_document
from fath_cuan.workflow import process_osv, process_vex

from slan_cuan import oci
from slan_cuan.models import (
    EXTRACT_RESULT_FILENAME,
    EXTRACT_UPSTREAM_SBOMS_DIRNAME,
    ExtractResult,
    GlobalContext,
    ImageReference,
)
from slan_cuan.utils import write_tekton_result

if TYPE_CHECKING:
    from fath_cuan.osidb import OsidbClient

_MURMURHASH_SEED = 42
_LOWER_64_MASK = 0xFFFF_FFFF_FFFF_FFFF
_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ADVISORY_ID_RE = re.compile(r"^RHLW-\d{4}-[0-9a-f]{16}$")


def _is_build_index(index_data: dict) -> bool:
    """Check whether the index is a unified build-index."""
    return "purls" in index_data or "ecosystem" in index_data


def _index_for_sbom_and_vex(index_data: dict) -> dict | None:
    """Return a build-index for SBOM/VEX generation, or None if impossible.

    SBOM and VEX generation work on the unified build-index (``purls`` /
    ``ecosystem``). Production PNC builds still attach the legacy gav-index
    (``primaryGav`` / ``gavs``); it is converted with fath-cuan's
    ``migrate_document`` (canonical ``pkg:maven`` purls, decomposed version,
    same ``vulns`` and ``created``) instead of silently skipping VEX. OSV
    generation keeps using the original index.
    """
    if _is_build_index(index_data):
        return index_data
    if "primaryGav" not in index_data:
        click.echo(
            "WARNING: index is neither a build-index (purls/ecosystem) nor a "
            "legacy gav-index (primaryGav); no SBOM or VEX generated.",
            err=True,
        )
        return None
    try:
        migrated = migrate_document(index_data)
    except (ValueError, TypeError, KeyError) as e:
        click.echo(
            f"WARNING: legacy gav-index could not be converted to a "
            f"build-index ({e}); no SBOM or VEX generated.",
            err=True,
        )
        return None
    click.echo(
        f"Legacy gav-index converted to a build-index for SBOM/VEX "
        f"generation ({len(migrated.get('purls', []))} module(s))."
    )
    return migrated


def _primary_module_index(build_index: dict) -> dict:
    """Restrict a build-index to its primary (fixed) module.

    A build-index lists every module the build produced, but only the
    primary one carries the security fix: the OSV advisory has a single
    ``affected`` entry for it. Other modules (parent POMs, build companions)
    must not get VEX statements or an enriched SBOM claiming the fix, so
    both use ``primaryPurl`` only.
    """
    primary = build_index.get("primaryPurl")
    if not primary:
        return build_index
    return {**build_index, "purls": [primary], "extraPurls": []}


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


_DEFAULT_SUPPLIER = {"name": "Red Hat Lightwell"}

_MAVEN_REPO_URL_REMEDIATED = os.environ.get(
    "SLAN_CUAN_REPOSITORY_URL_MAVEN_REMEDIATED",
    "https://packages.redhat.com/lightwell/java/remediated/",
)
_MAVEN_REPO_URL_VALIDATED = os.environ.get(
    "SLAN_CUAN_REPOSITORY_URL_MAVEN_VALIDATED",
    "https://packages.redhat.com/lightwell/java/validated/",
)
_MAVEN_REPO_URL_PREDISCLOSURE = os.environ.get(
    "SLAN_CUAN_REPOSITORY_URL_MAVEN_PREDISCLOSURE",
    "https://packages.redhat.com/lightwell/java/predisclosure/",
)


# Namespace UUID for Lightwell SBOM serial numbers (uuid5 domain separation).
_SBOM_SERIAL_NS = UUID("b8f5a1c2-7d3e-4f9a-a6b1-2c8d9e0f1a3b")


def _content_derived_serial(sbom: dict) -> str:
    """Derive a deterministic serial number from SBOM semantic content.

    Hashes the artifact-semantic fields (component identity, hashes,
    licenses, pedigree, and PURL including ``repository_url``) so that
    identical content produces an identical serial. Excludes build-
    identity metadata (serialNumber, timestamp, metadata.version) so a
    pure re-run of the same build yields the same serial.

    Note: the PURL embeds ``repository_url``, so identical content
    published to different repos gets different serials. This is
    intentional — the serial is scoped to one distribution target.
    Only ``components[0]`` contributes to the hash (per-artifact SBOMs
    have exactly one component).
    """
    components = sbom.get("components", [])
    if not components:
        return f"urn:uuid:{uuid4()}"

    comp = components[0]
    # Collect semantic fields in a stable order
    semantic = {
        "group": comp.get("group", ""),
        "name": comp.get("name", ""),
        "version": comp.get("version", ""),
        "purl": comp.get("purl", ""),
        "hashes": comp.get("hashes", []),
        "licenses": comp.get("licenses", []),
        "pedigree": comp.get("pedigree", {}),
    }
    canonical = json.dumps(semantic, sort_keys=True, separators=(",", ":"))
    digest = sha256(canonical.encode()).hexdigest()
    return f"urn:uuid:{uuid5(_SBOM_SERIAL_NS, digest)}"


def _resolve_repo_url(cve_ids: list[str], explicit_url: str | None) -> str:
    """Determine the repository URL for the SBOM PURL qualifier.

    When *explicit_url* is provided (from ``--repository-url``), it is
    used directly. Otherwise the URL is inferred from the vuln list.
    """
    if explicit_url:
        return explicit_url
    has_lw = any(cid.startswith("LW-") for cid in cve_ids)
    has_cves = any(not cid.startswith("LW-") for cid in cve_ids)
    if has_lw:
        return _MAVEN_REPO_URL_PREDISCLOSURE
    elif has_cves:
        return _MAVEN_REPO_URL_REMEDIATED
    return _MAVEN_REPO_URL_VALIDATED


def _build_pedigree(
    group_id: str,
    artifact_id: str,
    version: str,
    base_version: str,
    cve_ids: list[str],
) -> dict:
    """Build the CycloneDX pedigree object (ancestors, patches, notes)."""
    ancestor_purl = f"pkg:maven/{group_id}/{artifact_id}@{base_version}"
    has_lw = any(cid.startswith("LW-") for cid in cve_ids)
    has_cves = any(not cid.startswith("LW-") for cid in cve_ids)

    patches = []
    for cve_id in cve_ids:
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
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        },
                    }
                ],
            }
        )

    if has_lw:
        notes = (
            f"Lightwell novel fix: embargoed security fixes to "
            f"{artifact_id} {base_version}. Build {version}."
        )
    elif has_cves:
        notes = (
            f"Lightwell remediation: backported security fixes to "
            f"{artifact_id} {base_version}. Build {version}."
        )
    else:
        notes = (
            f"Lightwell validated build of "
            f"{artifact_id} {base_version}. Build {version}."
        )

    return {
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
        "notes": notes,
    }


def _merge_pedigree(existing: object, ours: dict) -> dict:
    """Merge the Lightwell pedigree into the upstream (PNC) pedigree.

    PNC already records ``ancestors`` (with the exact ``?type=jar`` purl);
    those are kept. Lightwell adds the CVE ``patches`` it resolves (skipping
    any already listed) and its ``notes``. All other upstream pedigree
    fields are preserved.
    """
    if not isinstance(existing, dict) or not existing:
        return ours
    merged = dict(existing)
    if not merged.get("ancestors"):
        merged["ancestors"] = ours["ancestors"]
    patches = [p for p in merged.get("patches") or [] if isinstance(p, dict)]
    resolved = {
        r.get("id")
        for p in patches
        for r in p.get("resolves") or []
        if isinstance(r, dict)
    }
    patches += [
        p for p in ours["patches"] if p["resolves"][0]["id"] not in resolved
    ]
    merged["patches"] = patches
    upstream_notes = merged.get("notes")
    if isinstance(upstream_notes, str) and upstream_notes.strip():
        if ours["notes"] not in upstream_notes:
            merged["notes"] = f"{upstream_notes}\n\n{ours['notes']}"
    else:
        merged["notes"] = ours["notes"]
    return merged


def _load_upstream_sbom(
    upstream_sboms_dir: Path,
    group_id: str,
    artifact_id: str,
    version: str,
) -> tuple[dict | None, Path | None]:
    """Load an upstream SBOM from the upstream-sboms directory.

    Searches for ``.bom.json`` (PNC convention) then ``.cyclonedx.json``
    (legacy) at the GAV-relative path. Returns ``(parsed_dict,
    source_path)`` or ``(None, None)`` when no upstream SBOM is found.
    """
    gav_dir = (
        upstream_sboms_dir / group_id.replace(".", "/") / artifact_id / version
    )
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


def _enrich_sbom(
    upstream_sbom: dict | None,
    group_id: str,
    artifact_id: str,
    version: str,
    pedigree: dict,
    repo_url: str,
    purl_qualified: str,
    serial_number: str,
    timestamp: str,
) -> dict:
    """Enrich an upstream SBOM or generate a minimal one from scratch.

    When *upstream_sbom* has components, mutates it in place: merges the
    Lightwell ``pedigree`` into the upstream one (see ``_merge_pedigree``),
    updates the PURL with ``repository_url``, and sets ``serialNumber``.
    All other upstream fields are preserved.

    When no upstream SBOM is available (or its components list is
    empty/malformed), generates a minimal CycloneDX 1.7 SBOM.
    """
    from packageurl import PackageURL

    components = upstream_sbom.get("components", []) if upstream_sbom else []

    if components and isinstance(components[0], dict):
        comp = components[0]

        # Derive enriched PURL from upstream, preserving type/classifier.
        upstream_purl_str = comp.get("purl", "")
        try:
            base_purl = PackageURL.from_string(upstream_purl_str)
            q = dict(base_purl.qualifiers or {})
            q["repository_url"] = repo_url
            enriched_purl = PackageURL(
                type=base_purl.type,
                namespace=base_purl.namespace,
                name=base_purl.name,
                version=base_purl.version,
                qualifiers=q,
                subpath=base_purl.subpath,
            ).to_string()
        except ValueError:
            enriched_purl = purl_qualified

        comp["purl"] = enriched_purl
        comp["pedigree"] = _merge_pedigree(comp.get("pedigree"), pedigree)

        upstream_sbom["serialNumber"] = serial_number
        if "metadata" not in upstream_sbom:
            upstream_sbom["metadata"] = {}
        if not upstream_sbom["metadata"].get("timestamp"):
            upstream_sbom["metadata"]["timestamp"] = timestamp
        if not upstream_sbom["metadata"].get("supplier"):
            upstream_sbom["metadata"]["supplier"] = _DEFAULT_SUPPLIER

        return upstream_sbom

    # Fallback: generate a minimal SBOM from scratch.
    purl_bare = f"pkg:maven/{group_id}/{artifact_id}@{version}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "supplier": _DEFAULT_SUPPLIER,
        },
        "components": [
            {
                "type": "library",
                "bom-ref": purl_bare,
                "group": group_id,
                "name": artifact_id,
                "version": version,
                "purl": purl_qualified,
                "hashes": [],
                "licenses": [],
                "pedigree": pedigree,
            }
        ],
    }


def _generate_sboms_from_index(
    index_data: dict,
    output_dir: Path,
    timestamp: str,
    upstream_sboms_dir: Path | None = None,
    explicit_repo_url: str | None = None,
    sbom_components: dict[str, dict] | None = None,
) -> dict[str, str]:
    """Generate per-artifact enriched CycloneDX SBOMs from build-index data.

    Reads upstream SBOMs from *upstream_sboms_dir* (populated by the
    extract task), enriches them with pedigree data, and writes the
    enriched SBOMs to ``output_dir / "enriched-sboms" / {GAV path}``.

    When no upstream SBOM exists for an artifact, generates a minimal
    SBOM from scratch.

    Returns a dict mapping each SBOM's exact ``bom-ref`` (e.g. PNC's
    ``pkg:maven/...@v?type=jar``) -> SBOM serialNumber for VEX
    cross-referencing, so the VEX BOM-Link fragment matches the SBOM. When
    *sbom_components* is given, it is filled with the same keys -> the SBOM
    subject (``components[0]``), whose identity (purl with
    ``repository_url`` and ``type``) becomes the VEX ``metadata.component``.
    """
    sbom_serial_numbers: dict[str, str] = {}
    vulns = index_data.get("vulns", [])
    purls = index_data.get("purls", [])
    ecosystem = index_data.get("ecosystem", "").lower()

    if ecosystem != "maven" or not purls:
        return sbom_serial_numbers

    enriched_root = output_dir / "enriched-sboms"
    enriched_root.mkdir(parents=True, exist_ok=True)

    version_info = index_data.get("version", {})
    upstream_version = version_info.get("upstream", "")

    from packageurl import PackageURL

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

        # Guard against path traversal in GAV components.
        for label, value in (
            ("group_id", group_id),
            ("artifact_id", artifact_id),
            ("version", version),
        ):
            if "/" in value or "\\" in value or ".." in value:
                raise click.ClickException(
                    f"{label} contains unsafe characters: {value!r}"
                )

        repo_url = _resolve_repo_url(vulns, explicit_repo_url)
        pedigree = _build_pedigree(
            group_id, artifact_id, version, base_version, vulns
        )

        # Load upstream SBOM if available.
        upstream_sbom: dict | None = None
        if upstream_sboms_dir and upstream_sboms_dir.is_dir():
            upstream_sbom, _ = _load_upstream_sbom(
                upstream_sboms_dir, group_id, artifact_id, version
            )

        # Build the qualified PURL. Default to type=jar; _enrich_sbom
        # preserves the upstream type/classifier when available.
        purl_qualified = PackageURL(
            type="maven",
            namespace=group_id,
            name=artifact_id,
            version=version,
            qualifiers={"type": "jar", "repository_url": repo_url},
        ).to_string()

        # Enrich the upstream SBOM (or generate from scratch).
        enriched = _enrich_sbom(
            upstream_sbom,
            group_id,
            artifact_id,
            version,
            pedigree,
            repo_url,
            purl_qualified,
            "",  # serial_number placeholder — derived below
            timestamp,
        )

        serial_number = _content_derived_serial(enriched)
        enriched["serialNumber"] = serial_number

        purl_bare = f"pkg:maven/{group_id}/{artifact_id}@{version}"
        # Key by the SBOM's exact bom-ref so the VEX BOM-Link fragment
        # resolves inside the SBOM (PNC uses the ?type=jar form). An upstream
        # SBOM without a bom-ref gets the bare purl as its bom-ref.
        subject = enriched["components"][0]
        bom_ref = subject.setdefault("bom-ref", purl_bare)
        sbom_serial_numbers[bom_ref] = serial_number
        if sbom_components is not None:
            sbom_components[bom_ref] = subject

        # Write enriched SBOM at GAV-relative path.
        gav_rel = (
            Path(group_id.replace(".", "/"))
            / artifact_id
            / version
            / f"{artifact_id}-{version}.bom.json"
        )
        sbom_path = enriched_root / gav_rel

        # Path-traversal guard on the output path.
        try:
            sbom_path.resolve().relative_to(enriched_root.resolve())
        except ValueError:
            raise click.ClickException(
                f"Enriched SBOM path escapes output tree: {gav_rel}"
            ) from None

        sbom_path.parent.mkdir(parents=True, exist_ok=True)
        click.echo(f"Writing enriched SBOM to {sbom_path}")
        with open(sbom_path, "w") as f:
            json.dump(enriched, f, indent=2)

    return sbom_serial_numbers


def _generate_vex_from_index(
    index_data: dict,
    output_dir: Path,
    osidb_client: "OsidbClient | None",
    sbom_serial_numbers: dict[str, str],
    timestamp: str,
    sbom_components: dict[str, dict] | None = None,
) -> None:
    """Generate the CycloneDX VEX document for the build's primary module.

    *sbom_components* (SBOM subjects keyed like *sbom_serial_numbers*) makes
    each VEX ``metadata.component`` byte-identical to its SBOM's
    ``components[0]`` identity, purl with ``repository_url`` and ``type``.
    """
    vex_result = process_vex(
        index_data,
        osidb_client=osidb_client,
        sbom_serial_numbers=sbom_serial_numbers,
        sbom_components=sbom_components,
    )

    # Exactly one VEX document per module (agreed Sonatype format): a single
    # CVE -> <CVE-ID>-<datetime>.bom.json; several CVEs -> one
    # <datetime>.bom.json holding all of them, never per-CVE files beside it
    # (that would publish every statement twice). For an LW- build the
    # LW- statement therefore always travels with its CVEs.
    multi_vulns = (vex_result.multi_cve or {}).get("vulnerabilities") or []
    if len(multi_vulns) >= 2:
        filename = f"{timestamp}.bom.json"
        document = vex_result.multi_cve
    elif len(vex_result.per_cve) == 1:
        cve_id, document = vex_result.per_cve[0]
        filename = f"{cve_id}-{timestamp}.bom.json"
    elif not vex_result.per_cve:
        click.echo("No VEX statements generated (nothing to publish).")
        return
    else:
        raise click.ClickException(
            f"Unexpected VEX result: {len(vex_result.per_cve)} per-CVE "
            f"documents without a multi-CVE document; refusing to publish "
            f"them as separate files."
        )
    statements = len(document.get("vulnerabilities") or [])
    path = output_dir / filename
    click.echo(f"Writing VEX ({statements} statement(s)) to {path}")
    with open(path, "w") as f:
        json.dump(document, f, indent=2)
    click.echo(f"VEX generation complete: 1 document, {statements} statement(s)")


def _normalize_build_timestamp(created: object) -> str:
    """Normalize a build-index ``created`` value to ``YYYY-MM-DDTHH:MM:SSZ``.

    The result is used both for VEX/SBOM filenames and (via the index
    handed to fath-cuan) for VEX ``published``/``updated``, so the two
    always agree. Offsets are converted to UTC; a naive value is taken
    as UTC. Falls back to the current UTC time when ``created`` is absent.
    """
    if not created:
        return datetime.now(UTC).strftime(_TIMESTAMP_FMT)
    if not isinstance(created, str):
        raise click.ClickException(
            f"Build index 'created' is not a string: {created!r}"
        )
    try:
        parsed = datetime.fromisoformat(created)
    except ValueError:
        raise click.ClickException(
            f"Build index 'created' is not ISO-8601: {created!r}"
        ) from None
    if "T" not in created and " " not in created:
        click.echo(
            f"WARNING: build index 'created' ({created!r}) has no time "
            "component; VEX published/updated will be midnight UTC.",
            err=True,
        )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime(_TIMESTAMP_FMT)


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
@click.option(
    "--repository-url",
    type=str,
    default="",
    show_default=True,
    help=(
        "Distribution target URL for the SBOM PURL repository_url qualifier. "
        "When set, overrides the vuln-based inference. Typically the Pulp "
        "Maven distribution URL (e.g. https://packages.redhat.com/lightwell/java/remediated/)."
    ),
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
    repository_url: str,
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

    # Generate the enriched SBOM (all builds) and VEX (gated on vulns — clean
    # builds have no vulnerabilities to declare) from a build-index; a legacy
    # gav-index is converted first. Both cover only the primary module: the
    # fix is in the primary module, and the other modules of a multi-module
    # build are dependents that must not claim it (they keep the PNC SBOM).
    sbom_serial_numbers: dict[str, str] = {}
    sbom_components: dict[str, dict] = {}
    build_index = _index_for_sbom_and_vex(index_data)
    if build_index is not None:
        # Pin to build provenance timestamp when available; fall back to now.
        # Normalize once and feed the same value to fath-cuan so the VEX
        # filename and its published/updated fields cannot diverge.
        ts_now = _normalize_build_timestamp(build_index.get("created"))
        primary_index = _primary_module_index(build_index)

        # Upstream SBOMs are captured by the extract task into
        # workdir/upstream-sboms/. This directory may not exist
        # (non-maven, or a deliverable without PNC SBOMs).
        upstream_sboms_dir = workdir / EXTRACT_UPSTREAM_SBOMS_DIRNAME
        sbom_serial_numbers = _generate_sboms_from_index(
            primary_index,
            output_dir,
            ts_now,
            upstream_sboms_dir=upstream_sboms_dir,
            explicit_repo_url=repository_url or None,
            sbom_components=sbom_components,
        )

        if build_index.get("vulns"):
            _generate_vex_from_index(
                {**primary_index, "created": ts_now},
                output_dir,
                osidb_client,
                sbom_serial_numbers,
                ts_now,
                sbom_components=sbom_components,
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
) -> OsidbClient:
    """Build an OSIDB client; fails closed when the keytab is unusable.

    Unlike the per-index command, this does not gate on the presence of
    vulnerabilities in an index: the snapshot command builds the client
    once, up front, before any index has been read. OSIDB enrichment is
    mandatory for this flow, so a missing or unreadable keytab aborts the
    run instead of silently producing un-enriched OSV records.
    """
    if (
        not osidb_keytab
        or not Path(osidb_keytab).is_file()
        or not os.access(osidb_keytab, os.R_OK)
    ):
        raise click.ClickException(
            f"OSIDB keytab {osidb_keytab!r} is missing or not readable; "
            "refusing to generate OSV metadata without OSIDB enrichment."
        )

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
    osidb_client: OsidbClient,
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
