"""Extract subcommand for pulling artifacts from PNC container images."""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import click

from slan_cuan.models import (
    EXTRACT_ATTACHMENTS_DIRNAME,
    EXTRACT_METADATA_DIRNAME,
    EXTRACT_RESULT_FILENAME,
    ExtractResult,
    GlobalContext,
    ImageReference,
    OCIManifest,
)
from slan_cuan.oci import OrasError, discover, manifest_fetch, pull
from slan_cuan.utils import write_tekton_result


def _deduplicate_referrers(
    referrers: list[dict],
    art_type: str,
    img_ref: ImageReference,
    registry_auth_file: Path | None,
    verbose: bool,
) -> dict | None:
    """Resolve referrers to a single one if layer blobs are identical.

    Returns the selected referrer descriptor, or None if no valid referrers
    exist. Raises click.ClickException if distinct artifact blob sets exist.
    """
    valid_referrers = [r for r in referrers if r.get("digest")]
    if not valid_referrers:
        return None

    # Fast path 1: Only 1 referrer
    if len(valid_referrers) == 1:
        return valid_referrers[0]

    # Fast path 2: All referrers point to the exact same manifest digest
    unique_manifest_digests = {r["digest"]: r for r in valid_referrers}
    if len(unique_manifest_digests) == 1:
        if verbose:
            click.echo(
                f"  Found {len(valid_referrers)} referrers for '{art_type}' "
                f"with identical manifest digest; deduplicating."
            )
        return next(iter(unique_manifest_digests.values()))

    # Slow path: Fetch raw manifests and compare layer/config digests
    blob_digests_seen: dict[tuple[str, ...], dict] = {}
    for ref_digest, ref_desc in unique_manifest_digests.items():
        ref_img = ImageReference(
            registry=img_ref.registry,
            repository=img_ref.repository,
            tag=None,
            digest=ref_digest,
        )
        ref_manifest_raw = manifest_fetch(
            ref_img,
            auth_file=registry_auth_file,
            verbose=verbose,
        )

        layers_raw = ref_manifest_raw.get("layers", [])
        if isinstance(layers_raw, list) and layers_raw:
            layer_digests = tuple(
                str(layer["digest"])
                for layer in layers_raw
                if isinstance(layer, dict) and "digest" in layer
            )
        else:
            # For 0-layer artifacts or index manifests, fall back to
            # config digest or raw manifest digest
            config_digest = (
                ref_manifest_raw.get("config", {}).get("digest")
                if isinstance(ref_manifest_raw.get("config"), dict)
                else None
            )
            layer_digests = (config_digest or ref_digest,)

        if layer_digests not in blob_digests_seen:
            blob_digests_seen[layer_digests] = ref_desc

    if len(blob_digests_seen) > 1:
        raise click.ClickException(
            f"Expected at most 1 unique artifact for type '{art_type}', "
            f"found {len(blob_digests_seen)} distinct blob sets across "
            f"{len(valid_referrers)} referrers."
        )

    if verbose:
        click.echo(
            f"  Found {len(valid_referrers)} referrers for '{art_type}' "
            f"with identical layer blobs; deduplicating."
        )
    return next(iter(blob_digests_seen.values()))


@click.command()
@click.option(
    "--image",
    required=True,
    type=str,
    help="Container image reference to extract artifacts from.",
)
@click.option(
    "--output-dir",
    required=True,
    type=click.Path(path_type=Path),
    help="Directory to extract artifacts to.",
)
@click.option(
    "--registry-auth-file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to container registry authentication file.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing output directory.",
)
@click.option(
    "--discover-attachments",
    multiple=True,
    envvar="SLAN_CUAN_EXTRACT_DISCOVER_ATTACHMENTS",
    help="OCI artifact-type(s) to discover and pull as attachments. "
    "Repeatable; env var accepts comma-separated values.",
)
@click.pass_obj
def extract(
    ctx: GlobalContext,
    image: str,
    output_dir: Path,
    registry_auth_file: Path | None,
    force: bool,
    discover_attachments: tuple[str, ...],
) -> None:
    """Extract artifacts from a PNC container image."""
    try:
        # Parse image reference
        img_ref = ImageReference.parse(image)
        if ctx.verbose:
            click.echo(f"Parsed image reference: {img_ref}")

        # Normalize discover_attachments: split comma-separated env var values
        artifact_types: tuple[str, ...] = tuple(
            t.strip()
            for raw in discover_attachments
            for t in raw.split(",")
            if t.strip()
        )

        # Validate/create output directory
        if output_dir.exists():
            if not force:
                raise click.ClickException(
                    f"Output directory {output_dir} already exists. "
                    "Use --force to overwrite."
                )
            if ctx.verbose:
                click.echo(f"Removing existing directory: {output_dir}")
            shutil.rmtree(output_dir)

        # Fetch manifest for metadata
        if ctx.verbose:
            click.echo(f"Fetching manifest for {img_ref}...")

        raw_manifest = manifest_fetch(
            img_ref,
            auth_file=registry_auth_file,
            verbose=ctx.verbose,
        )

        # Parse manifest using OCIManifest model
        manifest = OCIManifest.from_dict(raw_manifest)
        deliverable_name = manifest.deliverable_name
        layers = list(manifest.layers)
        annotations = manifest.annotations

        # Extract manifest digest
        # For digest-based refs, use the digest from the ref
        # Otherwise, calculate from manifest JSON (canonical form)
        if img_ref.digest:
            manifest_digest = img_ref.digest
        else:
            # Calculate SHA256 digest of the manifest JSON
            manifest_bytes = json.dumps(
                raw_manifest, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            digest_hash = hashlib.sha256(manifest_bytes).hexdigest()
            manifest_digest = f"sha256:{digest_hash}"

        # Dry-run path: display metadata and exit
        if ctx.dry_run:
            total_size = sum(layer.size for layer in layers)
            click.echo(f"Image: {img_ref}")
            click.echo(f"Manifest digest: {manifest_digest}")
            click.echo(f"Layers: {len(layers)}")
            click.echo(f"Total size: {total_size:,} bytes")
            click.echo(f"Deliverable: {deliverable_name}")
            if annotations:
                click.echo("Annotations:")
                for key, value in annotations.items():
                    click.echo(f"  {key}: {value}")
            click.echo(
                f"\ndry-run: would extract {len(layers)} layer(s) "
                f"({total_size:,} bytes) to {output_dir}"
            )
            if artifact_types:
                click.echo(
                    f"\ndry-run: would discover attachments "
                    f"for artifact types: {', '.join(artifact_types)}"
                )
                for art_type in artifact_types:
                    referrers = discover(
                        img_ref,
                        art_type,
                        auth_file=registry_auth_file,
                        verbose=ctx.verbose,
                    )
                    if referrers:
                        click.echo(
                            f"  {art_type}: {len(referrers)} referrer(s) found"
                        )
                        for ref in referrers:
                            click.echo(f"    - {ref.get('digest', 'unknown')}")
                    else:
                        click.echo(f"  {art_type}: no referrers found")
            return

        # Normal path: extract the artifact
        if ctx.verbose:
            click.echo(f"Creating output directory: {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create metadata directory
        metadata_dir = output_dir / EXTRACT_METADATA_DIRNAME
        metadata_dir.mkdir(exist_ok=True)

        # Save manifest
        manifest_path = metadata_dir / "manifest.json"
        if ctx.verbose:
            click.echo(f"Saving manifest to {manifest_path}")
        with manifest_path.open("w") as f:
            json.dump(manifest.to_dict(), f, indent=2)

        # Pull the artifact
        if ctx.verbose:
            click.echo(f"Pulling artifact to {output_dir}...")

        pull(
            img_ref,
            output_dir,
            auth_file=registry_auth_file,
            verbose=ctx.verbose,
        )

        # ZIP deliverables are intentionally not extracted: downstream consumers
        # use the archive directly, and materializing a large repository doubles
        # disk usage. Build the file inventory from ZIP metadata instead.
        deliverable_file = output_dir / deliverable_name
        files = []
        file_sizes: dict[str, int] = {}
        if deliverable_file.is_file() and zipfile.is_zipfile(deliverable_file):
            deliverable_name = deliverable_name.removesuffix(".zip")
            with zipfile.ZipFile(deliverable_file) as archive:
                members = archive.infolist()
                for member in members:
                    member_path = Path(member.filename)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        raise click.ClickException(
                            "Zip-slip path traversal attempt detected: "
                            + member.filename
                        )
                file_sizes = {
                    str(Path(member.filename)): member.file_size
                    for member in members
                    if not member.is_dir()
                }
                files = sorted(file_sizes.keys())
            if ctx.verbose:
                click.echo(f"Deliverable archive: {deliverable_file}")
        else:
            deliverable_path = output_dir / deliverable_name
            if not deliverable_path.exists():
                raise click.ClickException(
                    f"Deliverable directory not found: {deliverable_path}"
                )
            file_sizes = {
                str(item.relative_to(output_dir)): item.stat().st_size
                for item in deliverable_path.rglob("*")
                if item.is_file()
            }
            files = sorted(file_sizes.keys())

        # Discover and pull attachments
        attachment_files: list[str] = []
        if artifact_types:
            attachments_dir = output_dir / EXTRACT_ATTACHMENTS_DIRNAME
            attachments_dir.mkdir(exist_ok=True)

            for art_type in artifact_types:
                if ctx.verbose:
                    click.echo(
                        f"Discovering referrers for artifact type: {art_type}"
                    )

                referrers = discover(
                    img_ref,
                    art_type,
                    auth_file=registry_auth_file,
                    verbose=ctx.verbose,
                )

                if not referrers:
                    if ctx.verbose:
                        click.echo(f"  No referrers found for {art_type}")
                    continue

                referrer = _deduplicate_referrers(
                    referrers,
                    art_type,
                    img_ref,
                    registry_auth_file,
                    verbose=ctx.verbose,
                )

                if not referrer:
                    continue

                digest = referrer.get("digest")
                if not digest:
                    continue

                ref_image = ImageReference(
                    registry=img_ref.registry,
                    repository=img_ref.repository,
                    tag=None,
                    digest=digest,
                )

                if ctx.verbose:
                    click.echo(f"  Pulling attachment: {ref_image}")

                pull(
                    ref_image,
                    attachments_dir,
                    auth_file=registry_auth_file,
                    verbose=ctx.verbose,
                )

            # Collect attachment files
            for item in sorted(attachments_dir.rglob("*")):
                if item.is_file():
                    rel_path = item.relative_to(output_dir)
                    attachment_files.append(str(rel_path))

        # Build and save ExtractResult
        result = ExtractResult(
            image=img_ref,
            manifest_digest=manifest_digest,
            layers=layers,
            annotations=annotations,
            deliverable_dir=deliverable_name,
            files=files,
            extracted_at=datetime.now(timezone.utc).isoformat(),
            attachment_files=attachment_files,
        )

        result_path = output_dir / EXTRACT_RESULT_FILENAME
        if ctx.verbose:
            click.echo(f"Writing result manifest to {result_path}")
        result.save(result_path)

        # Write Tekton results
        write_tekton_result(
            ctx.tekton_results_dir, "MANIFEST_DIGEST", manifest_digest
        )
        write_tekton_result(
            ctx.tekton_results_dir, "DELIVERABLE_DIR", deliverable_name
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "ATTACHMENT_DIR",
            EXTRACT_ATTACHMENTS_DIRNAME if attachment_files else "__EMPTY__",
        )

        # Log summary
        jar_count = sum(
            1
            for f in files
            if f.endswith(".jar")
            and "-sources.jar" not in f
            and "-javadoc.jar" not in f
        )
        pom_count = sum(1 for f in files if f.endswith(".pom"))
        has_sbom = any("cyclonedx.json" in f for f in files)
        has_provenance = any("provenance.json" in f for f in files)
        total_size = sum(file_sizes.values())

        click.echo(
            f"Extracted: {jar_count} artifact(s), {pom_count} POM(s), "
            f"{'SBOM, ' if has_sbom else ''}"
            f"{'provenance, ' if has_provenance else ''}"
            f"{len(files)} total files ({total_size:,} bytes)"
        )

        if attachment_files:
            click.echo(f"Attachments: {len(attachment_files)} file(s) discovered")

        if ctx.verbose:
            click.echo(f"\nExtracted files ({len(files)}):")
            for file_path in files:
                size = file_sizes.get(file_path, 0)
                click.echo(f"  {file_path} ({size:,} bytes)")

    except OrasError as e:
        raise click.ClickException(f"OCI error: {e.message}") from e
    except ValueError as e:
        raise click.ClickException(str(e)) from e
