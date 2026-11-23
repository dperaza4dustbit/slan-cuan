"""javascript release extract command.

Reads the component images from the snapshot spec, pulls each one's
distribution files into a digest-namespaced directory under the
payload root, and fetches/verifies the Tekton Chains SLSA provenance
for each image against the npm trust policy
(``slan_cuan.javascript.provenance``).
"""

from __future__ import annotations

from pathlib import Path

import click

from slan_cuan.javascript.provenance import (
    NPM_PREDICATE_TYPES,
    build_npm_provenance_selector,
    parse_trusted_namespaces,
)
from slan_cuan.models import GlobalContext, parse_image_ref
from slan_cuan.oci import OrasError, pull
from slan_cuan.provenance import DEFAULT_PROVENANCE_KEY, fetch_chains_provenance
from slan_cuan.snapshot import snapshot_component_images


@click.command("extract")
@click.option(
    "--snapshot-path",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to the snapshot spec JSON (components[].containerImage).",
)
@click.option(
    "--files-dir",
    required=True,
    type=click.Path(path_type=Path),
    help="Directory to extract each image's distribution files into.",
)
@click.option(
    "--trusted-provenance-namespaces",
    type=str,
    default="calunga-tenant",
    help=(
        "Comma-separated Kubernetes namespaces allowed to produce "
        "accepted Chains provenance."
    ),
)
@click.option(
    "--registry-auth-file",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to container registry authentication file.",
)
@click.option(
    "--provenance-key",
    type=str,
    default=DEFAULT_PROVENANCE_KEY,
    help="cosign key reference for verifying Tekton Chains attestations.",
)
@click.pass_obj
def extract(
    ctx: GlobalContext,
    snapshot_path: Path,
    files_dir: Path,
    trusted_provenance_namespaces: str,
    registry_auth_file: Path | None,
    provenance_key: str,
) -> None:
    """Extract npm packages from the snapshot's component images."""
    images = snapshot_component_images(snapshot_path)

    if ctx.dry_run:
        # Side-effect-free preview, matching the python extract-filter
        # dry-run convention: exit before any registry pull or cosign
        # run touches the network or the filesystem.
        for image_ref_str in images:
            click.echo(f"Would extract {image_ref_str} into {files_dir}")
        click.echo("Would fetch Chains provenance for each image")
        return

    trusted_namespaces = parse_trusted_namespaces(trusted_provenance_namespaces)

    for image_ref_str in images:
        img_ref = parse_image_ref(image_ref_str)
        if not img_ref.digest:
            raise click.ClickException(
                f"Image reference must be digest-pinned: {image_ref_str}"
            )
        digest_safe = img_ref.digest.replace(":", "_").replace("/", "_")
        try:
            pull(
                img_ref,
                files_dir / digest_safe,
                auth_file=registry_auth_file,
                verbose=ctx.verbose,
            )
        except OrasError as e:
            raise click.ClickException(f"OCI error: {e.message}") from e

        fetch_chains_provenance(
            image_ref_str,
            files_dir / "chains-provenance",
            provenance_key,
            registry_auth_file,
            verbose=ctx.verbose,
            predicate_types=NPM_PREDICATE_TYPES,
            select=build_npm_provenance_selector(
                img_ref.digest, trusted_namespaces
            ),
        )
