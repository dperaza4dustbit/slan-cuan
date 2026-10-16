"""Merged Python release extract + filter command.

One TaskRun that: reads the component images from the snapshot spec,
pulls their distribution files into the payload directory, fetches the
Tekton Chains SLSA provenance for each image (consumed downstream by
wheel signing to build PEP 740 attestations), and filters the payload
against the build-index purls of the (single) component image.

Replaces the two-step ``extract-py-artifacts`` + ``build-index-filter``
TaskRun chain; the ``populate-release-notes`` step of the old extract
task is deliberately not ported (advisory creation was replaced by OSV
creation and nothing in the release path consumes
``releaseNotes.content.artifacts``).
"""

from __future__ import annotations

from pathlib import Path

import click

from slan_cuan.models import GlobalContext, ImageReference
from slan_cuan.oci import OrasError, pull
from slan_cuan.provenance import (
    DEFAULT_PROVENANCE_KEY,
    fetch_chains_provenance,
)
from slan_cuan.snapshot import snapshot_component_images
from slan_cuan.tasks.build_index import (
    apply_release_scope_filter,
    load_build_index,
    purls_from_index,
)
from slan_cuan.utils import write_tekton_result


@click.command("extract-filter")
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
    help="Directory to extract distribution files into and filter.",
)
@click.option(
    "--publish-all",
    is_flag=True,
    default=False,
    help="Publish all artifacts without filtering by build-index purls.",
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
def extract_filter(
    ctx: GlobalContext,
    snapshot_path: Path,
    files_dir: Path,
    publish_all: bool,
    registry_auth_file: Path | None,
    provenance_key: str,
) -> None:
    """Extract a Python release payload and filter it by build-index purls."""
    images = snapshot_component_images(snapshot_path)

    files_dir.mkdir(parents=True, exist_ok=True)

    # 1. Extract distribution files from every component image.
    for image_ref_str in images:
        img_ref = ImageReference.parse(image_ref_str)
        try:
            pull(
                img_ref,
                files_dir,
                auth_file=registry_auth_file,
                verbose=ctx.verbose,
            )
        except OrasError as e:
            raise click.ClickException(f"OCI error: {e.message}") from e

    # 2. Fetch Chains provenance for every component image; wheel signing
    #    consumes it downstream to build PEP 740 attestations.
    for image_ref_str in images:
        fetch_chains_provenance(
            image_ref_str,
            files_dir / "chains-provenance",
            provenance_key,
            registry_auth_file,
            verbose=ctx.verbose,
        )

    # 3. Filter against the build-index. The release filter scope is the
    #    single component image's index; multi-component snapshots are
    #    rejected rather than silently filtered against an arbitrary one.
    if len(images) != 1:
        raise click.ClickException(
            "Release filtering supports exactly one component image, "
            f"snapshot has {len(images)}: {', '.join(images)}"
        )

    index_data, build_index_digest = load_build_index(
        images[0], registry_auth_file, verbose=ctx.verbose
    )
    purls = purls_from_index(index_data)

    if ctx.dry_run:
        click.echo(f"Build index digest: {build_index_digest}")
        click.echo(f"Purls in build-index: {len(purls)}")
        click.echo(f"Publish all: {publish_all}")

    kept, removed = apply_release_scope_filter(
        files_dir,
        purls,
        publish_all,
        build_index_digest=build_index_digest,
        dry_run=ctx.dry_run,
    )

    if ctx.dry_run:
        return
    if ctx.tekton_results_dir:
        write_tekton_result(
            ctx.tekton_results_dir,
            "CONSUMED_BUILD_INDEX_DIGEST",
            build_index_digest,
        )
        write_tekton_result(ctx.tekton_results_dir, "KEPT_COUNT", str(kept))
        write_tekton_result(ctx.tekton_results_dir, "REMOVED_COUNT", str(removed))
