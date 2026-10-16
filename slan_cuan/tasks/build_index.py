"""Filter payload artifacts against build-index purls.

Keeps distribution files (wheels/sdists and their sidecars) whose purls are
in the build-index ``purls`` release allow-list; moves out-of-scope
distribution files to a sibling ``-filtered`` directory. Non-distribution
files (e.g. the ``chains-provenance/`` metadata directory) always pass
through untouched -- downstream signing consumes them.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import click

from slan_cuan.models import (
    BUILD_INDEX_MEDIA_TYPE,
    FILTER_REPORT_FILENAME,
    GlobalContext,
    ImageReference,
)
from slan_cuan.oci import (
    OrasError,
    deduplicate_referrers,
    discover,
    manifest_fetch,
    pull,
)
from slan_cuan.python.pypi import (
    get_purl_candidate_patterns,
    is_distribution_filename,
    matches_any_candidate,
)
from slan_cuan.utils import write_tekton_result
from slan_cuan.utils.checksum import compute_checksum


@click.command("build-index-filter")
@click.option(
    "--image-ref",
    required=True,
    type=str,
    help="Digest-pinned container image reference to discover index from.",
)
@click.option(
    "--payload-dir",
    required=True,
    type=click.Path(path_type=Path),
    help="Directory containing payload files to filter.",
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
@click.pass_obj
def build_index_filter(
    ctx: GlobalContext,
    image_ref: str,
    payload_dir: Path,
    publish_all: bool,
    registry_auth_file: Path | None,
) -> None:
    """Filter payload directory artifacts against build-index purls."""
    img_ref = ImageReference.parse(image_ref)
    if not img_ref.digest:
        raise click.ClickException(
            "Image reference must include a digest "
            f"(e.g. repo@sha256:...): {image_ref}"
        )

    if not payload_dir.is_dir():
        raise click.ClickException(
            "Payload directory does not exist or is not a directory: "
            f"{payload_dir}"
        )

    try:
        referrers = discover(
            img_ref,
            BUILD_INDEX_MEDIA_TYPE,
            auth_file=registry_auth_file,
            verbose=ctx.verbose,
        )
    except OrasError as e:
        raise click.ClickException(f"OCI error: {e.message}") from e

    if not referrers:
        raise click.ClickException(
            f"No build-index referrer found for {image_ref}"
        )

    try:
        referrer = deduplicate_referrers(
            referrers,
            BUILD_INDEX_MEDIA_TYPE,
            img_ref,
            registry_auth_file=registry_auth_file,
            verbose=ctx.verbose,
            manifest_fetch_fn=manifest_fetch,
        )
    except OrasError as e:
        raise click.ClickException(f"OCI error: {e.message}") from e
    if not referrer or not referrer.get("digest"):
        raise click.ClickException(
            f"No valid build-index referrer found for {image_ref}"
        )

    ref_digest = str(referrer["digest"])
    ref_image = ImageReference(
        registry=img_ref.registry,
        repository=img_ref.repository,
        tag=None,
        digest=ref_digest,
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            pull(
                ref_image,
                tmp_path,
                auth_file=registry_auth_file,
                verbose=ctx.verbose,
            )
        except OrasError as e:
            raise click.ClickException(f"OCI error: {e.message}") from e

        index_file = tmp_path / "build-index.json"
        if not index_file.is_file():
            candidates = list(tmp_path.rglob("build-index.json"))
            if candidates:
                index_file = candidates[0]
            else:
                raise click.ClickException(
                    "No build-index.json found after pulling referrer "
                    f"{ref_image}"
                )

        build_index_digest = f"sha256:{compute_checksum(index_file, 'sha256')}"
        try:
            index_data = json.loads(index_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise click.ClickException(
                f"Failed to parse build-index.json: {e}"
            ) from e

    if not isinstance(index_data, dict):
        raise click.ClickException(
            f"Expected JSON object in build-index.json, "
            f"got {type(index_data).__name__}"
        )

    raw_purls = index_data.get("purls", [])
    if not isinstance(raw_purls, list):
        raise click.ClickException(
            f"Expected 'purls' to be a list in build-index.json, "
            f"got {type(raw_purls).__name__}"
        )

    allowed_patterns: set[str] = set()
    purl_count = 0
    unmapped_purls: list[str] = []
    for purl_str in raw_purls:
        if not isinstance(purl_str, str):
            raise click.ClickException(
                f"build-index 'purls' entries must be strings, "
                f"got {type(purl_str).__name__}: {purl_str!r}"
            )
        pats = get_purl_candidate_patterns(purl_str)
        if pats:
            allowed_patterns.update(pats)
            purl_count += 1
        else:
            unmapped_purls.append(purl_str)
    if unmapped_purls:
        # Fail closed: a purl we cannot map to filename candidates might
        # name in-scope content whose files we would then wrongly remove.
        raise click.ClickException(
            "build-index purls yielded no filename candidates (unsupported "
            f"ecosystem or missing version): {', '.join(sorted(unmapped_purls))}"
        )

    all_files = sorted(f for f in payload_dir.rglob("*") if f.is_file())
    kept_files: list[Path] = []
    removed_files: list[Path] = []

    for f in all_files:
        if publish_all or matches_any_candidate(f.name, allowed_patterns):
            kept_files.append(f)
        elif is_distribution_filename(f.name):
            # Distribution-shaped but outside the release scope: remove.
            removed_files.append(f)
        else:
            # Non-distribution files (provenance, metadata) are not release
            # content and are never uploaded; downstream tasks depend on
            # them, so they pass through untouched.
            kept_files.append(f)

    filtered_dir = payload_dir.parent / f"{payload_dir.name}-filtered"
    report_path = payload_dir.parent / FILTER_REPORT_FILENAME

    if ctx.dry_run:
        click.echo(f"Build index digest: {build_index_digest}")
        click.echo(f"Purls in build-index: {purl_count}")
        click.echo(f"Publish all: {publish_all}")
        click.echo(
            f"dry-run: would keep {len(kept_files)} file(s), "
            f"remove {len(removed_files)} file(s) to {filtered_dir}"
        )
        for f in kept_files:
            click.echo(f"  keep: {f.relative_to(payload_dir)}")
        for f in removed_files:
            click.echo(f"  remove: {f.relative_to(payload_dir)}")
        return

    if removed_files:
        filtered_dir.mkdir(parents=True, exist_ok=True)
        for f in removed_files:
            rel = f.relative_to(payload_dir)
            dest = filtered_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                dest.unlink()
            shutil.move(str(f), str(dest))

    report = {
        "consumed_build_index_digest": build_index_digest,
        "consumed_digest": build_index_digest,
        "kept": [str(f.relative_to(payload_dir)) for f in kept_files],
        "removed": [str(f.relative_to(payload_dir)) for f in removed_files],
        "kept_count": len(kept_files),
        "removed_count": len(removed_files),
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if ctx.tekton_results_dir:
        write_tekton_result(
            ctx.tekton_results_dir,
            "CONSUMED_BUILD_INDEX_DIGEST",
            build_index_digest,
        )
        write_tekton_result(
            ctx.tekton_results_dir, "KEPT_COUNT", str(len(kept_files))
        )
        write_tekton_result(
            ctx.tekton_results_dir, "REMOVED_COUNT", str(len(removed_files))
        )

    click.echo(
        f"Filtered payload: {len(kept_files)} kept, {len(removed_files)} removed."
    )
