"""CLI entry point and group definition."""

from pathlib import Path

import click

from slan_cuan.models import GlobalContext
from slan_cuan.tasks import (
    build_index_filter,
    extract,
    generate_security_metadata,
    generate_security_metadata_from_snapshot,
    publish,
    register,
    sign,
)


@click.group(context_settings={"auto_envvar_prefix": "SLAN_CUAN"})
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose output.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Perform a dry run without making any changes.",
)
@click.option(
    "--ca-cert",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to a custom CA certificate bundle for TLS verification.",
)
@click.option(
    "--tekton-results-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory where Tekton result files should be written.",
)
@click.pass_context
def main(
    ctx: click.Context,
    verbose: bool,
    dry_run: bool,
    ca_cert: Path | None,
    tekton_results_dir: Path | None,
) -> None:
    """Release tooling for Red Hat Lightwell artifacts (multi-ecosystem)."""
    ctx.obj = GlobalContext(
        verbose=verbose,
        dry_run=dry_run,
        ca_cert=ca_cert,
        tekton_results_dir=tekton_results_dir,
    )


main.add_command(generate_security_metadata)
main.add_command(generate_security_metadata_from_snapshot)
main.add_command(extract)
main.add_command(build_index_filter)
main.add_command(publish)
main.add_command(sign)
main.add_command(register)

if __name__ == "__main__":
    main()
