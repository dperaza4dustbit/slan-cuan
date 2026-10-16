"""Python ecosystem CLI group."""

from __future__ import annotations

import click

from slan_cuan.python.extract_filter import extract_filter


@click.group("python")
def python_cli() -> None:
    """Python ecosystem release commands."""


python_cli.add_command(extract_filter)
