"""Shared YAML-loading and click-introspection helpers for the integrity tests.

Not a test module itself -- deliberately named without a _test.py suffix so pytest
does not collect it.
"""

from __future__ import annotations

import ast
import inspect
import os
from pathlib import Path

import click
import yaml

from slan_cuan.cli import main as cli_main

TEKTON_TASKS_DIR = Path(__file__).resolve().parents[2] / "tekton" / "tasks"

TASK_YAML_FILENAMES = sorted(p.name for p in TEKTON_TASKS_DIR.glob("*.yaml"))


def load_task_yaml(filename: str) -> dict:
    """Parse one Tekton Task YAML file by filename under tekton/tasks/."""
    return yaml.safe_load((TEKTON_TASKS_DIR / filename).read_text())


def get_run_step(task_doc: dict) -> dict:
    """Return the step named 'run' -- the one invoking the slan-cuan CLI."""
    steps = task_doc["spec"]["steps"]
    return next(s for s in steps if s["name"] == "run")


def get_subcommand_name(run_step: dict) -> str:
    """Return the CLI subcommand name from a run step's args.

    The subcommand is always the last element -- several Tasks prefix it
    with a global flag, e.g. args: [--verbose, sign].
    """
    return run_step["args"][-1]


def get_env_var_names(run_step: dict) -> list[str]:
    """Return every env var name set on a run step.

    Reads only the 'name' key -- some entries use valueFrom.secretKeyRef
    instead of value and have no 'value' key at all.
    """
    return [e["name"] for e in run_step.get("env", [])]


def build_contexts(subcommand_name: str) -> tuple[click.Context, click.Context]:
    """Build the (group_ctx, sub_ctx) click Context chain for a subcommand.

    Mirrors exactly how click builds this chain internally when invoking a
    subcommand, so auto_envvar_prefix propagation matches real CLI
    behavior -- never hardcode the prefix string.
    """
    group_ctx = click.Context(
        cli_main, info_name="slan-cuan", **cli_main.context_settings
    )
    sub_cmd = cli_main.commands[subcommand_name]
    sub_ctx = click.Context(sub_cmd, parent=group_ctx, info_name=subcommand_name)
    return group_ctx, sub_ctx


def resolve_env_var_to_param(
    env_var_name: str, group_ctx: click.Context, sub_ctx: click.Context
) -> click.Parameter | None:
    """Find which click Parameter resolves an env var name, if any.

    Uses click's own Parameter.resolve_envvar_value, not a reimplementation
    of its naming rule, so this can't drift from click's real behavior.
    Checks both the subcommand's own params and the group's params, since
    Task YAMLs mix both kinds (e.g. SLAN_CUAN_EXTRACT_IMAGE is a subcommand
    option, SLAN_CUAN_TEKTON_RESULTS_DIR is a group option).
    """
    sentinel = f"__INTEGRITY_PROBE__{env_var_name}__"
    old_value = os.environ.get(env_var_name)
    os.environ[env_var_name] = sentinel
    try:
        candidates = [(p, sub_ctx) for p in sub_ctx.command.params]
        candidates += [(p, group_ctx) for p in group_ctx.command.params]
        matches = [
            p for p, ctx in candidates if p.resolve_envvar_value(ctx) == sentinel
        ]
    finally:
        if old_value is None:
            del os.environ[env_var_name]
        else:
            os.environ[env_var_name] = old_value
    if len(matches) > 1:
        raise AssertionError(
            f"{env_var_name} resolves to multiple params: "
            f"{[m.name for m in matches]}"
        )
    return matches[0] if matches else None


def written_tekton_result_names(command: click.Command) -> set[str]:
    """Extract literal result-name strings from write_tekton_result calls.

    Parses the command's callback function via AST to find all calls to
    write_tekton_result and extracts the literal result-name string
    (second positional argument). Scoped to the callback's own source code,
    not the whole module, so that generate_security_metadata.py's two
    commands don't merge their result names.

    Limitation: only recognizes literal string names; dynamic computation
    would be invisible.
    """
    source = inspect.getsource(command.callback)
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "write_tekton_result"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            names.add(node.args[1].value)
    return names
