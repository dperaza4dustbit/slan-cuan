"""Layer A/B: every Tekton Task's subcommand and env vars map to CLI options.

See tests/integrity/README.md for details.
"""

from __future__ import annotations

import pytest

from slan_cuan.cli import main as cli_main
from tests.integrity._yaml_helpers import (
    TASK_YAML_FILENAMES,
    build_context_chain,
    get_command_path,
    get_env_var_names,
    get_run_step,
    load_task_yaml,
    resolve_env_var_to_param,
)


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_subcommand_is_registered(filename: str) -> None:
    """Each Task's run-step subcommand is a real slan-cuan CLI command."""
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)

    # Walk the (possibly nested) command path, e.g. python -> extract-filter
    commands = cli_main.commands
    path = get_command_path(run_step)
    for token in path[:-1]:
        assert token in commands, (
            f"{filename}: command group {token!r} is not registered on "
            f"slan_cuan.cli.main -- was it renamed or removed?"
        )
        commands = commands[token].commands
    assert path[-1] in commands, (
        f"{filename}: subcommand {path[-1]!r} is not registered under "
        f"{' -> '.join(path[:-1]) or 'slan_cuan.cli.main'} "
        f"-- was it renamed or removed?"
    )


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_every_env_var_resolves_to_a_real_option(filename: str) -> None:
    """Each Task's SLAN_CUAN_* env var must map to a real CLI option."""
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)
    chain = build_context_chain(run_step)

    for env_var_name in get_env_var_names(run_step):
        param = resolve_env_var_to_param(env_var_name, chain)
        assert param is not None, (
            f"{filename}: env var {env_var_name!r} does not resolve to any "
            f"option on '{chain[-1].command.name}' or its command path -- "
            f"likely a renamed or removed CLI option that this Task's env "
            f"list was never updated for"
        )


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_every_required_option_has_a_wired_env_var(filename: str) -> None:
    """Each required (no-default) option must have a matching env var."""
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)
    chain = build_context_chain(run_step)
    env_var_names = get_env_var_names(run_step)

    wired_param_names = {
        p.name
        for name in env_var_names
        if (p := resolve_env_var_to_param(name, chain)) is not None
    }

    all_params = [p for ctx in chain for p in ctx.command.params]
    missing = [
        p.name
        for p in all_params
        if getattr(p, "required", False) and p.name not in wired_param_names
    ]
    assert missing == [], (
        f"{filename}: subcommand '{chain[-1].command.name}' has required "
        f"option(s) {missing} with no env var wired anywhere in this "
        f"Task's env list "
        f"-- this Task would fail at runtime with 'Missing option'"
    )


def test_force_flag_is_not_flagged_as_missing_required_env_var() -> None:
    """Pin: a boolean is_flag option (extract's --force) is never flagged.

    Even though it has no env var in extract.yaml and no explicit required=True.
    """
    sub_ctx = build_context_chain({"args": ["extract"]})[-1]

    force_param = next(p for p in sub_ctx.command.params if p.name == "force")
    assert getattr(force_param, "required", False) is False


def test_valuefrom_env_entries_do_not_crash_name_extraction() -> None:
    """Pin: register.yaml's SSO_CLIENT_ID/SECRET use valueFrom with no key.

    Name extraction must not assume 'value' exists.
    """
    task_doc = load_task_yaml("slan-cuan-register.yaml")
    run_step = get_run_step(task_doc)
    env_var_names = get_env_var_names(run_step)

    assert "SLAN_CUAN_REGISTER_SSO_CLIENT_ID" in env_var_names
    assert "SLAN_CUAN_REGISTER_SSO_CLIENT_SECRET" in env_var_names
