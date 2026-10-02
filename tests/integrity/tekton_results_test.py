"""Layer D: every Tekton result name a CLI command writes is declared.

See tests/integrity/README.md.
"""

from __future__ import annotations

import inspect
from unittest.mock import patch

import pytest

from slan_cuan.cli import main as cli_main
from tests.integrity._yaml_helpers import (
    TASK_YAML_FILENAMES,
    get_run_step,
    get_subcommand_name,
    load_task_yaml,
    written_tekton_result_names,
)


@pytest.mark.parametrize("filename", TASK_YAML_FILENAMES)
def test_written_results_are_declared_on_the_task(filename: str) -> None:
    """Every result name the CLI writes appears in the Task's declared results.

    Not the reverse, since some results (e.g. sourceDataArtifact) come from a
    stepaction, not the CLI.
    """
    task_doc = load_task_yaml(filename)
    run_step = get_run_step(task_doc)
    subcommand_name = get_subcommand_name(run_step)
    command = cli_main.commands[subcommand_name]

    written = written_tekton_result_names(command)
    declared = {r["name"] for r in task_doc["spec"].get("results", [])}

    missing = written - declared
    assert missing == set(), (
        f"{filename}: '{subcommand_name}' writes Tekton result(s) {missing} "
        f"that are not declared in this Task's results: -- Tekton will not "
        f"surface these, silently dropping the data"
    )


def test_ast_extraction_is_scoped_per_function_not_whole_module() -> None:
    """Pin: source-fetching must be scoped to the command's own callback.

    generate_security_metadata.py hosts two commands that currently write
    the same result name, so comparing output alone wouldn't catch a
    module-wide scan regression -- this pins written_tekton_result_names to
    call inspect.getsource on exactly the command's callback, never the
    whole module.
    """
    gsm = cli_main.commands["generate-security-metadata"]
    real_getsource = inspect.getsource
    captured: list[str] = []

    def spy_getsource(obj):  # noqa: D103
        source = real_getsource(obj)
        captured.append(source)
        return source

    patch_target = "tests.integrity._yaml_helpers.inspect.getsource"
    with patch(patch_target, side_effect=spy_getsource):
        written_tekton_result_names(gsm)

    assert len(captured) == 1
    assert "def generate_security_metadata_from_snapshot" not in captured[0]
