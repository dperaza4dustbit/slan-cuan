"""Layer E cross-repo pipeline param contract test.

Verifies, offline against a vendored and pinned fixture, that the
slan-cuan-release Pipeline (release-service-catalog) only passes params a
Task declares and supplies every param a Task requires. See
tests/integrity/README.md for how to refresh the fixture and what a
failure means.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.integrity._yaml_helpers import load_task_yaml

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "release-service-catalog"
    / "pipelines"
    / "managed"
    / "slan-cuan-release"
    / "slan-cuan-release.yaml"
)


def _load_pipeline_fixture() -> dict:
    return yaml.safe_load(FIXTURE_PATH.read_text())


def _slan_cuan_task_filename(pipeline_task: dict) -> str | None:
    """Return the tekton/tasks/*.yaml filename this pipeline task resolves to.

    Returns None if it's not a slan-cuan task (e.g. collect-data,
    verify-conforma -- these use a different taskRef shape entirely).
    """
    task_ref_params = pipeline_task.get("taskRef", {}).get("params", [])
    path_in_repo = next(
        (p["value"] for p in task_ref_params if p["name"] == "pathInRepo"),
        None,
    )
    if path_in_repo is None or not path_in_repo.startswith("tekton/tasks/"):
        return None
    return path_in_repo.removeprefix("tekton/tasks/")


def _slan_cuan_pipeline_tasks() -> list[tuple[str, str]]:
    """Return the (pipeline_task_name, tekton_task_filename) pairs.

    One pair for every pipeline task that maps to a local
    tekton/tasks/*.yaml file.
    """
    pipeline = _load_pipeline_fixture()
    result = []
    for task in pipeline["spec"]["tasks"]:
        filename = _slan_cuan_task_filename(task)
        if filename is not None:
            result.append((task["name"], filename))
    return result


def test_exactly_four_pipeline_tasks_map_to_local_slan_cuan_tasks() -> None:
    """Pin: only 4 of the fixture's 9 pipeline tasks map to a local Task file.

    The 4 are extract, sign, generate-security-metadata, and publish.
    register is not currently wired into this pipeline at all.
    """
    mapped = _slan_cuan_pipeline_tasks()
    assert sorted(name for name, _ in mapped) == [
        "extract",
        "generate-security-metadata",
        "publish",
        "sign",
    ]


@pytest.mark.parametrize(
    "pipeline_task_name,task_filename", _slan_cuan_pipeline_tasks()
)
def test_pipeline_only_passes_params_the_task_declares(
    pipeline_task_name: str, task_filename: str
) -> None:
    """Every param the Pipeline supplies to a task must be Task-declared.

    An undeclared param is silently stray.
    """
    pipeline = _load_pipeline_fixture()
    pipeline_task = next(
        t for t in pipeline["spec"]["tasks"] if t["name"] == pipeline_task_name
    )
    supplied = {p["name"] for p in pipeline_task.get("params", [])}

    task_doc = load_task_yaml(task_filename)
    declared = {p["name"] for p in task_doc["spec"]["params"]}

    undeclared = supplied - declared
    assert undeclared == set(), (
        f"pipeline task '{pipeline_task_name}' passes param(s) {undeclared} "
        f"that {task_filename} does not declare in spec.params -- stray or "
        f"renamed param"
    )


@pytest.mark.parametrize(
    "pipeline_task_name,task_filename", _slan_cuan_pipeline_tasks()
)
def test_pipeline_supplies_every_required_task_param(
    pipeline_task_name: str, task_filename: str
) -> None:
    """Every Task param without a default must be supplied by the Pipeline.

    Otherwise the real pipeline run fails immediately.
    """
    pipeline = _load_pipeline_fixture()
    pipeline_task = next(
        t for t in pipeline["spec"]["tasks"] if t["name"] == pipeline_task_name
    )
    supplied = {p["name"] for p in pipeline_task.get("params", [])}

    task_doc = load_task_yaml(task_filename)
    required = {
        p["name"] for p in task_doc["spec"]["params"] if "default" not in p
    }

    missing = required - supplied
    assert missing == set(), (
        f"{task_filename} requires param(s) {missing} (no default) that "
        f"pipeline task '{pipeline_task_name}' does not supply -- this "
        f"would fail at pipeline-run time"
    )
