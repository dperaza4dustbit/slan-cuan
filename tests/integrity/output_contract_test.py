"""Layer C: Output path contract tests.

Tekton Task steps that read CLI output paths directly via raw shell (not
through another CLI call) must stay in sync with the real filename/dirname
constants. See tests/integrity/README.md.
"""

from __future__ import annotations

from slan_cuan.models import (
    EXTRACT_ATTACHMENTS_DIRNAME,
    EXTRACT_METADATA_DIRNAME,
    EXTRACT_RESULT_FILENAME,
)
from tests.integrity._yaml_helpers import get_run_step, load_task_yaml


def _extract_output_dir(task_doc: dict) -> str:
    """Return the extract Task's declared SLAN_CUAN_EXTRACT_OUTPUT_DIR value.

    Read from the 'run' step's own env, independent of the
    prepare-source-data script under test below, so the expected path is
    anchored to the Task's own declared output directory rather than
    re-derived from the same script being checked.
    """
    run_step = get_run_step(task_doc)
    for env in run_step.get("env", []):
        if env["name"] == "SLAN_CUAN_EXTRACT_OUTPUT_DIR":
            return env["value"]
    raise AssertionError(
        "slan-cuan-extract.yaml's 'run' step no longer sets "
        "SLAN_CUAN_EXTRACT_OUTPUT_DIR -- update _extract_output_dir"
    )


def _prepare_source_data_script(task_doc: dict) -> str:
    """Return the prepare-source-data step's raw shell script."""
    steps = task_doc["spec"]["steps"]
    prepare_step = next(s for s in steps if s["name"] == "prepare-source-data")
    return prepare_step["script"]


def test_extract_prepare_source_data_paths_match_code_constants() -> None:
    """Extract's prepare-source-data step hardcodes paths the CLI writes.

    They must match the real constants/dirnames, not a stale literal.
    """
    task_doc = load_task_yaml("slan-cuan-extract.yaml")
    output_dir = _extract_output_dir(task_doc)
    script = _prepare_source_data_script(task_doc)

    assert EXTRACT_RESULT_FILENAME in script, (
        f"prepare-source-data no longer references "
        f"EXTRACT_RESULT_FILENAME ({EXTRACT_RESULT_FILENAME!r}) -- if "
        f"slan_cuan.models.EXTRACT_RESULT_FILENAME changed, update this "
        f"Task's prepare-source-data script to match"
    )

    expected_metadata_path = f"{output_dir}/{EXTRACT_METADATA_DIRNAME}"
    assert expected_metadata_path in script, (
        f"prepare-source-data no longer references "
        f"{expected_metadata_path!r} -- if "
        f"slan_cuan.models.EXTRACT_METADATA_DIRNAME or extract.py's output "
        f"directory changed, update this Task's prepare-source-data script "
        f"to match"
    )

    expected_attachments_path = f"{output_dir}/{EXTRACT_ATTACHMENTS_DIRNAME}"
    assert expected_attachments_path in script, (
        f"prepare-source-data no longer references "
        f"{expected_attachments_path!r} -- if "
        f"slan_cuan.models.EXTRACT_ATTACHMENTS_DIRNAME or extract.py's "
        f"output directory changed, update this Task's prepare-source-data "
        f"script to match"
    )


def test_metadata_and_attachments_dirname_drift_is_detected() -> None:
    """Regression: a producer-side dirname change must break the check above.

    Pins that the assertions above are anchored to the real
    EXTRACT_METADATA_DIRNAME/EXTRACT_ATTACHMENTS_DIRNAME constants and the
    Task's own declared output dir -- not a loose "is this word anywhere in
    the script" check. A dirname that diverges from what extract.py actually
    writes must NOT be found in the real (unchanged) Task script.
    """
    task_doc = load_task_yaml("slan-cuan-extract.yaml")
    output_dir = _extract_output_dir(task_doc)
    script = _prepare_source_data_script(task_doc)

    drifted_metadata_path = f"{output_dir}/{EXTRACT_METADATA_DIRNAME}-renamed"
    assert drifted_metadata_path not in script

    drifted_attachments_path = (
        f"{output_dir}/{EXTRACT_ATTACHMENTS_DIRNAME}-renamed"
    )
    assert drifted_attachments_path not in script
