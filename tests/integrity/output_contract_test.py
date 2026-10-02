"""Layer C: Tekton Task steps that read CLI output paths directly via raw.

Tekton Task steps that read CLI output paths directly via raw shell (not
through another CLI call) must stay in sync with the real filename/dirname
constants. See tests/integrity/README.md.
"""

from __future__ import annotations

from slan_cuan.models import EXTRACT_RESULT_FILENAME
from tests.integrity._yaml_helpers import load_task_yaml


def test_extract_prepare_source_data_paths_match_code_constants() -> None:
    """Extract's prepare-source-data step hardcodes paths the CLI writes.

    They must match the real constants/dirnames, not a stale literal.
    """
    task_doc = load_task_yaml("slan-cuan-extract.yaml")
    steps = task_doc["spec"]["steps"]
    prepare_step = next(s for s in steps if s["name"] == "prepare-source-data")
    script = prepare_step["script"]

    assert EXTRACT_RESULT_FILENAME in script, (
        f"prepare-source-data no longer references "
        f"EXTRACT_RESULT_FILENAME ({EXTRACT_RESULT_FILENAME!r}) -- if "
        f"slan_cuan.models.EXTRACT_RESULT_FILENAME changed, update this "
        f"Task's prepare-source-data script to match"
    )
    assert "metadata" in script, (
        "prepare-source-data no longer references the 'metadata' "
        "subdirectory that extract.py writes via output_dir / 'metadata'"
    )
    assert "attachments" in script, (
        "prepare-source-data no longer references the 'attachments' "
        "subdirectory that extract.py writes via output_dir / 'attachments'"
    )
