# slan-cuan Integrity Tests: Design

- **Ticket:** LWLP-2376 (follow-on)
- **Status:** Approved for implementation planning
- **Date:** 2026-10-02

## Context

LWLP-2376 refactored `slan-cuan`'s internal module layout (splitting `pulp`,
`trustify`, `utils` into packages; moving CLI task modules under
`slan_cuan.tasks`). During review, two problems surfaced that unit tests did
not catch:

1. `pyproject.toml`'s explicit `packages = [...]` list omitted the new
   packages, so an installed wheel silently broke at import time even though
   source-checkout tests passed. (Fixed separately, prior to this spec.)
2. No test verified that `slan-cuan`'s CLI surface — subcommand names,
   options, their `SLAN_CUAN_*` env var bindings, on-disk output file names,
   and Tekton `results` — still matches what the `slan-cuan-release` Tekton
   Pipeline (defined in a separate repo, `release-service-catalog`) and its
   Tasks (defined in this repo, under `tekton/tasks/`) expect.

The second gap is the subject of this spec: a suite of **interface/contract
tests** ("integrity tests") that fail when a future `slan-cuan` code change
would silently break one of these established contracts, without requiring
a real Tekton/Konflux pipeline run to discover it.

`calunga-push-to-pulp-lightwell` was investigated as a possible third
caller and ruled out: its `ReleasePlanAdmission`s bind it only to the
`calunga-v2-index-main` and `remediated-build` applications, never
`slan-cuan`. It has no CLI/env-var contract with this codebase, so it is
out of scope for this spec.

## Contract Layers

All layers are derived generically from the existing `tekton/tasks/*.yaml`
files and the real `slan_cuan.cli.main` click object — never hand-enumerated
per task — so that adding or changing a task/option is automatically
covered without a human remembering to add a matching assertion.

| Layer | What it guards | Source of truth (expected) | Source of truth (actual) |
|-------|-----------------|------------------------------|----------------------------|
| A | Each Task's `args: [<subcommand>]` names a real CLI command | `tekton/tasks/*.yaml` `spec.steps[].args` | `slan_cuan.cli.main.commands` |
| B | Each Task's `SLAN_CUAN_*` env var resolves to a real option on that subcommand; every required (no-default) option has a corresponding env var somewhere in the Task | `tekton/tasks/*.yaml` `spec.steps[].env` | click `Context`/`Parameter.resolve_envvar_value()` on the real command objects |
| C | Hardcoded on-disk paths a Task's own shell steps read directly (not through another CLI call) match the real filename constants | `tekton/tasks/*.yaml` inline `script:` blocks | `slan_cuan.models.EXTRACT_RESULT_FILENAME` and the literal subdirectory names (`metadata`, `attachments`) used in `slan_cuan/tasks/extract.py` |
| D | Every Tekton result name the CLI actually writes is declared on the Task (not the reverse — some results, e.g. `sourceDataArtifact`, come from a stepaction, not the CLI) | `tekton/tasks/*.yaml` `spec.results[].name` | AST-extracted literal name arguments from `write_tekton_result(...)` calls in `slan_cuan/tasks/*.py` |
| E | The `slan-cuan-release` Pipeline (in `release-service-catalog`) only passes params a Task declares, and supplies every param a Task requires (no default) | vendored fixture of `release-service-catalog`'s `slan-cuan-release.yaml` `spec.tasks[].params[].name` | `tekton/tasks/*.yaml` `spec.params[].name` / presence of `default` |

**Explicit known gap (out of scope):** several Layer-E params are wired
through `collect-task-params`'s positional `extractedValues[N]` array (e.g.
`PULP_URL: $(tasks.collect-task-params.results.extractedValues[0])`), whose
correctness depends on index alignment with a separate `keysToExtract` JSON
list in the Pipeline. Verifying that alignment requires modeling
`collect-task-params`'s own behavior, which is `release-service-catalog`'s
task, not `slan-cuan`'s contract. Not covered by this suite.

## Mechanism

### Layers A/B — `tests/integrity/cli_task_yaml_test.py`

For each `tekton/tasks/*.yaml` file:
- Parse `spec.steps[].args` to get the subcommand name; assert it's a key in
  `slan_cuan.cli.main.commands`.
- Parse `spec.steps[].env` for `SLAN_CUAN_*` names.
- For each such env var, build the **real** nested `click.Context` chain
  (group context with `auto_envvar_prefix` read from
  `main.context_settings["auto_envvar_prefix"]` — never hardcoded — then a
  child context for the resolved subcommand), monkeypatch the env var to a
  sentinel value in `os.environ`, and call the real
  `click.Parameter.resolve_envvar_value(ctx)` on each parameter in **both**
  the group context's own params (e.g. `--tekton-results-dir`,
  `--verbose`, `--ca-cert`, `--dry-run`) **and** the subcommand context's
  params, to find which one (if any) picks up the sentinel. Assert exactly
  one match across the combined set. Task YAMLs mix both kinds of env var —
  e.g. `slan-cuan-extract.yaml` sets both `SLAN_CUAN_EXTRACT_IMAGE`
  (subcommand option) and `SLAN_CUAN_TEKTON_RESULTS_DIR` (group option) —
  so checking only the subcommand's params would wrongly flag the latter.
  This uses click's actual resolution code, not a reimplementation of its
  naming rule, so it cannot drift from click's real behavior across click
  version upgrades.
- Assert every parameter — group-level or subcommand-level — that is
  `required` and has no `default` has a matching env var present somewhere
  in that Task's `env:` list (via the same resolution check). In practice
  today this only bites on subcommand params, since the group-level options
  all have defaults, but the check should not assume that stays true.

A small helper module, `tests/integrity/_yaml_helpers.py`, centralizes YAML
loading and the click-context-building logic shared across test files.

### Layer C — `tests/integrity/output_contract_test.py`

Hand-written, since this is about specific known couplings rather than a
uniform pattern. Initially: the `extract` Task's `prepare-source-data` step,
asserting its hardcoded `extract-result.json`, `metadata`, and `attachments`
path segments match `slan_cuan.models.EXTRACT_RESULT_FILENAME` and the
literal directory names used in `slan_cuan/tasks/extract.py`. New couplings
of this kind (a Task step reading a CLI output path via raw shell) get added
here as they're introduced.

### Layer D — `tests/integrity/tekton_results_test.py`

For each `tekton/tasks/*.yaml` / `slan_cuan/tasks/*.py` pair: AST-parse the
Python module for `ast.Call` nodes where the function name is
`write_tekton_result` and the second positional argument is a string
literal; collect those names. Parse the Task YAML's `spec.results[].name`.
Assert the written-names set is a subset of the declared-names set.

**Assumption:** this only recognizes a literal string as the second
positional argument, which matches every `write_tekton_result` call site
today (verified by inspection). A future call site that computes the result
name dynamically (a variable or f-string) would be silently invisible to
this check. If that ever becomes necessary, this test needs revisiting
alongside it — noted here so the assumption doesn't rot silently.

### Layer E — `tests/integrity/pipeline_contract_test.py`

- A vendored, pinned copy of `release-service-catalog`'s
  `pipelines/managed/slan-cuan-release/slan-cuan-release.yaml` lives at
  `tests/integrity/fixtures/release-service-catalog/pipelines/managed/slan-cuan-release/slan-cuan-release.yaml`,
  with a header comment recording the source URL and the commit/revision it
  was copied from.
- The test parses the fixture's `spec.tasks[]`, filters to entries whose
  `taskRef.params` (git resolver) `pathInRepo` points at one of this repo's
  `tekton/tasks/*.yaml` files, and for each one compares the `params[].name`
  the Pipeline supplies against that Task's own live `spec.params[].name`:
  - every Pipeline-supplied name must be declared on the Task;
  - every Task param without a `default` must be supplied by the Pipeline.
- Runs entirely offline against the fixture — no network calls in the
  blocking test suite.

### Freshness check (non-blocking, `slan-cuan`-only)

`scripts/check_pipeline_fixture_freshness.py` fetches the live file from
`release-service-catalog@development` via stdlib `urllib.request` (no new
runtime dependency) and diffs it against the vendored fixture, exiting
non-zero on drift. Wired into a new, separate scheduled GitHub Actions
workflow, `.github/workflows/pipeline-fixture-freshness.yml` (weekly cron),
which never blocks a PR — its only job is to make fixture staleness visible
instead of silent. It is intentionally **not** mirrored into
`release-service-catalog`, which has no Python/pytest tooling today (it
tests Tekton tasks via a Kind-cluster runner and bash scripts); adding a
foreign Python check there was explicitly decided against.

## File Layout

```
slan-cuan/
  tests/integrity/
    __init__.py
    README.md                          # how the suite works + Layer-E caveats (see below)
    _yaml_helpers.py                   # shared YAML loading + click-context helpers
    cli_task_yaml_test.py              # Layers A/B
    output_contract_test.py            # Layer C
    tekton_results_test.py             # Layer D
    pipeline_contract_test.py          # Layer E
    fixtures/
      release-service-catalog/
        pipelines/managed/slan-cuan-release/
          slan-cuan-release.yaml       # vendored, pinned copy
  scripts/
    check_pipeline_fixture_freshness.py
  .github/workflows/
    pipeline-fixture-freshness.yml     # weekly cron, non-blocking
  pyproject.toml                       # + pyyaml in [project.optional-dependencies].dev
  tox.ini                              # + pyyaml in [testenv] deps
```

## `tests/integrity/README.md` Contents

1. **Purpose** — one paragraph per contract layer (A–E), referencing the
   table above.
2. **How each test file works** — one paragraph per file, including why
   `cli_task_yaml_test.py` drives click's real `Context`/
   `resolve_envvar_value()` instead of reimplementing click's auto-envvar
   naming rule.
3. **`pipeline_contract_test.py` caveats** (the part explicitly called out
   for this spec):
   - The fixture is a **pinned, vendored snapshot**, not a live fetch. A
     legitimate change in `release-service-catalog` (new param, renamed
     param, new task wiring in the Pipeline) will **not** be visible to this
     suite until the fixture is refreshed.
   - **How to refresh it:** copy the updated file over the fixture path and
     update the header comment with the new source commit/revision.
   - **How to tell a real break from a stale fixture:** if
     `pipeline_contract_test.py` fails after a `slan-cuan` change, check
     whether `tekton/tasks/*.yaml`'s `params:` actually changed in that
     diff — if so, it's a real contract break to fix. If the test starts
     failing with no related `slan-cuan` change, the fixture is stale and
     needs refreshing (likely `release-service-catalog` changed first).
   - **Freshness check:** `scripts/check_pipeline_fixture_freshness.py` runs
     weekly (non-blocking) specifically to catch this before it causes
     confusion; its failure means "refresh the fixture," not "a contract
     broke."
   - The known gap on `extractedValues[N]` positional wiring, restated.

## Dependencies

- `pyyaml` added to `[project.optional-dependencies].dev` in `pyproject.toml`
  and to `tox.ini`'s `[testenv]` deps. Not a runtime dependency of the CLI.

## CI Wiring

- `tests/integrity/` is discovered and run as part of the existing
  `unit-tests` job (`tox -e py311` → `pytest`) in `.github/workflows/ci.yml`
  — no new blocking job required.
- The freshness check is a new, separate, scheduled-only workflow that never
  gates merges.

## Testing the Tests

- Each new test, run against the current (post-LWLP-2376) `main`, must pass
  today — this is the regression baseline.
- As a sanity check during implementation, temporarily reintroduce a known
  break (e.g. rename `--image` to `--src-image` on `extract` without
  updating the Task YAML) and confirm the relevant integrity test fails with
  a clear message identifying the task/option/env-var involved, then revert.

## Out of Scope

- Live-fetch validation in the blocking test suite (rejected in favor of
  the vendored-fixture approach, for CI determinism).
- Mirroring the freshness check or any Python tooling into
  `release-service-catalog`.
- Validating `collect-task-params`'s `extractedValues[N]` positional-index
  correctness (belongs to `release-service-catalog`).
- `calunga-push-to-pulp-lightwell` (ruled out — no contract with
  `slan-cuan`).
