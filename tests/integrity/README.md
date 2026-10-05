# Integrity Tests

This suite verifies that slan-cuan's CLI still satisfies the contracts the
`slan-cuan-release` Tekton pipeline and its Tasks depend on, so an internal
refactor (like LWLP-2376) can't silently break them. See the design spec:
`docs/superpowers/specs/2026-10-02-slan-cuan-integrity-tests-design.md`.

All checks are generic and data-driven off the real `tekton/tasks/*.yaml`
files and the real `slan_cuan.cli.main` click object -- never a hand-written
table of expected options -- so adding or changing a task/option is
automatically covered without anyone remembering to add a matching
assertion.

## Layers and files

- **`cli_task_yaml_test.py`** (Layers A/B) -- for every Task YAML, the run
  step's subcommand must be a registered CLI command, and every
  `SLAN_CUAN_*` env var must resolve to a real option. This drives click's
  actual `Context`/`Parameter.resolve_envvar_value()` -- never reimplements
  click's auto-envvar naming rule -- by monkeypatching a sentinel value into
  `os.environ` and checking which parameter (group-level or
  subcommand-level) picks it up. Also checks the inverse: every required
  (no-default) option must have a wired env var somewhere in the Task.
- **`output_contract_test.py`** (Layer C) -- a few Task steps read CLI
  output paths directly via raw shell instead of another CLI call (e.g.
  `extract`'s `prepare-source-data` step hardcodes `extract-result.json`,
  `metadata`, `attachments`). These get an explicit test per occurrence,
  checked against the real constant/dirname, not a duplicated literal.
- **`tekton_results_test.py`** (Layer D) -- AST-parses each CLI command's
  callback for literal `write_tekton_result(..., "NAME", ...)` calls and
  asserts every name is declared in the Task's `results:`. Scoped per
  function (not per module), since `generate_security_metadata.py` hosts
  two commands.
- **`pipeline_contract_test.py`** (Layer E) -- cross-repo: see below.

## `pipeline_contract_test.py` caveats

This is the one layer that reaches outside this repo, into
`release-service-catalog`'s `slan-cuan-release.yaml` pipeline. There's no
live fetch in the blocking test suite -- it runs against a **pinned,
vendored snapshot** at
`fixtures/release-service-catalog/pipelines/managed/slan-cuan-release/slan-cuan-release.yaml`.

**What this means for a legitimate change:** if someone adds a param, renames
one, or rewires a task in `release-service-catalog`'s pipeline, this suite
will **not** see it until the fixture is refreshed. It is not watching that
repo live.

**How to refresh the fixture:** copy the current
`pipelines/managed/slan-cuan-release/slan-cuan-release.yaml` from
`release-service-catalog` over the vendored path above, and update the
header comment with the new source commit/revision.

**How to tell a real break from a stale fixture**, when
`pipeline_contract_test.py` fails:
- If the failure appears after a change to this repo's own
  `tekton/tasks/*.yaml` `params:` -- that's a real contract break. Fix the
  Task or the (separately vendored) fixture to match, whichever is wrong.
- If the failure appears with no related change in this repo -- the fixture
  is stale, most likely because `release-service-catalog` changed first.
  Refresh the fixture (see above) rather than "fixing" working code.

**Real example:** while this suite was first being built, it caught exactly
this kind of drift for real — `generate-security-metadata` and `publish`
were each missing a param their pipeline invocation already depended on
(`trustedArtifactsDebug` and `CA_CERT_SECRET` respectively). Both were fixed
(removing the former as genuinely-unused wiring, adding the latter as a real
missing capability) before this test ever shipped passing. This is the suite
doing exactly what it's for.

**Freshness check:** `scripts/check_pipeline_fixture_freshness.py` runs on
a weekly schedule (non-blocking -- never gates a PR) specifically to catch
staleness before it causes confusion. Its failure means "refresh the
fixture," not "a contract broke."

**Transitional state (as of this writing):** the vendored fixture reflects
a `release-service-catalog` branch (`fix/LWLP-2376-remove-dead-radas-umb-host-param`,
commit `2a3979f`) that has not yet merged to that repo's `development`
branch. Until it does: the weekly freshness job will fail -- expected, not
a bug. Do NOT "fix" that failure by refreshing the fixture from live
`development` in the meantime -- doing so would re-introduce the dead
`RADAS_UMB_HOST`/`trustedArtifactsDebug` wiring this branch removed.
`pipeline_contract_test.py`'s blocking tests would catch that immediately
(those params aren't declared on the tasks), but it's a confusing failure
to debug without this context. Once the sibling PR merges, refresh the
fixture normally and update this note/the header comment.

**Known gap, out of scope:** several params are wired through
`collect-task-params`'s positional `extractedValues[N]` array in the real
pipeline (e.g. `PULP_URL: $(tasks.collect-task-params.results.extractedValues[0])`),
whose correctness depends on index alignment with a separate
`keysToExtract` JSON list elsewhere in the same pipeline file. Verifying
that alignment would mean modeling `collect-task-params`'s own behavior,
which belongs to `release-service-catalog`, not slan-cuan's contract. Not
covered here.
