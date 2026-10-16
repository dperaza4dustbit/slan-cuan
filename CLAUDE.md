# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**slan-cuan** is the release pipeline for Red Hat Lightwell's Java artifacts. It is a Python CLI application packaged in a container image alongside Tekton Task definitions. The container image produced by this repository serves double duty: it provides both the Tekton Tasks (for Konflux pipeline orchestration) and the Python application that those Tasks execute.

Lightwell backports security fixes (CVEs) onto older versions of open-source Java libraries. `balor-cuan` builds the patched artifacts; `slan-cuan` releases them.

## Architecture

### Release Pipeline Stages

The application processes Java artifacts through these stages:

1. **Extract** -- Pull artifacts from the container image produced by PNC (Project Newcastle)
2. **Identify** -- Determine required components, Maven coordinates (GAV), and metadata
3. **Sign** -- Cryptographically sign the artifacts
4. **Register** -- Upload SBOMs and attestations to Atlas/Trustify (TPA) for vulnerability cross-referencing
5. **Publish** -- Push signed artifacts to Pulp for distribution via `packages.redhat.com`

### CLI Structure

Each subcommand maps 1:1 to a Tekton Task. The Tekton Task YAML invokes the corresponding subcommand inside the container image.

For details on the subcommand pattern and environment variable conventions, see [CLI documentation](docs/cli.md).

### Configuration

12-factor style (12factor.net): every setting is configurable via environment variables. CLI flags override environment variables when both are set. No config files.

### Container Image Layout

The single container image contains:
- The Python CLI application (entrypoint)
- Tekton Task YAML definitions (embedded at `/tekton/tasks/`)

Task definitions are also published as a Tekton OCI bundle (`<tag>-bundle`) for the `bundles` resolver. See [Tekton Bundle](docs/tekton.md#tekton-bundle).

### Tekton Tasks

Each CLI subcommand has a corresponding Tekton Task under `tekton/tasks/`. Ecosystem-specific subcommands and modules live in the `slan_cuan/java/` and `slan_cuan/python/` packages (new ecosystems get their own package beside them); shared core code stays out of ecosystem packages. Ecosystem-specific task manifests live under `tekton/tasks/<ecosystem>/`.
The naming convention is `slan-cuan-<subcommand>`.

| Subcommand | Tekton Task | Task YAML |
|------------|-------------|-----------|
| `extract` | `slan-cuan-extract` | `tekton/tasks/slan-cuan-extract.yaml` |
| `sign` | `slan-cuan-sign` | `tekton/tasks/slan-cuan-sign.yaml` |
| `register` | `slan-cuan-register` | `tekton/tasks/slan-cuan-register.yaml` |
| `publish` | `slan-cuan-publish` | `tekton/tasks/slan-cuan-publish.yaml` |
| `generate-security-metadata` | `slan-cuan-generate-security-metadata` | `tekton/tasks/slan-cuan-generate-security-metadata.yaml` |
| `generate-security-metadata-from-snapshot` | `slan-cuan-generate-security-metadata-from-snapshot` | `tekton/tasks/slan-cuan-generate-security-metadata-from-snapshot.yaml` |

**Invariant:** When adding or modifying a CLI subcommand, the corresponding
Tekton Task MUST be updated (and vice versa). The Task's `run` step
environment variables must match the subcommand's Click options and their
`envvar=` declarations. See [Tekton integration](docs/tekton.md) for the
full environment variable mapping.

## Domain Context

### Upstream Systems

- **PNC (Project Newcastle)** -- IBM's enterprise Java build system. Produces the artifacts that `slan-cuan` releases. Generates CycloneDX SBOMs and SLSA provenance via its PiG component.
- **balor-cuan** -- Experimental hermetic archival within Lightwell. Uses a Python Click CLI (`cuan`) with `onboard` and `refire` subcommands.
- **Hermeto** (formerly Cachi2) -- Red Hat's dependency pre-fetch tool for hermetic builds.

### Downstream Systems

- **Trustify (TPA)** -- SBOM ingestion and continuous CVE cross-referencing service.
- **Pulp** -- Repository management for artifact distribution (S3 + CDN).
- **Enterprise Contract (Conforma)** -- Policy-as-code gate evaluated before release.

### Konflux Integration

Tasks run inside Konflux pipelines. Key patterns:
- **Trusted Artifacts (TA)** -- Source and build outputs pass between Tasks as OCI artifacts (`SOURCE_ARTIFACT`), not PVC-backed workspaces.
- **Tekton Chains** -- SLSA provenance signing happens automatically for container images; JAR-level attestation requires explicit `ARTIFACT_OUTPUTS` type hints.
- **Bundle-referenced Tasks** -- Tasks are published as a Tekton OCI bundle at `quay.io/light-castle/slan-cuan:<tag>-bundle`. Consumers reference individual Tasks via the `bundles` resolver. See [Tekton Bundle](docs/tekton.md#tekton-bundle).
- **computeResources** -- Override step-level resource limits at the PipelineRun level via `taskRunSpecs[]` to avoid quota exhaustion from Tekton's container-per-step model.

## Documentation

This project uses **progressive disclosure** with three layers:

1. **`README.md`** -- Map-of-content index. Links to everything, explains nothing in depth.
2. **`docs/`** -- Detailed documentation on architecture, domain concepts, Tekton integration, and operations.
3. **`CONTRIBUTING.md`** -- Development workflow, coding standards, and conventions. Serves both human contributors and agentic tools.

**Never duplicate information across layers.** Link to the specific header in the canonical location instead. When adding or modifying documentation, find where the topic already lives before writing. If a concept is explained in `docs/`, CONTRIBUTING.md and README.md should link to it, not restate it.

**This file (`CLAUDE.md`) follows the same rule.** Once `CONTRIBUTING.md` and `docs/` exist, move detailed content there and replace it here with links to the specific headers (e.g., `[CLI Structure](CONTRIBUTING.md#cli-structure)`, `[Konflux Integration](docs/tekton.md#konflux-integration)`). The `CLAUDE.md` should contain only what Claude Code needs beyond what those files already provide.

## Code Formatting

**Before every commit**, run `ruff check --fix . && ruff format .` (or the
equivalent `poe fmt && poe format-fix`) to fix lint and formatting issues.
Always verify with `ruff check . && ruff format --check .` afterwards. Never
commit code that fails these checks.

If a virtual environment exists at `.venv/`, use `.venv/bin/ruff`; otherwise
fall back to `uvx ruff`.

## Naming Convention

The Lightwell project uses an Irish mythology naming convention:
- **balor-fianna** -- production CI pipeline (GitLab CI + Tekton/Konflux)
- **balor-cuan** -- hermetic archival and offline rebuild
- **slan-cuan** -- release pipeline (this project)
