# slan-cuan

Release tooling for Red Hat Lightwell artifacts, shared across language ecosystems. For Java it extracts artifacts from PNC container images, signs them, registers SBOMs and attestations, and publishes to Pulp for distribution via `packages.redhat.com`. For Python it extracts wheels from component images, fetches Tekton Chains provenance, and filters release payloads against build-index purls. Other ecosystems (npm, ...) are expected to land as additional modules.

Packaged as a single container image that provides the Python CLI application (one entrypoint, ecosystem-specific subcommands) and Tekton Task definitions for Konflux pipeline orchestration.

## Repository layout

Shared core and per-ecosystem packages live side by side; an ecosystem kernel never leaks into the shared core.

```
slan_cuan/            # shared core: OCI client, models, utils, Pulp/Trustify clients,
                      #   and ecosystem-agnostic commands (register, generate-security-metadata, build-index-filter)
slan_cuan/java/       # Java ecosystem: extract, sign, publish, maven helpers
slan_cuan/python/     # Python ecosystem: PyPI filename/PURL kernel, extract+filter commands
tekton/tasks/         # Tekton Task manifests, one per CLI subcommand
tekton/tasks/python/  # Python-ecosystem task manifests (java tasks remain at the top
                      #   level until their live pipeline consumers are migrated in lockstep)
```

## Documentation

| Document | Purpose |
|----------|---------|
| [CLI Reference](docs/cli.md) | Global options, environment variables, architecture |
| [Extract](docs/extract.md) | Extract artifacts from PNC container images |
| [Sign](docs/sign.md) | Cryptographically sign Maven artifacts on RADAS |
| [Register](docs/register.md) | Upload SBOMs to Trustify for vulnerability cross-referencing |
| [Publish](docs/publish.md) | Publish Maven artifacts to Pulp |
| [Tekton Tasks](docs/tekton.md) | Tekton Task definitions and pipeline integration |
| [Integrity Tests](tests/integrity/README.md) | CLI<->Tekton pipeline contract tests, vendored `release-service-catalog` fixture |
| [Contributing](CONTRIBUTING.md) | Development setup, code style, adding subcommands |
