# slan-cuan

Release pipeline for Red Hat Lightwell's Java artifacts. Extracts artifacts from PNC container images, signs them, registers SBOMs and attestations, and publishes to Pulp for distribution via `packages.redhat.com`.

Packaged as a container image that provides both the Python CLI application and Tekton Task definitions for Konflux pipeline orchestration.

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
