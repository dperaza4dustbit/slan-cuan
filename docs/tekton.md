# Tekton Tasks

Each CLI subcommand has a corresponding Tekton Task under `tekton/tasks/`. The Task YAML invokes the CLI via environment variables inside the container image.

## Task Naming Convention

Tasks follow the pattern `slan-cuan-<subcommand>`:

| Subcommand | Tekton Task | Task YAML |
|------------|-------------|-----------|
| `extract` | `slan-cuan-extract` | `tekton/tasks/slan-cuan-extract.yaml` |
| `sign` | `slan-cuan-sign` | `tekton/tasks/slan-cuan-sign.yaml` |
| `register` | `slan-cuan-register` | `tekton/tasks/slan-cuan-register.yaml` |
| `publish` | `slan-cuan-publish` | `tekton/tasks/slan-cuan-publish.yaml` |
| `generate-security-metadata` | `slan-cuan-generate-security-metadata` | `tekton/tasks/slan-cuan-generate-security-metadata.yaml` |

## Task Structure

Each Task contains a single `run` step that executes the corresponding CLI subcommand. The step uses environment variables to configure the CLI:

```yaml
steps:
  - name: run
    image: quay.io/light-castle/slan-cuan:latest
    args:
      - <subcommand>
    env:
      - name: SLAN_CUAN_<SUBCOMMAND>_<OPTION>
        value: $(params.OPTION)
      - name: SLAN_CUAN_TEKTON_RESULTS_DIR
        value: $(step.results)
```

Task parameters map directly to CLI options. See [Environment Variable Mapping](#environment-variable-mapping) for the full list.

## Trusted Artifacts

Tasks do NOT include Trusted Artifact steps for data movement. Consumer pipelines are responsible for orchestrating data flow between Tasks.

The typical three-step pattern for pipeline operators:

1. **use-trusted-artifact** -- Fetch inputs from OCI artifact storage
2. **slan-cuan-<subcommand>** -- Run the CLI step
3. **create-trusted-artifact** -- Push outputs to OCI artifact storage

This separation keeps Tasks focused on business logic and allows pipeline authors to choose their data movement strategy (Trusted Artifacts, workspaces, or other mechanisms).

## Distribution

### Container Image

The container image is published at `quay.io/light-castle/slan-cuan`. It contains:

- The `slan-cuan` CLI (entrypoint)
- Tekton Task YAML definitions at `/tekton/tasks/`

### Tekton Bundle

Task definitions are also published as a Tekton OCI bundle:

    quay.io/light-castle/slan-cuan:<tag>-bundle

The bundle contains all four Task resources. Tags are synchronized with the CLI image (`latest` → `latest-bundle`, `0.1.0` → `0.1.0-bundle`).

#### Referencing Tasks from the Bundle

```yaml
taskRef:
  resolver: bundles
  params:
    - name: bundle
      value: quay.io/light-castle/slan-cuan:latest-bundle
    - name: name
      value: slan-cuan-extract
    - name: kind
      value: task
```

For production pipelines, pin by digest:

```yaml
- name: bundle
  value: quay.io/light-castle/slan-cuan@sha256:<digest>
```

#### Inspecting the Bundle

```bash
tkn bundle list quay.io/light-castle/slan-cuan:latest-bundle
```

## Required Kubernetes Secrets

Tasks reference these Kubernetes Secrets via parameters:

| Secret Name | Format | Used By | Keys |
|-------------|--------|---------|------|
| `registry-auth` | `.dockerconfigjson` | extract | Standard Docker config format |
| `lightwell-radas-certificates` | Opaque | sign | `nonprod.crt`, `nonprod.pem`, `nonprod.pw`, `ca-custom-bundle.crt` (RADAS certificates and key password) |
| `trustify-sso` | Opaque | register | `client-id`, `client-secret` |
| `pulp-tbr-auth` | Opaque | publish | `username`, `password` |
| `pulp-entitlement-cert` | kubernetes.io/tls | publish | `tls.crt`, `tls.key` |
| Custom CA cert | Opaque | register, publish | `ca.crt` (optional) |

Secret names for `registry-auth` and `trustify-sso` are configurable via Task parameters. The `lightwell-radas-certificates` secret name is hardcoded in the sign Task.

## Environment Variable Mapping

Tasks expose CLI options as Tekton parameters. The parameter values map to environment variables consumed by the CLI.

### Global Options

| Task Parameter | Environment Variable | Used By |
|----------------|---------------------|---------|
| `CA_CERT_PATH` | `SLAN_CUAN_CA_CERT` | All |
| `VERBOSE` | `SLAN_CUAN_VERBOSE` | All |
| `DRY_RUN` | `SLAN_CUAN_DRY_RUN` | All |

All Tasks automatically set `SLAN_CUAN_TEKTON_RESULTS_DIR=$(step.results)` to enable result file output.

### Extract

| Task Parameter | Environment Variable | CLI Flag |
|----------------|---------------------|----------|
| `IMAGE` | `SLAN_CUAN_EXTRACT_IMAGE` | `--image` |
| `REGISTRY_AUTH_SECRET` | `SLAN_CUAN_EXTRACT_REGISTRY_AUTH_FILE` | `--registry-auth-file` |
| `FORCE` | `SLAN_CUAN_EXTRACT_FORCE` | `--force` |

**Results:**
- `MANIFEST_DIGEST` -- OCI manifest digest of the extracted image
- `DELIVERABLE_DIR` -- Name of the deliverable directory inside the artifact

### Sign

| Task Parameter | Environment Variable | CLI Flag |
|----------------|---------------------|----------|
| `SIGN_REPO_URL` | `SLAN_CUAN_SIGN_REPO_URL` | `--repo-url` |
| `SIGNING_KEY` | `SLAN_CUAN_SIGN_SIGNING_KEY` | `--signing-key` |
| `RADAS_UMB_HOST` | `SLAN_CUAN_RADAS_UMB_HOST` | `--radas-umb-host` |
| `RADAS_RESULT_QUEUE` | `SLAN_CUAN_RADAS_RESULT_QUEUE` | `--radas-result-queue` |
| `RADAS_REQUEST_CHANNEL` | `SLAN_CUAN_RADAS_REQUEST_CHANNEL` | `--radas-request-channel` |
| -- | `SLAN_CUAN_RADAS_CLIENT_CA` | `--radas-client-ca` |
| -- | `SLAN_CUAN_RADAS_CLIENT_KEY` | `--radas-client-key` |
| -- | `SLAN_CUAN_RADAS_CLIENT_KEY_PASS_FILE` | `--radas-client-key-pass-file` |
| -- | `SLAN_CUAN_RADAS_ROOT_CA` | `--radas-root-ca` |
| `RADAS_RECEIVER_TIMEOUT` | `SLAN_CUAN_RADAS_RECEIVER_TIMEOUT` | `--radas-receiver-timeout` |
| `REQUESTER_ID` | `SLAN_CUAN_SIGN_REQUESTER_ID` | `--requester-id` |
| `SIGN_ZIP_ROOT_PATH` | `SLAN_CUAN_SIGN_ZIP_ROOT_PATH` | `--zip-root-path` |
| `SIGN_PRODUCT_KEY` | `SLAN_CUAN_SIGN_PRODUCT_KEY` | `--product-key` |
| `SIGN_IGNORE_PATTERNS` | `SLAN_CUAN_SIGN_IGNORE_PATTERNS` | `--ignore-patterns` |
| `REGISTRY_AUTH_SECRET` | `SLAN_CUAN_SIGN_REGISTRY_AUTH_FILE` | `--registry-auth-file` |
| `DIRECT_SIGN` | `SLAN_CUAN_SIGN_DIRECT_SIGN` | `--direct-sign` |
| `DIRECT_SIGN_PIPELINE_NAME` | `SLAN_CUAN_SIGN_DIRECT_SIGN_PIPELINE_NAME` | `--direct-sign-pipeline-name` |
| `DIRECT_SIGN_TASK_GIT_URL` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_GIT_URL` | `--direct-sign-task-git-url` |
| `DIRECT_SIGN_TASK_GIT_REVISION` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_GIT_REVISION` | `--direct-sign-task-git-revision` |
| `DIRECT_SIGN_VERBOSE` | `SLAN_CUAN_SIGN_DIRECT_SIGN_VERBOSE` | `--direct-sign-verbose` |
| `ociStorage` | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_STORAGE` | `--direct-sign-task-ta-storage` |
| -- | `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_SOURCE_ARTIFACT_FILE` | `--direct-sign-task-ta-source-artifact-file` |

For direct signing, `SLAN_CUAN_SIGN_DIRECT_SIGN_TASK_TA_SOURCE_ARTIFACT_FILE` is
wired to a fixed in-pod path (`/var/workdir/direct-sign-sourceDataArtifact`)
written by the `create-direct-sign-input-trusted-artifact` step, not to a task
parameter. See [Direct Signing](sign.md#direct-signing).

**Results:** None

### Register

| Task Parameter | Environment Variable | CLI Flag |
|----------------|---------------------|----------|
| `TRUSTIFY_API_URL` | `SLAN_CUAN_REGISTER_TRUSTIFY_API_URL` | `--trustify-api-url` |
| `SSO_TOKEN_URL` | `SLAN_CUAN_REGISTER_SSO_TOKEN_URL` | `--sso-token-url` |
| `SSO_CLIENT_ID` | `SLAN_CUAN_REGISTER_SSO_CLIENT_ID` | `--sso-client-id` |
| `SSO_CLIENT_SECRET` | `SLAN_CUAN_REGISTER_SSO_CLIENT_SECRET` | `--sso-client-secret` |
| `INSECURE` | `SLAN_CUAN_REGISTER_INSECURE` | `--insecure` |
| `RETRIES` | `SLAN_CUAN_REGISTER_RETRIES` | `--retries` |

**Results:**
- `SBOM_URN` -- Trustify URN of the uploaded SBOM

### Publish

| Task Parameter | Environment Variable | CLI Flag |
|----------------|---------------------|----------|
| `PULP_URL` | `SLAN_CUAN_PUBLISH_PULP_URL` | `--pulp-url` |
| `PULP_REPOSITORY` | `SLAN_CUAN_PUBLISH_PULP_REPOSITORY` | `--pulp-repository` |
| `INSECURE` | `SLAN_CUAN_PUBLISH_INSECURE` | `--insecure` |
| `PULP_AUTH_TYPE` | `SLAN_CUAN_PUBLISH_PULP_AUTH_TYPE` | `--pulp-auth-type` |
| `PULP_USERNAME` | `SLAN_CUAN_PUBLISH_PULP_USERNAME` | `--pulp-username` |
| `PULP_PASSWORD` | `SLAN_CUAN_PUBLISH_PULP_PASSWORD` | `--pulp-password` |
| `PULP_CLIENT_CERT` | `SLAN_CUAN_PUBLISH_PULP_CLIENT_CERT` | `--pulp-client-cert` |
| `PULP_CLIENT_KEY` | `SLAN_CUAN_PUBLISH_PULP_CLIENT_KEY` | `--pulp-client-key` |
| `SKIP_ASSOCIATE` | `SLAN_CUAN_PUBLISH_SKIP_ASSOCIATE` | `--skip-associate` |

**Results:**
- `ARTIFACTS_UPLOADED` -- Count of successfully uploaded artifacts
- `ARTIFACTS_SKIPPED` -- Count of skipped artifacts (already published)
- `PUBLISHED_ARTIFACT_OUTPUTS` -- JSON object with `uri` and `digest` keys for Tekton Chains SLSA provenance

## Pipeline Topology

The typical pipeline topology is sequential:

```
extract → sign → register → publish
```

Data flows between Tasks via a shared workspace or Trusted Artifacts. Each stage consumes the output of the previous stage:

1. **extract** produces `extract-result.json` in the artifact directory
2. **sign** reads the artifact directory and produces signed outputs
3. **register** reads `extract-result.json` to locate the SBOM
4. **publish** reads `extract-result.json` to discover artifacts for upload

Pipeline authors MUST ensure the artifact directory persists across Tasks (via PVC workspace, Trusted Artifacts, or equivalent).

## Tekton Chains Integration

The `publish` Task emits a `PUBLISHED_ARTIFACT_OUTPUTS` result as a JSON object with `uri` and `digest` keys:

```json
{"uri": "https://pulp.example.com/pulp/maven/repo/", "digest": ""}
```

The `-ARTIFACT_OUTPUTS` suffix triggers Tekton Chains to include the published artifacts as SLSA provenance subjects. The `uri` field contains the Pulp distribution URL; `digest` is reserved for future per-artifact attestation.

For Chains to process the result, the Task result type must be `object` with `uri` and `digest` properties. See the Tekton Chains documentation for details.
