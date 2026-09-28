# Publish

Upload Maven artifacts to a Pulp repository for distribution via `packages.redhat.com`.

## What It Does

1. Reads `extract-result.json` from the artifact directory
2. Discovers Maven artifacts in the `repository/` tree
3. Parses Maven coordinates (group, artifact, version) from directory paths
4. Reads checksum sidecars (`.md5`, `.sha1`, `.sha256`)
5. Uploads each artifact to Pulp via the Maven deploy endpoint
6. Saves `publish-result.json` with upload summary

If extracted GAV index data lists vulnerability IDs (`vulns`), or generated
security metadata files are present, `--pulp-file-repository` is required and
is resolved before Maven content is uploaded or its repository is modified.
A clean GAV index with no generated OSV files does not require a File
repository.

When `--pulp-domain` is set, the deploy URL includes the domain segment (`/pulp/maven/{domain}/{distribution}/{path}`). When not set, it uses the standard path (`/pulp/maven/{distribution}/{path}`).

The artifact directory must be the output of the `extract` stage, containing a valid `extract-result.json`.

## Pulp Labels

Every content unit uploaded to Pulp is tagged with a `pulp_labels` metadata field containing the fully qualified OCI image reference of the source container:

```json
{"source_image": "quay.io/light-castle/example@sha256:abc123..."}
```

Labels are always attached — no flag is needed. The value is the `str()` representation of the `ImageReference` parsed during the extract stage, which includes registry, repository, and digest (or tag when digest is unavailable).

Labels are also:
- Persisted in `publish-result.json` under the `pulp_labels` key
- Exposed as a `PULP_LABELS` Tekton result for downstream pipeline tasks

## Options

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--pulp-url` | string | Yes | -- | Pulp instance base URL |
| `--pulp-repository` | string | Yes | -- | Maven distribution name |
| `--pulp-domain` | string | No | -- | Pulp domain for domain-scoped deployments (e.g. `lightwell`) |
| `--artifact-dir` | path | Yes | -- | Extract stage output directory |
| `--insecure` | flag | No | `False` | Disable TLS certificate verification |
| `--pulp-auth-type` | choice | No | `tbr` | Authentication method (`tbr` or `cert`) |
| `--pulp-username` | string | When `tbr` | -- | Username for TBR basic auth |
| `--pulp-password` | string | When `tbr` | -- | Password for TBR basic auth |
| `--pulp-client-cert` | path | When `cert` | -- | Client certificate for entitlement cert auth |
| `--pulp-client-key` | path | When `cert` | -- | Client key for entitlement cert auth |
| `--upload-workers` | integer | No | `4` | Number of concurrent upload threads |
| `--pulp-file-repository` | string | When OSV present | -- | Pulp File repository name for OSV/VEX upload |
| `--github-osv-repo` | string | No | -- | GitHub repo (`owner/name`) to also publish OSV records to |
| `--github-osv-token` | string | With `--github-osv-repo` | -- | Token with write access to the OSV repo |
| `--github-osv-branch` | string | No | `main` | Branch to commit records onto |
| `--github-osv-path` | string | No | repo root | Directory prefix inside the OSV repo |

The `--insecure` flag is intended for development only. In production, use the global `--ca-cert` option for custom certificate authorities.

## Environment Variables

See [CLI Reference](cli.md#environment-variables) for naming conventions.

| Flag | Environment Variable |
|------|---------------------|
| `--pulp-url` | `SLAN_CUAN_PUBLISH_PULP_URL` |
| `--pulp-repository` | `SLAN_CUAN_PUBLISH_PULP_REPOSITORY` |
| `--pulp-domain` | `SLAN_CUAN_PUBLISH_PULP_DOMAIN` |
| `--artifact-dir` | `SLAN_CUAN_PUBLISH_ARTIFACT_DIR` |
| `--insecure` | `SLAN_CUAN_PUBLISH_INSECURE` |
| `--pulp-auth-type` | `SLAN_CUAN_PUBLISH_PULP_AUTH_TYPE` |
| `--pulp-username` | `SLAN_CUAN_PUBLISH_PULP_USERNAME` |
| `--pulp-password` | `SLAN_CUAN_PUBLISH_PULP_PASSWORD` |
| `--pulp-client-cert` | `SLAN_CUAN_PUBLISH_PULP_CLIENT_CERT` |
| `--pulp-client-key` | `SLAN_CUAN_PUBLISH_PULP_CLIENT_KEY` |
| `--upload-workers` | `SLAN_CUAN_PUBLISH_UPLOAD_WORKERS` |
| `--pulp-file-repository` | `SLAN_CUAN_PUBLISH_PULP_FILE_REPOSITORY` |
| `--github-osv-repo` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_REPO` |
| `--github-osv-token` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_TOKEN` |
| `--github-osv-branch` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_BRANCH` |
| `--github-osv-path` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_PATH` |

## Security Metadata (OSV) Publication

Generated OSV/VEX records are published to two destinations:

- **Pulp File repository** (`--pulp-file-repository`) — required whenever the
  GAV index lists vulnerabilities or generated security metadata is present.
  Records are routed by type against the repository name
  (`osv-java-backport`/`osv-java-novel`); see the routing note in
  `slan_cuan/publish.py`.
- **GitHub repository** (`--github-osv-repo`, optional) — when set together
  with `--github-osv-token`, the same filtered record set is committed and
  pushed to the OSV git repository (e.g.
  `project-lightwell/lightwell-osv`) as a single commit. This runs
  **in addition to** the Pulp upload; leaving `--github-osv-repo` unset
  disables it and preserves Pulp-only behavior.

GitHub publication is idempotent: re-publishing records identical to the
repository's current contents produces no commit. The pushed commit SHA and
record count are recorded in `publish-result.json`
(`github_osv_commit`, `github_osv_uploaded`) and exposed as the
`GITHUB_OSV_COMMIT` and `GITHUB_OSV_UPLOADED` Tekton results.

## Authentication

The `publish` command supports two authentication methods for Pulp, selected by `--pulp-auth-type`.

### TBR Basic Auth (default)

TBR (Terms-Based Registry) uses HTTP Basic Authentication. Both `--pulp-username` and `--pulp-password` are required.

```bash
slan-cuan publish \
    --pulp-url https://pulp.example.com \
    --pulp-repository my-repo \
    --pulp-domain lightwell \
    --pulp-username "$PULP_USER" \
    --pulp-password "$PULP_PASS" \
    --artifact-dir /var/workdir/extracted
```

### Entitlement Certificate Auth

Entitlement certificate auth uses mTLS (mutual TLS). Both `--pulp-client-cert` and `--pulp-client-key` are required.

```bash
slan-cuan publish \
    --pulp-url https://pulp.example.com \
    --pulp-repository my-repo \
    --pulp-domain lightwell \
    --pulp-auth-type cert \
    --pulp-client-cert /certs/client/tls.crt \
    --pulp-client-key /certs/client/tls.key \
    --artifact-dir /var/workdir/extracted
```

## Domain-Scoped Deployments

When Pulp has `DOMAIN_ENABLED=True`, set `--pulp-domain` to include the domain segment in deploy URLs. The Tekton Task defaults `PULP_DOMAIN` to `lightwell`.

Without `--pulp-domain`, the deploy URL is `/pulp/maven/{distribution}/{path}`. With `--pulp-domain`, it becomes `/pulp/maven/{domain}/{distribution}/{path}`.

## TLS Configuration

By default, TLS verification uses the system CA bundle. Two global options modify this behavior:

- `--ca-cert /path/to/ca.crt` — use a custom CA certificate bundle (e.g. for enterprise proxies or self-signed certificates)
- `--insecure` — disable TLS verification entirely (development only)

When both are set, `--insecure` takes precedence and `--ca-cert` is ignored.

Example with a custom CA:

```bash
slan-cuan --ca-cert /etc/ssl/certs/lan-ca.crt \
    publish --pulp-url https://rachael.home.lan ...
```

## Concurrent Uploads

Artifact uploads run concurrently using a thread pool sized by `--upload-workers` (default: 4). The repository modification (`modify_repository`) remains a single sequential call after all uploads complete. Set `--upload-workers 1` for sequential behavior.

## Dry-Run Behavior

With `--dry-run`, loads the extract result and discovers artifacts but does not upload. Displays the authentication type, distribution name, Pulp URL, artifact count, coordinate count, and each artifact path that would be uploaded. When GitHub OSV publication is configured, it also reports the repository, branch, and number of records that would be pushed.

## Tekton Task

The corresponding Tekton Task is `slan-cuan-publish`, defined at `tekton/tasks/slan-cuan-publish.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
