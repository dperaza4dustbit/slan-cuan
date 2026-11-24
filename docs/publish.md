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
OSV files are present, `--pulp-file-repository` is required and is resolved
before Maven content is uploaded or its repository is modified. Generated
VEX documents require `--pulp-vex-repository` the same way. A clean GAV
index with no generated OSV files does not require a File repository.

Security metadata may only contain OSV records and VEX documents. Any other
CycloneDX document (an SBOM, including one with `"vulnerabilities": []` or
with `components[]`) fails validation before anything is uploaded: SBOMs are
injected next to the artifact in the Maven repository (`enriched-sboms/`),
never published to the OSV or VEX File repository.

## Embargo And Predisclosure Routing

When the GAV index contains an `LW-` vulnerability ID, the build is treated as
security-embargoed. `publish` resolves `--pulp-repository` and verifies that
the backend Maven repository is served by the `java/predisclosure` Maven
distribution before uploading any content. A repository with no distribution,
a non-predisclosure distribution, or an unreadable distribution lookup fails
closed.

Embargoed dry runs perform this same read-only Pulp validation and therefore
require Pulp credentials. Dry runs for builds without `LW-` IDs remain
offline and do not create a Pulp client.

A backend repository is valid for embargoed content when its associated
distribution serves `java/predisclosure`.

`LW-` builds produce OSV records (and VEX documents) for the novel fix, so
the OSV coverage check and the `--pulp-file-repository` requirement apply to
them as to any vulnerable build. A build with `LW-` IDs and no OSV metadata
fails.

For a build with any `LW-` ID (from the GAV index, or named in any generated
OSV/VEX file), **all** of its security metadata is embargoed content, whatever
the IDs or source inside individual files. Right after the Maven
`java/predisclosure` check, before any upload and also in dry-run mode,
`publish` fails closed unless each File repository that receives files is
served by a predisclosure distribution in Pulp:

- the File distribution named like `--pulp-file-repository` (and, when VEX is
  present, like `--pulp-vex-repository`) must exist, and its `base_path` must
  have a `predisclosure` segment (e.g. `osv/java/predisclosure`);
- a missing distribution or an unreadable lookup fails closed.

This checks where the content is actually served, not the repository name,
so an existing novel repository such as `osv-java-novel` qualifies when its
distribution serves a predisclosure path.

Every OSV record and VEX document of such a build is uploaded to those
predisclosure repositories without backport/novel source filtering, so a
CVE-only file of an `LW-` build is not dropped. GitHub OSV publication is
skipped for the build, even when configured: nothing from an `LW-` build is
pushed to the public repository.

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
| `--pulp-repository` | string | Yes | -- | Backend Maven repository name |
| `--pulp-domain` | string | No | -- | Pulp domain for domain-scoped deployments (e.g. `lightwell`) |
| `--artifact-dir` | path | Yes | -- | Extract stage output directory |
| `--insecure` | flag | No | `False` | Disable TLS certificate verification |
| `--pulp-auth-type` | choice | No | `tbr` | Authentication method (`tbr` or `cert`) |
| `--pulp-username` | string | When `tbr` | -- | Username for TBR basic auth |
| `--pulp-password` | string | When `tbr` | -- | Password for TBR basic auth |
| `--pulp-client-cert` | path | When `cert` | -- | Client certificate for entitlement cert auth |
| `--pulp-client-key` | path | When `cert` | -- | Client key for entitlement cert auth |
| `--upload-workers` | integer | No | `4` | Number of concurrent upload threads |
| `--skip-associate` | flag | No | off | Upload and label content but skip the repository modify (see Skip Association) |
| `--pulp-file-repository` | string | When OSV present | -- | Pulp File repository name for OSV upload |
| `--pulp-vex-repository` | string | When VEX present | -- | Pulp File repository name for VEX upload |
| `--github-osv-repo` | string | No | -- | GitHub repo (`owner/name`) to also publish OSV records to |
| `--github-osv-token` | string | With `--github-osv-repo` | -- | Token with write access to the OSV repo |
| `--github-osv-branch` | string | No | `main` | Branch to commit records onto |
| `--github-osv-path` | string | No | `advisories` | Directory prefix inside the OSV repo (osv.dev ingests only this directory; empty means repo root) |

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
| `--skip-associate` | `SLAN_CUAN_PUBLISH_SKIP_ASSOCIATE` |
| `--pulp-file-repository` | `SLAN_CUAN_PUBLISH_PULP_FILE_REPOSITORY` |
| `--pulp-vex-repository` | `SLAN_CUAN_PUBLISH_PULP_VEX_REPOSITORY` |
| `--github-osv-repo` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_REPO` |
| `--github-osv-token` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_TOKEN` |
| `--github-osv-branch` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_BRANCH` |
| `--github-osv-path` | `SLAN_CUAN_PUBLISH_GITHUB_OSV_PATH` |

## Security Metadata (OSV) Publication

Generated OSV/VEX records are published to two destinations:

- **Pulp File repository** (`--pulp-file-repository`) — required whenever the
  GAV index lists vulnerabilities or generated OSV metadata is present.
  Records are routed by type against the repository name
  (`osv-java-backport`/`osv-java-novel`); see the routing note in
  `slan_cuan/java/publish.py`.
- **Pulp VEX repository** (`--pulp-vex-repository`) — required when generated
  VEX documents are present. VEX uses the same upload and backport/novel
  routing as OSV, against the VEX repository name. A
  CycloneDX file is VEX when `vulnerabilities` is a non-empty list and
  `components` is absent. Before any upload the run fails when the VEX
  repository:
  - is missing, or equals `--pulp-file-repository` (VEX never goes to the OSV
    repository);
  - is not recognized as backport/novel by name (it must contain `backport`
    or `novel`, e.g. `vex-java-backport`, `vex-java-novel`).

  VEX naming an `LW-` ID makes the whole build embargoed, so its VEX
  repository must be served by a predisclosure distribution (gate above).
- **GitHub repository** (`--github-osv-repo`, optional) — when set together
  with `--github-osv-token`, records are committed and pushed to the OSV git
  repository (e.g. `project-lightwell/lightwell-osv`) under
  `--github-osv-path` as a single commit. This runs **in addition to** the
  Pulp upload; leaving `--github-osv-repo` unset disables it and preserves
  Pulp-only behavior.

Pulp File publication is upload-only. Each file lands in the File repository
as a new repository version, and the repository-backed distributions managed
by pulp-config auto-publish every version, so the distribution always serves
the latest content. `publish` does not create a File publication or repoint a
distribution; before uploading anything it fails closed unless the
distribution named like the repository serves that repository and the
repository has autopublish enabled (LWLP-4823). A drifted distribution is
repaired by re-applying the pulp-config environment, not by this command.

The GitHub repository is a public feed ingested by osv.dev, so its record set
is selected independently of the Pulp routing and fails closed:

- Nothing is pushed for a build with any `LW-` ID (build-level); publication
  to GitHub is skipped with a message.
- Only OSV records whose source is `pnc-build` (remediated backports) are
  pushed. VEX documents and `novel-pipeline` records are never pushed.
- An OSV record whose source cannot be classified fails the run.
- When security metadata is present, `--pulp-file-repository` must be
  recognized as the backport repository; a novel or unrecognized repository
  name fails the run.

These checks run before anything is uploaded to Pulp. In Tekton, the token
comes from the Secret named by the `GITHUB_OSV_TOKEN_SECRET` param (key
`token`); a missing Secret or key surfaces as an empty-token error naming that
param.

GitHub publication is idempotent: re-publishing records identical to the
repository's current contents produces no commit. The pushed commit SHA and
record count are recorded in `publish-result.json`
(`github_osv_commit`, `github_osv_uploaded`) and exposed as the
`GITHUB_OSV_COMMIT` and `GITHUB_OSV_UPLOADED` Tekton results. A separate
`github_osv_configured` flag (Tekton result `GITHUB_OSV_CONFIGURED`)
distinguishes an in-sync no-op (configured, 0 uploaded) from a run where
GitHub publication was never enabled.

**Concurrency.** Records are written one file per CVE ID, so concurrent
releases produce net-new, disjoint files. If a competing release pushes first,
this run's shallow clone becomes stale and its push is rejected
non-fast-forward; the client then re-clones from fresh HEAD and replays the
copy/commit/push (it never rebases), with exponential backoff and jitter
between attempts. Git network operations are bounded by a per-command timeout.

After exhausting retries — or on a non-retriable failure such as bad
credentials or a protected branch — the command fails the run (non-zero exit)
rather than letting the pipeline go green on a partial publish. This is safe
because the whole command is cleanly retriable: Pulp Maven content is
content-addressed (a re-upload reuses the existing content unit and re-adding it
to the repository is a no-op), the OSV/VEX File upload is keyed by sha256, and
the GitHub push is idempotent (in-sync → no commit). Re-running `publish` after
a GitHub failure therefore converges without duplicating anything.

**Re-publication semantics.** Records with a name already present are
overwritten (last-writer-wins). For deterministic record generation this never
changes bytes; if it does, the command logs a warning naming each changed
record before overwriting it.

The token is supplied to git via a `GIT_ASKPASS` helper and never appears on a
command line (so it is not exposed through `/proc/<pid>/cmdline`).

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

## Skip Association

`--skip-associate` (LWLP-6026) keeps the uploads and `source_image` labels but skips the repository modify (`add_and_remove`):

- The content stays unassociated for a later batch association.
- `publish-result.json` lists every `content_unit_hrefs` entry, with `repository_version: null`.
- OSV/VEX file records are published as usual.
- Off by default; behaviour is unchanged unless set.

## Retry Behavior

Every Pulp API call retries transient failures -- HTTP 5xx responses and connection errors -- with exponential backoff (about 1s, then 2s, capped at 30s per sleep, plus up to 25% random jitter). The run fails only after 3 consecutive failed attempts, with the same error as before. HTTP 4xx responses are never retried, and timeouts are not retried because the server may still be processing the request.

These process-wide settings apply to every subcommand that talks to Pulp, so they are plain environment variables rather than per-subcommand flags:

| Environment Variable | Default | Meaning |
|---------------------|---------|---------|
| `SLAN_CUAN_PULP_RETRIES` | `3` | Total attempts per request (initial + retries) |
| `SLAN_CUAN_PULP_BACKOFF_SECONDS` | `1.0` | Base backoff, doubled per attempt |

## Dry-Run Behavior

With `--dry-run`, loads the extract result and discovers artifacts but does not upload. Displays the authentication type, distribution name, Pulp URL, artifact count, coordinate count, and each artifact path that would be uploaded. When GitHub OSV publication is configured, it also reports the repository, branch, and number of records that would be pushed.

## Tekton Task

The corresponding Tekton Task is `slan-cuan-publish`, defined at `tekton/tasks/slan-cuan-publish.yaml`.

See [Tekton Tasks](tekton.md) for integration details.
