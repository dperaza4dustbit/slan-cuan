#!/usr/bin/env bash
# npm-sbom-publish: discover a CycloneDX referrer, push it, label Pulp.
# Missing referrers skip. oras and curl are stubs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/scripts/npm/npm-sbom-publish"
HEX64="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REF64="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
REF2_64="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
PUSH64="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
IMAGE="quay.io/example/snapshot@sha256:${HEX64}"
PREFIX="quay.io/example/compliance"
fail=0

assert_eq() {
  local got="$1" want="$2" msg="$3"
  if [[ "${got}" != "${want}" ]]; then
    echo "FAIL: ${msg}: got='${got}' want='${want}'" >&2
    fail=1
  else
    echo "ok: ${msg}"
  fi
}

assert_ok() {
  local msg="$1"
  shift
  if "$@"; then
    echo "ok: ${msg}"
  else
    echo "FAIL: ${msg} (exit $?)" >&2
    fail=1
  fi
}

assert_fail() {
  local msg="$1"
  shift
  if "$@"; then
    echo "FAIL: ${msg}: expected non-zero" >&2
    fail=1
  else
    echo "ok: ${msg}"
  fi
}

write_cdx() {
  local path="$1" name="$2" version="$3"
  jq -n --arg name "${name}" --arg version "${version}" \
    '{bomFormat: "CycloneDX", specVersion: "1.6",
      metadata: {component: {name: $name, version: $version}}}' > "${path}"
}

install_stubs() {
  local bin="$1"
  mkdir -p "${bin}"
  cat > "${bin}/oras" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${ORAS_LOG}"
# ORAS_OPTIONS is prepended, so flags can precede the subcommand.
cmd=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --registry-config)
      shift 2
      ;;
    --registry-config=*)
      shift
      ;;
    discover|pull|push|resolve)
      cmd="$1"
      shift
      break
      ;;
    *)
      echo "unexpected oras $1" >&2
      exit 1
      ;;
  esac
done
case "${cmd}" in
  discover)
    if [[ "${DISCOVER_FAIL:-}" == "1" ]]; then
      echo "discover failed" >&2
      exit 1
    fi
    cat "${DISCOVER_JSON}"
    ;;
  pull)
    out=""
    prev=""
    for arg in "$@"; do
      if [[ "${prev}" == "-o" ]]; then
        out="${arg}"
      fi
      prev="${arg}"
    done
    mkdir -p "${out}"
    src="${CDX_FILE}"
    if [[ "$*" == *"sha256:${REF2_64}"* && -n "${CDX_FILE_2:-}" ]]; then
      src="${CDX_FILE_2}"
    fi
    cp "${src}" "${out}/pkg.cdx.json"
    ;;
  push)
    echo "Digest: sha256:${PUSH64}"
    ;;
  resolve)
    echo "sha256:${PUSH64}"
    ;;
  *)
    echo "unexpected oras ${cmd}" >&2
    exit 1
    ;;
esac
EOF
  cat > "${bin}/curl" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${CURL_LOG}"
url="${*: -1}"
if [[ "${url}" == *set_label/* ]]; then
  exit 0
fi
printf '%s\n' '{"pulp_labels":{}}'
EOF
  chmod +x "${bin}/oras" "${bin}/curl"
}

prepare_tree() {
  local work="$1"
  mkdir -p "${work}/files/sha256_${HEX64}" "${work}/secret"
  printf 'user\n' > "${work}/secret/username"
  printf 'pass\n' > "${work}/secret/password"
  printf '%s\n' "${IMAGE}" > "${work}/images.txt"
  : > "${work}/files/sha256_${HEX64}/bluebird-3.7.2.tgz"
  install_stubs "${work}/bin"
}

run_publish() {
  local work="$1"
  shift
  PATH="${work}/bin:${PATH}" \
    FILES_DIR="${work}/files" \
    IMAGES_TXT="${work}/images.txt" \
    SBOM_IMAGE_PREFIX="${PREFIX}" \
    SBOM_CACHE_DIR="${work}/cache" \
    PULP_BASE_URL="https://pulp.example" \
    SECRET_DIR="${work}/secret" \
    ORAS_OPTIONS="--registry-config ${work}/push-auth.json" \
    ORAS_LOG="${work}/oras.log" \
    CURL_LOG="${work}/curl.log" \
    DISCOVER_JSON="${work}/discover.json" \
    CDX_FILE="${work}/cdx.json" \
    CDX_FILE_2="${work}/cdx-2.json" \
    REF2_64="${REF2_64}" \
    PUSH64="${PUSH64}" \
    "${SCRIPT}" \
      "${work}/files/sha256_${HEX64}/bluebird-3.7.2.tgz" \
      "/pulp/api/v3/content/npm/packages/1/" \
      "bluebird" \
      "3.7.2" \
      "$@"
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
prepare_tree "${work}"

# No image list: skip, do not call oras.
rm -f "${work}/images.txt"
: > "${work}/oras.log"
assert_ok "missing images.txt skips" run_publish "${work}"
assert_eq "$(wc -l < "${work}/oras.log" | tr -d ' ')" "0" \
  "missing images.txt does not call oras"
printf '%s\n' "${IMAGE}" > "${work}/images.txt"

# Referrer for a different package: skip, no push.
write_cdx "${work}/cdx.json" "other" "1.0.0"
jq -n --arg ref "quay.io/example/snapshot@sha256:${REF64}" --arg digest "sha256:${REF64}" \
  '{referrers: [{reference: $ref, digest: $digest, artifactType: "application/vnd.cyclonedx+json"}]}' \
  > "${work}/discover.json"
: > "${work}/oras.log"
assert_ok "unmatched referrer skips" run_publish "${work}"
if grep -q '^push ' "${work}/oras.log"; then
  echo "FAIL: unmatched referrer pushed an OCI" >&2
  fail=1
else
  echo "ok: unmatched referrer does not push"
fi

# Empty referrer list: skip. This is the Calunga snapshot shape.
rm -rf "${work}/cache"
printf '%s\n' '{"referrers":[]}' > "${work}/discover.json"
: > "${work}/oras.log"
assert_ok "empty referrer list skips" run_publish "${work}"
if grep -q 'pull \|push ' "${work}/oras.log"; then
  echo "FAIL: empty referrer list pulled or pushed" >&2
  cat "${work}/oras.log" >&2
  fail=1
else
  echo "ok: empty referrer list does not pull or push"
fi

# Matching referrer: push and label.
rm -rf "${work}/cache"
write_cdx "${work}/cdx.json" "bluebird" "3.7.2"
jq -n --arg ref "quay.io/example/snapshot@sha256:${REF64}" --arg digest "sha256:${REF64}" \
  '{referrers: [{reference: $ref, digest: $digest, artifactType: "application/vnd.cyclonedx+json"}]}' \
  > "${work}/discover.json"
: > "${work}/oras.log"
: > "${work}/curl.log"
assert_ok "matching referrer publishes" run_publish "${work}"
if grep -q "discover ${IMAGE} " "${work}/oras.log" \
  && ! grep '^discover ' "${work}/oras.log" | grep -q -- '--registry-config'; then
  echo "ok: discover uses the snapshot image without the push registry config"
else
  echo "FAIL: discover command was unexpected" >&2
  cat "${work}/oras.log" >&2
  fail=1
fi
if grep -q "push ${PREFIX}:bluebird-3.7.2-sbom " "${work}/oras.log" \
  && grep 'push ' "${work}/oras.log" | grep -q -- '--registry-config' \
  && grep 'push ' "${work}/oras.log" | grep -q 'application/vnd.cyclonedx+json'; then
  echo "ok: push targets the sbom tag with the compliance registry config"
else
  echo "FAIL: push command was unexpected" >&2
  cat "${work}/oras.log" >&2
  fail=1
fi
for key in tl.oci_registry_base tl.sbom_oci_digest tl.sbom_artifact_type; do
  if grep -q "\"key\":\"${key}\"" "${work}/curl.log"; then
    echo "ok: set ${key}"
  else
    echo "FAIL: missing Pulp label ${key}" >&2
    cat "${work}/curl.log" >&2
    fail=1
  fi
done
if grep -q "\"value\":\"sha256:${PUSH64}\"" "${work}/curl.log" \
  && grep -q "\"value\":\"${PREFIX}\"" "${work}/curl.log" \
  && grep -q "\"value\":\"application/vnd.cyclonedx+json\"" "${work}/curl.log"; then
  echo "ok: label values are the registry base, digest, and artifact type"
else
  echo "FAIL: label values were unexpected" >&2
  cat "${work}/curl.log" >&2
  fail=1
fi

# Two different matching documents fail.
rm -rf "${work}/cache"
write_cdx "${work}/cdx-2.json" "bluebird" "3.7.2"
jq -n --arg ref "quay.io/example/snapshot@sha256:${REF64}" \
  --arg digest "sha256:${REF64}" \
  --arg ref2 "quay.io/example/snapshot@sha256:${REF2_64}" \
  --arg digest2 "sha256:${REF2_64}" \
  '{referrers: [
      {reference: $ref, digest: $digest, artifactType: "application/vnd.cyclonedx+json"},
      {reference: $ref2, digest: $digest2, artifactType: "application/vnd.cyclonedx+json"}
    ]}' > "${work}/discover.json"
# Make the second document differ by an extra field so the file hash changes.
jq '.metadata.component.extra = "second"' "${work}/cdx-2.json" > "${work}/cdx-2.json.tmp"
mv "${work}/cdx-2.json.tmp" "${work}/cdx-2.json"
assert_fail "two matching SBOMs fail" run_publish "${work}"

# Discover failure fails the package.
rm -rf "${work}/cache"
export DISCOVER_FAIL=1
assert_fail "discover error fails" run_publish "${work}"
unset DISCOVER_FAIL

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi
echo "All npm SBOM publish checks passed"
