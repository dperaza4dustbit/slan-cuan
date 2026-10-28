#!/usr/bin/env bash
# Lightweight checks for npm attestation label helpers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/npm/npm-common.sh
source "${ROOT}/scripts/npm/npm-common.sh"

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

assert_eq "$(normalize_oci_registry_base 'quay.io/org/repo')" \
  'quay.io/org/repo' 'base without tag'
assert_eq "$(normalize_oci_registry_base 'quay.io/org/repo:latest')" \
  'quay.io/org/repo' 'base strips tag'
assert_eq "$(normalize_oci_registry_base 'quay.io/org/repo@sha256:abc')" \
  'quay.io/org/repo' 'base strips digest'
assert_eq "$(attestation_oci_tag 'express' '4.22.0')" \
  'express-4.22.0-att' 'unscoped attestation tag'
assert_eq "$(attestation_oci_tag '@scope/pkg' '1.2.3')" \
  'scope--pkg-1.2.3-att' 'scoped attestation tag uses -- for /'
assert_eq "$(attestation_oci_tag '@a/b' '1.0.0')" \
  'a--b-1.0.0-att' 'scoped @a/b tag'
assert_eq "$(attestation_oci_tag 'a-b' '1.0.0')" \
  'a-b-1.0.0-att' 'unscoped a-b does not collide with @a/b'
assert_eq "$(attestation_oci_tag 'pkg' '2.1.0+build.42')" \
  'pkg-2.1.0-build.42-att' 'semver build metadata + sanitized for OCI'
assert_eq "$(attestation_oci_tag '@scope/pkg' '1.0.0+meta')" \
  'scope--pkg-1.0.0-meta-att' 'scoped name with build metadata sanitized'
assert_eq "${DEFAULT_ATTESTATION_PREDICATE_TYPE}" \
  'https://slsa.dev/provenance/v1' 'shared predicate type default'

HEX64='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
assert_eq "$(normalize_digest "${HEX64}")" \
  "sha256:${HEX64}" 'normalize_digest accepts bare hex'
assert_eq "$(normalize_digest "SHA256:${HEX64}")" \
  "sha256:${HEX64}" 'normalize_digest lowercases prefixed digest'
assert_eq "$(normalize_digest "$(printf '%s' "${HEX64}" | tr 'a' 'A')")" \
  "sha256:${HEX64}" 'normalize_digest lowercases bare hex'
# 64 chars, includes non-hex 'z' / '!' so it must not get a sha256: prefix.
BAD64='zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
assert_eq "$(normalize_digest "${BAD64}")" \
  '' 'normalize_digest rejects non-hex 64-char string'
assert_eq "$(normalize_digest 'sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz')" \
  '' 'normalize_digest rejects non-hex prefixed digest'

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi
echo "All npm attestation helper checks passed"
