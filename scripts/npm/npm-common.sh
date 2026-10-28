#!/usr/bin/env bash
# Shared helpers for npm pulp release scripts. Source from other scripts:
#   # shellcheck source=npm-common.sh
#   source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/npm-common.sh"
# Prefer sibling when running from a checkout; fall back to PATH install:
#   source "$(command -v npm-common.sh)"

# Write ERROR status for Tekton results.status (do not write Success — that
# belongs to record-success after create-trusted-artifact).
write_status_error() {
  local detail="${1:-unknown error}"
  if [[ -n "${STATUS_PATH:-}" ]]; then
    printf 'ERROR: %s\n' "${detail}" > "${STATUS_PATH}"
  fi
}

# Fail with stderr + optional STATUS_PATH update.
fail_with_status() {
  local detail="${1:-unknown error}"
  echo "ERROR: ${detail}" >&2
  write_status_error "${detail}"
  exit 1
}

# Strip :tag / @digest from an image prefix → registry/repo base for labels.
normalize_oci_registry_base() {
  local prefix="$1"
  local base
  if [[ "${prefix}" == *"@"* ]] && [[ "${prefix}" != *"@" ]]; then
    base="${prefix%%@*}"
  else
    base="${prefix}"
  fi
  if [[ "${base##*/}" == *:* ]]; then
    base="${base%:*}"
  fi
  printf '%s' "${base}"
}

# SLSA predicate type embedded in DSSE (--type=) and recorded on Pulp labels.
# Keep generate-and-sign-npm-attestations and npm-attestation-publish in sync via
# this constant (override with ATTESTATION_PREDICATE_TYPE in the environment).
DEFAULT_ATTESTATION_PREDICATE_TYPE="https://slsa.dev/provenance/v1"

# Mutable Quay tag for a package attestation OCI (writer-only; not a Pulp label).
# Scoped names replace "/" with "--" so @a/b and unscoped a-b cannot collide.
# Remaining characters outside the OCI tag charset ([A-Za-z0-9._-], max 128,
# first char [A-Za-z0-9_]) are replaced with "-" so npm build metadata like
# 2.1.0+build.42 does not break oras push.
attestation_oci_tag() {
  local name="$1"
  local version="$2"
  local raw
  if [[ "${name}" == @* ]]; then
    local tag="${name#@}"
    raw="${tag//\//--}-${version}-att"
  else
    raw="${name}-${version}-att"
  fi
  local sanitized
  sanitized="$(printf '%s' "${raw}" | sed 's/[^A-Za-z0-9._-]/-/g')"
  if [[ ! "${sanitized}" =~ ^[A-Za-z0-9_] ]]; then
    sanitized="_${sanitized}"
  fi
  if [[ ${#sanitized} -gt 128 ]]; then
    sanitized="${sanitized:0:128}"
  fi
  printf '%s' "${sanitized}"
}

# Normalize an OCI/content digest to lowercase sha256:<64 hex>.
# Bare 64-char strings must be hex (same rule as update-npm-closure); otherwise
# return empty so callers fail closed instead of stamping sha256: on garbage.
# Prefixed values are re-validated the same way.
normalize_digest() {
  local digest="$1"
  digest="$(printf '%s' "${digest}" | tr -d '[:space:]')"
  [[ -n "${digest}" ]] || {
    printf ''
    return 0
  }
  local hex="${digest}"
  local looked_like_digest=0
  # Accept sha256: prefix case-insensitively (oras / tooling vary).
  if [[ "${digest}" =~ ^[Ss][Hh][Aa]256: ]]; then
    hex="${digest#*:}"
    looked_like_digest=1
  elif [[ ${#digest} -eq 64 ]]; then
    looked_like_digest=1
  fi
  hex="$(printf '%s' "${hex}" | tr '[:upper:]' '[:lower:]')"
  if [[ ${#hex} -eq 64 && "${hex}" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'sha256:%s' "${hex}"
    return 0
  fi
  # Digest-shaped but invalid → empty (fail closed). Other strings pass through.
  if [[ "${looked_like_digest}" -eq 1 ]]; then
    printf ''
    return 0
  fi
  printf '%s' "${digest}"
}

# Set a Pulp content label when the value differs from current.
# Usage: pulp_set_label CONTENT_HREF KEY VALUE [CURRENT]
# When CURRENT is omitted, fetch pulp_labels from CONTENT_HREF first.
# Requires: PULP_BASE_URL, AUTH (curl -u array), optional CURL_RETRY /
# CURL_MAX_TIME_QUERY_SECONDS.
pulp_set_label() {
  local content_href="${1:?content href required}"
  local key="${2:?label key required}"
  local value="${3:?label value required}"
  local current=""
  local have_current=0
  local curl_retry="${CURL_RETRY:-3}"
  local curl_max="${CURL_MAX_TIME_QUERY_SECONDS:-30}"

  if [[ $# -ge 4 ]]; then
    current="${4}"
    have_current=1
  fi

  if [[ "${have_current}" -eq 0 ]]; then
    local response
    response="$(curl --fail-with-body --silent \
      --retry "${curl_retry}" \
      --max-time "${curl_max}" \
      "${AUTH[@]}" \
      "${PULP_BASE_URL}${content_href}")" || return 1
    current="$(jq -r --arg k "${key}" '.pulp_labels[$k] // empty' <<<"${response}")"
  fi

  if [[ "${current}" == "${value}" ]]; then
    echo "  Label ${key}=${value} already set"
    return 0
  fi

  echo "  Setting ${key}=${value} on ${content_href}"
  curl --fail-with-body --silent \
    --retry "${curl_retry}" \
    --max-time "${curl_max}" \
    "${AUTH[@]}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$(jq -nc --arg k "${key}" --arg v "${value}" '{key: $k, value: $v}')" \
    "${PULP_BASE_URL}${content_href}set_label/"
}

# Fail if the named tar member is missing, empty, or larger than max_bytes.
# Probes with head -c so we never buffer more than max+1 bytes.
assert_tar_member_size() {
  local archive="${1}"
  local member="${2}"
  local max_bytes="${3}"
  local tmp size
  tmp="$(mktemp)"
  # Process substitution avoids a pipefail-sensitive tar|head pipeline:
  # head closes early on truncate; tar's SIGPIPE stays in the subshell.
  head -c "$((max_bytes + 1))" \
    < <(tar -xOf "${archive}" "${member}" 2>/dev/null) \
    > "${tmp}" || true
  size="$(wc -c < "${tmp}" | tr -d ' ')"
  rm -f "${tmp}"
  if [[ -z "${size}" || "${size}" -eq 0 ]]; then
    return 1
  fi
  if [[ "${size}" -gt "${max_bytes}" ]]; then
    echo "ERROR: ${member} in $(basename "${archive}") exceeds" \
      "${max_bytes} bytes" >&2
    return 1
  fi
  return 0
}
