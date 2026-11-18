"""npm Tekton Chains SLSA provenance trust-policy predicates.

Pure predicate-matching logic -- no I/O, no subprocess calls -- ported
directly from ``npm-fetch-chains-provenance``'s ``jq`` filter. Builds the
``select`` callable that ``slan_cuan.provenance.fetch_chains_provenance``
calls with the decoded DSSE envelope candidates, returning the first
candidate whose Chains builder, SLSA buildType, npm pipeline identity,
trusted namespace, and subject digest all check out -- never raising on
a missing/malformed field, only when no candidate satisfies every
predicate.
"""

from __future__ import annotations

from collections.abc import Callable

import click

NPM_PREDICATE_TYPES: tuple[str, ...] = ("slsaprovenance", "slsaprovenance1")

_CHAINS_BUILDERS = frozenset(
    {
        "https://tekton.dev/chains/v2",
        "https://konflux-ci.dev/chains/v2",
    }
)

_SLSA_BUILD_TYPES = frozenset(
    {
        "https://tekton.dev/chains/v2/slsa",
        "tekton.dev/v1/PipelineRun",
    }
)

_NPM_PIPELINES = frozenset(
    {
        "build-npm-compliance",
        "build-npm",
        "promote-npm",
    }
)


def _dig(obj: object, *path: str) -> object:
    """Walk nested dicts along *path*; ``None`` as soon as a step misses.

    Mirrors jq's behavior of treating a missing/non-object field as
    null rather than raising, so a malformed or partial candidate is
    simply not selected instead of throwing.
    """
    current = obj
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _first_str(*values: object) -> str:
    """First non-``None`` value in *values*, coerced to ``str`` or ``""``.

    Mirrors jq's ``a // b // ""`` fallback chain: the first path that is
    present (even if falsy, e.g. an empty string) wins over later ones,
    and anything that isn't a string collapses to ``""`` so comparisons
    never raise.
    """
    for value in values:
        if value is not None:
            return value if isinstance(value, str) else ""
    return ""


def _chains_builder(predicate: dict) -> bool:
    """``predicate.runDetails.builder.id // predicate.builder.id`` check."""
    builder_id = _first_str(
        _dig(predicate, "runDetails", "builder", "id"),
        _dig(predicate, "builder", "id"),
    )
    return builder_id in _CHAINS_BUILDERS


def _slsa_type_ok(predicate: dict) -> bool:
    """``predicate.buildDefinition.buildType // predicate.buildType``."""
    build_type = _first_str(
        _dig(predicate, "buildDefinition", "buildType"),
        _dig(predicate, "buildType"),
    )
    return build_type in _SLSA_BUILD_TYPES


def _npm_pipeline(predicate: dict) -> bool:
    """SLSA v1 ``pipelineRef.name`` or the v0.2 runtime label."""
    pipeline_name = _first_str(
        _dig(
            predicate,
            "buildDefinition",
            "externalParameters",
            "runSpec",
            "pipelineRef",
            "name",
        )
    )
    runtime_label = _first_str(
        _dig(
            predicate,
            "invocation",
            "environment",
            "labels",
            "pipelines.openshift.io/runtime",
        )
    )
    return pipeline_name in _NPM_PIPELINES or runtime_label in _NPM_PIPELINES


def _trusted_ns(predicate: dict, trusted_namespaces: tuple[str, ...]) -> bool:
    """Namespace signal from invocationId, PAC log-url, or Results annos."""
    invocation_id = _first_str(
        _dig(predicate, "runDetails", "metadata", "invocationId")
    )
    log_url = _first_str(
        _dig(
            predicate,
            "invocation",
            "environment",
            "annotations",
            "pipelinesascode.tekton.dev/log-url",
        )
    )
    result_annotation = _first_str(
        _dig(
            predicate,
            "invocation",
            "environment",
            "annotations",
            "results.tekton.dev/result",
        )
    )
    record_annotation = _first_str(
        _dig(
            predicate,
            "invocation",
            "environment",
            "annotations",
            "results.tekton.dev/record",
        )
    )
    return any(
        invocation_id.startswith(f"{ns}/")
        or f"/ns/{ns}/" in log_url
        or result_annotation.startswith(f"{ns}/")
        or record_annotation.startswith(f"{ns}/")
        for ns in trusted_namespaces
    )


def _subject_ok(candidate: dict, digest_hex: str) -> bool:
    """Any ``subject[].digest.sha256`` equals the target digest hex."""
    subjects = candidate.get("subject")
    if not isinstance(subjects, list):
        return False
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        if _dig(subject, "digest", "sha256") == digest_hex:
            return True
    return False


def build_npm_provenance_selector(
    image_digest: str, trusted_namespaces: tuple[str, ...]
) -> Callable[[list[dict]], dict]:
    """Build the ``select`` callable for ``fetch_chains_provenance``.

    Returns the first candidate in the list satisfying all five trust
    predicates (Chains builder, SLSA buildType, npm pipeline identity,
    trusted namespace, subject digest match against *image_digest*).
    Raises ``click.ClickException`` if none qualify.
    """
    digest_hex = image_digest.removeprefix("sha256:")

    def select(candidates: list[dict]) -> dict:
        for candidate in candidates:
            predicate = candidate.get("predicate")
            if not isinstance(predicate, dict):
                continue
            if (
                _chains_builder(predicate)
                and _slsa_type_ok(predicate)
                and _npm_pipeline(predicate)
                and _trusted_ns(predicate, trusted_namespaces)
                and _subject_ok(candidate, digest_hex)
            ):
                return candidate
        raise click.ClickException(
            "No trusted Chains SLSA provenance for "
            f"sha256:{digest_hex}\n"
            "  accepted builders: https://tekton.dev/chains/v2, "
            "https://konflux-ci.dev/chains/v2\n"
            "  accepted buildType: tekton.dev/v1/PipelineRun (SLSA v0.2) "
            "or https://tekton.dev/chains/v2/slsa (v1)\n"
            "  expected npm pipeline: pipelineRef.name or "
            "pipelines.openshift.io/runtime in {build-npm-compliance, "
            "build-npm} (legacy promote-npm also accepted)\n"
            "  expected namespace in invocationId, PAC log-url, or "
            "Tekton Results annotations: "
            f"{', '.join(trusted_namespaces)}"
        )

    return select


def parse_trusted_namespaces(raw: str) -> tuple[str, ...]:
    """Split a comma-separated namespace list, stripping and dropping empties.

    Raises ``click.ClickException`` if no usable namespace remains,
    matching the bash script's "must list at least one namespace" check.
    """
    namespaces = tuple(ns.strip() for ns in raw.split(",") if ns.strip())
    if not namespaces:
        raise click.ClickException(
            "trustedProvenanceNamespaces must list at least one namespace"
        )
    return namespaces
