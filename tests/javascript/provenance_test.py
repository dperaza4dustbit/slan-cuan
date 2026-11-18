"""Tests for the npm Chains provenance trust-policy selector."""

from __future__ import annotations

import click
import pytest

from slan_cuan.javascript.provenance import (
    build_npm_provenance_selector,
    parse_trusted_namespaces,
)

TRUSTED_NAMESPACES = ("calunga-tenant",)
DIGEST_HEX = "ab" * 32
IMAGE_DIGEST = f"sha256:{DIGEST_HEX}"


def _v02_candidate(
    *,
    builder_id: str = "https://tekton.dev/chains/v2",
    build_type: str = "tekton.dev/v1/PipelineRun",
    runtime_label: str = "build-npm-compliance",
    log_url_ns: str = "calunga-tenant",
    digest_hex: str = DIGEST_HEX,
) -> dict:
    """Build a SLSA v0.2 PipelineRun-shaped candidate.

    Uses predicate.builder / predicate.buildType / predicate.invocation.* --
    the current Konflux Chains default shape.
    """
    return {
        "predicate": {
            "builder": {"id": builder_id},
            "buildType": build_type,
            "invocation": {
                "environment": {
                    "labels": {"pipelines.openshift.io/runtime": runtime_label},
                    "annotations": {
                        "pipelinesascode.tekton.dev/log-url": (
                            f"https://console.example/ns/{log_url_ns}/runs/1"
                        ),
                    },
                }
            },
        },
        "subject": [{"name": "image", "digest": {"sha256": digest_hex}}],
    }


def _v1_candidate(
    *,
    builder_id: str = "https://konflux-ci.dev/chains/v2",
    build_type: str = "https://tekton.dev/chains/v2/slsa",
    pipeline_name: str = "build-npm",
    invocation_id_ns: str = "calunga-tenant",
    digest_hex: str = DIGEST_HEX,
) -> dict:
    """Build a SLSA v1 (buildDefinition/runDetails)-shaped candidate."""
    return {
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": {
                    "runSpec": {"pipelineRef": {"name": pipeline_name}}
                },
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": f"{invocation_id_ns}/12345"},
            },
        },
        "subject": [{"name": "image", "digest": {"sha256": digest_hex}}],
    }


def test_parse_trusted_namespaces_splits_and_strips() -> None:
    """Splits on comma, strips whitespace, and drops empty entries."""
    result = parse_trusted_namespaces("calunga-tenant, other-ns ,,")

    assert result == ("calunga-tenant", "other-ns")


@pytest.mark.parametrize("raw", ["", ",,"])
def test_parse_trusted_namespaces_empty_raises(raw: str) -> None:
    """Raises when no usable namespace remains after parsing."""
    with pytest.raises(click.ClickException):
        parse_trusted_namespaces(raw)


def test_selector_accepts_v02_pipelinerun_candidate() -> None:
    """Selects a well-formed SLSA v0.2 PipelineRun candidate."""
    candidate = _v02_candidate()
    select = build_npm_provenance_selector(IMAGE_DIGEST, TRUSTED_NAMESPACES)

    result = select([candidate])

    assert result is candidate


def test_selector_accepts_v1_slsa_candidate() -> None:
    """Selects a well-formed SLSA v1 candidate with pipelineRef build-npm."""
    candidate = _v1_candidate(pipeline_name="build-npm")
    select = build_npm_provenance_selector(IMAGE_DIGEST, TRUSTED_NAMESPACES)

    result = select([candidate])

    assert result is candidate


def test_selector_rejects_wrong_builder() -> None:
    """Rejects a candidate whose builder id is not a known Chains builder."""
    candidate = _v02_candidate(builder_id="https://example.com/other-builder")
    select = build_npm_provenance_selector(IMAGE_DIGEST, TRUSTED_NAMESPACES)

    with pytest.raises(click.ClickException):
        select([candidate])


def test_selector_rejects_untrusted_namespace() -> None:
    """Rejects a candidate whose namespace is not in trusted_namespaces."""
    candidate = _v02_candidate(log_url_ns="some-other-tenant")
    select = build_npm_provenance_selector(IMAGE_DIGEST, TRUSTED_NAMESPACES)

    with pytest.raises(click.ClickException):
        select([candidate])


def test_selector_rejects_subject_digest_mismatch() -> None:
    """Rejects a candidate whose subject digest does not match the image."""
    candidate = _v02_candidate(digest_hex="cd" * 32)
    select = build_npm_provenance_selector(IMAGE_DIGEST, TRUSTED_NAMESPACES)

    with pytest.raises(click.ClickException):
        select([candidate])


def test_selector_picks_first_matching_of_several_candidates() -> None:
    """Returns the first matching candidate, not merely "a" match."""
    non_matching = _v02_candidate(builder_id="https://example.com/other")
    matching = _v1_candidate()
    select = build_npm_provenance_selector(IMAGE_DIGEST, TRUSTED_NAMESPACES)

    result = select([non_matching, matching])

    assert result is matching


def test_selector_accepts_runtime_label_pipeline_alternative() -> None:
    """Accepts the runtime-label pipeline signal when pipelineRef is absent."""
    candidate = {
        "predicate": {
            "builder": {"id": "https://tekton.dev/chains/v2"},
            "buildType": "tekton.dev/v1/PipelineRun",
            "invocation": {
                "environment": {
                    "labels": {
                        "pipelines.openshift.io/runtime": ("build-npm-compliance")
                    },
                    "annotations": {
                        "results.tekton.dev/result": "calunga-tenant/abcd",
                    },
                }
            },
        },
        "subject": [{"name": "image", "digest": {"sha256": DIGEST_HEX}}],
    }
    select = build_npm_provenance_selector(IMAGE_DIGEST, TRUSTED_NAMESPACES)

    result = select([candidate])

    assert result is candidate
