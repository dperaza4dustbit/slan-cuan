"""Tekton Chains provenance fetching.

Fetches and verifies the Chains SLSA provenance of a digest-pinned
image reference with ``cosign verify-attestation``, saving the decoded
predicate as ``<digest>.json`` so downstream consumers can match
provenance to the image that produced it. Ecosystem-agnostic.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

import click

from slan_cuan.models import parse_image_ref

DEFAULT_PROVENANCE_KEY = "k8s://openshift-pipelines/public-key"


def _format_failures(failures: list[tuple[str, str]]) -> str:
    """Render per-predicate-type cosign stderr for an error message.

    A single attempted type renders as its bare stderr (the original
    single-call message format); multiple types render each type's
    stderr labelled by type, so no failure reason is hidden.
    """
    if len(failures) == 1:
        return failures[0][1]
    return "; ".join(
        f"[--type={ptype}] {stderr or '(no stderr)'}"
        for ptype, stderr in failures
    )


def fetch_chains_provenance(
    image_ref_str: str,
    provenance_dir: Path,
    key_ref: str,
    registry_auth_file: Path | None = None,
    verbose: bool = False,
    *,
    predicate_types: Sequence[str] = ("slsaprovenance",),
    select: Callable[[list[dict]], dict] | None = None,
) -> Path:
    """Fetch, verify, and save a Tekton Chains attestation for an image.

    Verifies the image's attestations with ``cosign verify-attestation``
    against ``key_ref``, picks one decoded in-toto statement, and writes it
    to ``provenance_dir/<digest>.json``.

    cosign is run once per entry in ``predicate_types``. A type whose
    cosign call fails, or an envelope line that can't be decoded, is
    skipped. Note that this also hides a real cosign error on one type
    when another type succeeds. All decoded payloads are collected in
    invocation order.

    Args:
        image_ref_str: Image reference; must include a digest.
        provenance_dir: Output directory (created if missing).
        key_ref: cosign key reference used for verification.
        registry_auth_file: Optional registry auth (docker config JSON).
        verbose: Echo progress messages.
        predicate_types: cosign ``--type`` values to try.
        select: Picks the payload to save from the non-empty candidate
            list; must raise if none is acceptable. Defaults to the
            first candidate.

    Returns:
        Path to the written JSON file.

    Raises:
        click.ClickException: If the reference has no digest, if cosign
        fails for every type (message includes cosign's stderr), or
            if cosign succeeds but no attestation decodes. Exceptions
            raised by ``select`` propagate unchanged.

    """
    img_ref = parse_image_ref(image_ref_str)
    if not img_ref.digest:
        raise click.ClickException(
            "Image reference must include a digest for provenance "
            f"filenames: {image_ref_str}"
        )

    provenance_dir.mkdir(parents=True, exist_ok=True)
    out_file = provenance_dir / f"{img_ref.digest}.json"

    env = os.environ.copy()
    docker_config_dir = None
    if registry_auth_file is not None:
        # cosign (go-containerregistry) reads registry credentials from
        # $DOCKER_CONFIG/config.json.
        docker_config_dir = tempfile.mkdtemp(prefix="slan-cuan-cosign-")
        shutil.copy(registry_auth_file, Path(docker_config_dir) / "config.json")
        env["DOCKER_CONFIG"] = docker_config_dir
    try:
        if verbose:
            click.echo(f"Fetching Chains provenance for {image_ref_str}")
        candidates: list[dict] = []
        any_type_succeeded = False
        failures: list[tuple[str, str]] = []
        for predicate_type in predicate_types:
            cmd = [
                "cosign",
                "verify-attestation",
                f"--type={predicate_type}",
                "--insecure-ignore-tlog=true",
                "--insecure-ignore-sct=true",
                "--key",
                key_ref,
                image_ref_str,
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, env=env
            )
            if result.returncode != 0:
                # A single predicate type failing isn't fatal on its
                # own — it just contributes no candidates. Only
                # raised if every type fails (below).
                failures.append((predicate_type, result.stderr.strip()))
                continue
            any_type_succeeded = True
            stdout = result.stdout.strip()
            if not stdout:
                continue
            for line in stdout.splitlines():
                # A malformed/undecodable envelope line isn't fatal
                # to the invocation either — it just contributes no
                # candidate, consistent with how a whole predicate
                # type failing is handled above.
                try:
                    envelope = json.loads(line)
                    payload = json.loads(base64.b64decode(envelope["payload"]))
                except (ValueError, KeyError):
                    continue
                candidates.append(payload)

        # Order matters: a cosign infrastructure failure (bad key,
        # unreachable registry/tlog, ...) on every type must surface
        # cosign's own stderr, never be masked by select()'s generic
        # trust-policy rejection message — mirroring the bash
        # original's `verified -ne 1` check before its jq filter.
        if not any_type_succeeded:
            raise click.ClickException(
                "cosign verify-attestation failed for "
                f"{image_ref_str}: {_format_failures(failures)}"
            )
        if not candidates:
            raise click.ClickException(
                "cosign verify-attestation returned no attestations for "
                f"{image_ref_str}"
            )
        payload = select(candidates) if select is not None else candidates[0]

        out_file.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
    finally:
        if docker_config_dir is not None:
            shutil.rmtree(docker_config_dir, ignore_errors=True)

    if verbose:
        click.echo(f"Saved Chains provenance to {out_file}")
    return out_file
