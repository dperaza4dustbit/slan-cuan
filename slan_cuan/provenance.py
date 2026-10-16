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
from pathlib import Path

import click

from slan_cuan.models import parse_image_ref

DEFAULT_PROVENANCE_KEY = "k8s://openshift-pipelines/public-key"


def fetch_chains_provenance(
    image_ref_str: str,
    provenance_dir: Path,
    key_ref: str,
    registry_auth_file: Path | None = None,
    verbose: bool = False,
) -> Path:
    """Fetch and verify Tekton Chains SLSA provenance for an image.

    Runs ``cosign verify-attestation`` against the given key reference,
    decodes the first DSSE envelope's payload, and saves it as
    ``<digest>.json`` so downstream consumers can match provenance to
    the image that produced it.
    """
    img_ref = parse_image_ref(image_ref_str)
    if not img_ref.digest:
        raise click.ClickException(
            "Image reference must include a digest for provenance "
            f"filenames: {image_ref_str}"
        )

    provenance_dir.mkdir(parents=True, exist_ok=True)
    out_file = provenance_dir / f"{img_ref.digest}.json"

    cmd = [
        "cosign",
        "verify-attestation",
        "--type=slsaprovenance",
        "--insecure-ignore-tlog=true",
        "--insecure-ignore-sct=true",
        "--key",
        key_ref,
        image_ref_str,
    ]
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
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, env=env
        )
        if result.returncode != 0:
            raise click.ClickException(
                "cosign verify-attestation failed for "
                f"{image_ref_str}: {result.stderr.strip()}"
            )
        stdout = result.stdout.strip()
        if not stdout:
            raise click.ClickException(
                "cosign verify-attestation returned no attestations for "
                f"{image_ref_str}"
            )
        envelope = json.loads(stdout.splitlines()[0])
        payload = json.loads(base64.b64decode(envelope["payload"]))
        out_file.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
    finally:
        if docker_config_dir is not None:
            shutil.rmtree(docker_config_dir, ignore_errors=True)

    if verbose:
        click.echo(f"Saved Chains provenance to {out_file}")
    return out_file
