"""Sign subcommand for signing Maven artifacts."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

import click

from slan_cuan.java.maven import sign_individual_artifacts
from slan_cuan.models import EXTRACT_RESULT_FILENAME, GlobalContext
from slan_cuan.oci import blob_fetch
from slan_cuan.utils import safe_json_load

logger = logging.getLogger(__name__)


def _split_ignore_patterns(
    ctx: click.Context,
    param: click.Parameter,
    value: tuple[str, ...],
) -> tuple[str, ...]:
    """Split comma-separated patterns from environment variables."""
    if len(value) == 1 and "," in value[0]:
        return tuple(p.strip() for p in value[0].split(",") if p.strip())
    return value


def _resolve_direct_sign_source_artifact(
    source_artifact: str,
    source_artifact_file: Path | None,
) -> str:
    """Resolve the direct-sign trusted-artifact pullspec.

    The middleware-signing input TA is created by an earlier Tekton step that
    writes its pullspec to a file. Reading that file here lets the sign task
    hand off the pullspec without inline shell in the run step. When no file is
    given, fall back to the value passed directly (the pre-existing behaviour).
    """
    if source_artifact_file is None:
        return source_artifact
    try:
        content = source_artifact_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise click.UsageError(
            f"Could not read --direct-sign-task-ta-source-artifact-file "
            f"{source_artifact_file}: {exc}"
        ) from exc
    if not content:
        raise click.UsageError(
            f"--direct-sign-task-ta-source-artifact-file {source_artifact_file} "
            "is empty; expected a trusted-artifact pullspec"
        )
    return content


def wait_for_internal_request(
    ir_name: str,
    *,
    poll_interval: int = 10,
    log_interval: int = 60,
    timeout: int = 3600,
) -> None:
    """Wait for an InternalRequest to complete with fixed polling.

    Uses a static polling interval and periodic heartbeat logging.
    """
    start_time = time.time()
    last_log_time = 0.0

    while True:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            raise click.ClickException(
                f"Timed out waiting for InternalRequest '{ir_name}' "
                f"after {int(elapsed)}s"
            )

        cmd = ["kubectl", "get", "internalrequest", ir_name, "-o", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            if time.time() - last_log_time >= log_interval:
                err = proc.stderr.strip()
                click.echo(
                    f"  - Waiting for InternalRequest '{ir_name}'... "
                    f"(kubectl: {err})"
                )
                last_log_time = time.time()
            time.sleep(poll_interval)
            continue

        try:
            ir_obj = json.loads(proc.stdout)
        except json.JSONDecodeError:
            # Don't fail on a transient unparsable read (e.g. an empty or
            # partial `kubectl` payload) -- keep polling, but log on the
            # heartbeat cadence so a persistently bad response is visible
            # rather than silently swallowed.
            if time.time() - last_log_time >= log_interval:
                click.echo(
                    f"  - Waiting for InternalRequest '{ir_name}'... "
                    f"(unparsable kubectl output)"
                )
                last_log_time = time.time()
            time.sleep(poll_interval)
            continue

        pipeline_run = ir_obj.get("status", {}).get("pipelineRun", "")
        pr_info = f" (pipelineRun: {pipeline_run})" if pipeline_run else ""

        conditions = ir_obj.get("status", {}).get("conditions") or []
        for condition in conditions:
            if condition.get("type") == "Succeeded":
                # Terminal state is keyed off `reason`, not `status`:
                # release-service reports status "False" with reason
                # "Running" while the InternalRequest is still executing, so
                # a `status == "False"` check would misfire mid-run. Only the
                # reason distinguishes running / succeeded / failed (matching
                # the vendored internal_request.wait_for_completion helper).
                reason = condition.get("reason", "")
                message = condition.get("message", "")
                if reason == "Succeeded":
                    return
                if reason and reason != "Running":
                    detail = f": {message}" if message else ""
                    # Surface the pipelineRun so a failed sign can be
                    # inspected directly (the vendored helper dumped the
                    # full conditions on failure; this keeps the pointer).
                    raise click.ClickException(
                        f"InternalRequest '{ir_name}' failed with reason "
                        f"'{reason}'{detail}{pr_info}"
                    )

        if time.time() - last_log_time >= log_interval:
            click.echo(
                f"  - Waiting for InternalRequest '{ir_name}' to complete... "
                f"(elapsed: {int(elapsed)}s){pr_info}"
            )
            last_log_time = time.time()

        time.sleep(poll_interval)


def _sign_directly(
    repo_url: str,
    signing_key: str,
    requester_id: str,
    ignore_patterns: tuple[str, ...],
    registry_auth_file: Path | None,
    direct_sign_pipeline_name: str,
    direct_sign_task_git_url: str,
    direct_sign_task_git_revision: str,
    direct_sign_verbose: bool,
    intention: str,
    sign_artifact_dir: str,
    tmp_dir_sign_url: str,
) -> None:
    # Lazy import: internal_request is a vendored, runtime-only module that is
    # only on the path inside the container, not in dev/test environments.
    from internal_request import create as create_internal_request
    from internal_request import fetch_results

    click.echo("Signing the repository directly via internal-request...")
    click.echo(f"  - registry_auth_file: {registry_auth_file}")
    if registry_auth_file is not None:
        with open(registry_auth_file, "rb") as f:
            file_hash = hashlib.file_digest(f, "sha256")
        click.echo(f"  - sha256 creds: {file_hash.hexdigest()}")
    click.echo(f"  - repo_url: {repo_url}")
    click.echo(f"  - requester: {requester_id}")
    click.echo(f"  - sign_key: {signing_key}")
    click.echo(f"  - result_path: {sign_artifact_dir}")
    # Forward ignore_patterns to middleware-signing as a JSON-encoded string.
    # An InternalRequest's spec.params is map[string]string (see the CRD's
    # Params field), and the internal-services controller coerces every param
    # to a Tekton *string* param, so an array value can never survive this path.
    # middleware-signing's "exclude" param is now typed `string` and json.loads
    # it back into a list on the signing side (signing!155), so a JSON-encoded
    # string round-trips cleanly through both the map[string]string schema and
    # Tekton's param-type check (LWLP-1958).
    exclude_json = json.dumps(list(ignore_patterns))
    click.echo(f"  - exclude (JSON): {exclude_json}")

    params: dict[str, str] = {
        "taskGitUrl": direct_sign_task_git_url,
        "taskGitRevision": direct_sign_task_git_revision,
        "sourceDataArtifact": repo_url,
        "onbehalfof": requester_id,
        "keyname": signing_key,
        "ociStorage": sign_artifact_dir,
        "exclude": exclude_json,
        "verbose": str(direct_sign_verbose).lower(),
    }
    if registry_auth_file:
        params["registryAuthFile"] = str(registry_auth_file)

    labels = {
        "internal-services.appstudio.openshift.io/rate-limited": "true",
        "internal-services.appstudio.openshift.io/rate-limiting-group": (
            "signing-server"
        ),
        "internal-services.appstudio.openshift.io/intention": intention,
    }

    click.echo(f"  - params: {params}")
    click.echo(f"  - labels: {labels}")

    ir_name = create_internal_request(
        direct_sign_pipeline_name,
        params=params,
        labels=labels,
        sync=False,
        service_account="signing-pipeline-sa",
    )
    click.echo(
        f"  - InternalRequest '{ir_name}' created, waiting for completion..."
    )
    wait_for_internal_request(ir_name)
    click.echo(f"  - InternalRequest '{ir_name}' completed successfully")

    results = fetch_results(ir_name)
    click.echo(f"  - results: {results}")

    source_data_artifact = results.get("sourceDataArtifact", "")
    if not source_data_artifact:
        raise click.ClickException(
            "InternalRequest results missing 'sourceDataArtifact'"
        )
    pullspec = source_data_artifact.removeprefix("oci:")
    click.echo(f"  - Fetching signed artifact blob: {pullspec}")

    blob_tar = Path(tmp_dir_sign_url) / "blob.tar.gz"
    blob_fetch(pullspec, blob_tar, auth_file=registry_auth_file)

    with tarfile.open(blob_tar, "r:gz") as tar:
        tar.extractall(path=tmp_dir_sign_url, filter="data")
    blob_tar.unlink()

    click.echo(f"  - Signed artifact stored in: {tmp_dir_sign_url}")


@click.command()
@click.option(
    "--repo-url",
    "-u",
    required=True,
    type=str,
    help=(
        "The pullspec of the image containing the maven repository."
        " E.g. quay.io/someorg/maven:latest"
    ),
)
@click.option(
    "--repo-path",
    "-p",
    required=True,
    type=str,
    help=(
        "The directory (or ZIP file) containing the downloaded maven repository."
    ),
)
@click.option(
    "--signing-key",
    "-k",
    required=True,
    type=str,
    help="The signing key name.",
)
@click.option(
    "--output-path",
    "-o",
    required=True,
    type=str,
    help="The path to output the signed file(s).",
)
@click.option(
    "--requester-id",
    "-r",
    required=True,
    type=str,
    help="The requester ID to use for the signature.",
)
@click.option(
    "--zip-root-path",
    "-z",
    default="repository",
    type=str,
    help="The path to the root of maven's repository tree in the ZIP file.",
)
@click.option(
    "--product-key",
    "-b",
    default="slan-cuan",
    type=str,
    help="The product key to use for metadata generation.",
)
@click.option(
    "--ignore-patterns",
    "-i",
    multiple=True,
    callback=_split_ignore_patterns,
    help="Regex patterns to filter out files from signing.",
)
@click.option(
    "--registry-auth-file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to container registry authentication file.",
)
@click.option(
    "--direct-sign",
    is_flag=True,
    default=True,
    show_default=True,
    help="Directly sign the repository using the internal-request pipeline.",
)
@click.option(
    "--direct-sign-pipeline-name",
    default="middleware-signing",
    type=str,
    show_default=True,
    help="The name of the pipeline to use for direct signing.",
)
@click.option(
    "--direct-sign-task-git-url",
    default="https://gitlab.cee.redhat.com/signing/signing.git",
    type=str,
    show_default=True,
    help="The Git URL to use for direct signing.",
)
@click.option(
    "--direct-sign-task-git-revision",
    type=str,
    default="main",
    show_default=True,
    help="The Git branch to use for direct signing.",
)
@click.option(
    "--direct-sign-verbose",
    is_flag=True,
    default=False,
    show_default=True,
    help="Enable verbose Kerberos diagnostics for direct signing.",
)
@click.option(
    "--direct-sign-task-ta-storage",
    type=str,
    default="",
    show_default=True,
    help=(
        "The ociStorage for the trusted artifact to "
        "transfer files between the internal task."
    ),
)
@click.option(
    "--direct-sign-task-ta-source-artifact",
    type=str,
    default="",
    show_default=True,
    help=(
        "The sourceDataArtifact for the trusted artifact to "
        "transfer files between the internal task."
    ),
)
@click.option(
    "--direct-sign-task-ta-source-artifact-file",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Path to a file containing the sourceDataArtifact pullspec for the "
        "direct-sign trusted artifact. Takes precedence over "
        "--direct-sign-task-ta-source-artifact when set. Lets the Tekton task "
        "hand off the reduced-TA pullspec written by an earlier step without "
        "inline shell in the run step."
    ),
)
@click.option(
    "--intention",
    default="production",
    type=str,
    show_default=True,
    help="The intention to use for direct signing.",
)
@click.pass_obj
def sign(
    ctx: GlobalContext,
    repo_url: str,
    repo_path: str,
    signing_key: str,
    output_path: str,
    requester_id: str,
    zip_root_path: str,
    product_key: str,
    ignore_patterns: tuple[str, ...],
    registry_auth_file: Path | None,
    direct_sign: bool,
    direct_sign_pipeline_name: str,
    direct_sign_task_git_url: str,
    direct_sign_task_git_revision: str,
    direct_sign_verbose: bool,
    direct_sign_task_ta_storage: str,
    direct_sign_task_ta_source_artifact: str,
    direct_sign_task_ta_source_artifact_file: Path | None,
    intention: str,
) -> None:
    """Sign Maven artifacts directly via internal-request."""
    requester_id = (requester_id or "").strip()
    if not requester_id:
        raise click.UsageError("The --requester-id option cannot be empty.")
    try:
        # Direct signing is the only supported mode: the RADAS/UMB broker path
        # was removed. Honor the flag explicitly rather than silently ignoring
        # a DIRECT_SIGN=false request.
        if not direct_sign:
            raise click.ClickException(
                "Direct signing is the only supported signing mode; the "
                "RADAS/broker signing path has been removed. Unset "
                "DIRECT_SIGN or set it to 'true'."
            )

        # Fall back to the extracted directory when the zip was already unpacked
        # by the extract command (newer PNC images deliver a zip that extract
        # unzips in-place and removes).
        if repo_path.endswith(".zip") and not os.path.exists(repo_path):
            dir_path = repo_path.removesuffix(".zip")
            if os.path.isdir(dir_path):
                repo_path = dir_path

        log_level = logging.DEBUG if ctx.verbose else logging.INFO
        logging.basicConfig(level=log_level)
        logger.setLevel(log_level)

        with tempfile.TemporaryDirectory(
            prefix="slan-cuan-sign-url-"
        ) as tmp_dir_sign_url:
            repo_url = repo_url.removeprefix("https://").removeprefix("http://")
            sign_artifact_dir = os.path.join(output_path, "signed", "repository")

            click.echo("Signing the repository directly via internal-request...")
            source_artifact = _resolve_direct_sign_source_artifact(
                direct_sign_task_ta_source_artifact,
                direct_sign_task_ta_source_artifact_file,
            )
            if not source_artifact:
                source_artifact = repo_url
            _sign_directly(
                repo_url=source_artifact,
                signing_key=signing_key,
                requester_id=requester_id,
                ignore_patterns=ignore_patterns,
                registry_auth_file=registry_auth_file,
                direct_sign_pipeline_name=direct_sign_pipeline_name,
                direct_sign_task_git_url=direct_sign_task_git_url,
                direct_sign_task_git_revision=direct_sign_task_git_revision,
                direct_sign_verbose=direct_sign_verbose,
                intention=intention,
                sign_artifact_dir=direct_sign_task_ta_storage,
                tmp_dir_sign_url=tmp_dir_sign_url,
            )

            # 2 - Find the signed JSON files in the output path
            click.echo("Finding the signed JSON files in the output path...")
            signed_json_files = list(Path(tmp_dir_sign_url).rglob("*.json"))
            if not signed_json_files:
                raise click.ClickException(
                    "No signed JSON file found in the output path"
                )
            signed_json_file = signed_json_files[0]

            # 3 - Sign individual artifacts and generate metadata
            click.echo("Signing individual artifacts and generating metadata...")
            click.echo(f"  - repos: [{repo_path}]")
            click.echo(f"  - prod key: [{product_key}]")
            click.echo(f"  - root path: [{zip_root_path}]")
            click.echo(f"  - signed file: [{signed_json_file}]")
            click.echo(f"  - output dir: [{sign_artifact_dir}]")
            with tempfile.TemporaryDirectory(prefix="slan-cuan-sign-") as tmp_dir:
                click.echo(f"  - tmp dir: [{tmp_dir}]")
                sign_individual_artifacts(
                    repo_path=repo_path,
                    sign_result_file=str(signed_json_file),
                    destination_dir=sign_artifact_dir,
                    root_path=zip_root_path,
                    product_key=product_key,
                    ignore_patterns=ignore_patterns,
                    temp_dir=tmp_dir,
                )

        # 4 - Copy only the small metadata needed by publish. Never copy the
        # original extracted repository: for large releases it contains both a
        # multi-gigabyte ZIP and its (unneeded) expanded tree.
        original_dir = Path(repo_path).resolve().parent
        for name in (EXTRACT_RESULT_FILENAME, "attachments", "metadata"):
            source = original_dir / name
            destination = Path(output_path) / name
            if source.is_dir():
                shutil.copytree(source, destination, dirs_exist_ok=True)
            elif source.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

        # 5 - Adjust the EXTRACT_RESULT_FILENAME to point to the signed directory
        extract_result_path = os.path.join(output_path, EXTRACT_RESULT_FILENAME)
        if not os.path.isfile(extract_result_path):
            raise click.ClickException(
                f"Expected extract result file not found: {extract_result_path}."
                " Cannot repoint deliverable_dir to the signed directory."
            )
        with open(extract_result_path, "r") as f:
            extract_result = safe_json_load(f)
        extract_result["deliverable_dir"] = "signed"
        with open(extract_result_path, "w") as f:
            json.dump(extract_result, f)
    except Exception as e:
        raise click.ClickException(f"Error signing artifacts: {e}") from e
    click.echo("Sign command completed successfully.")
