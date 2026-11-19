"""Base Pulp REST API client for repository operations."""

import ssl
from types import TracebackType
from typing import Any, Self

import click
import httpx

from slan_cuan.http import (
    create_ssl_context,
    parse_json_dict,
    request,
)
from slan_cuan.pulp.constants import (
    AUTH_TYPE_CERT,
    AUTH_TYPE_TBR,
    AUTH_TYPES,
    DEFAULT_TIMEOUT_SECONDS,
    TASK_CANCEL_TIMEOUT_SECONDS,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import ModifyResult, PulpConfig
from slan_cuan.pulp.tasks import (
    BlockerLookup,
    BlockerLookupStatus,
    PulpTaskPoller,
)
from slan_cuan.pulp.utils import utc_timestamp


def _validate_auth(config: PulpConfig) -> None:
    """Validate auth fields are consistent with auth_type.

    Raises:
        PulpError: If required credentials are missing or inconsistent.

    """
    if config.auth_type not in AUTH_TYPES:
        raise PulpError(
            f"Invalid auth type '{config.auth_type}', "
            f"must be one of: {', '.join(sorted(AUTH_TYPES))}",
            status_code=0,
            response_body="",
        )
    if config.auth_type == AUTH_TYPE_TBR:
        if not config.username or not config.password:
            raise PulpError(
                "TBR auth requires --pulp-username and --pulp-password",
                status_code=0,
                response_body="",
            )
    elif config.auth_type == AUTH_TYPE_CERT:
        if config.client_cert is None or config.client_key is None:
            raise PulpError(
                "Certificate auth requires "
                "--pulp-client-cert and --pulp-client-key",
                status_code=0,
                response_body="",
            )


def _validate_config(config: PulpConfig) -> None:
    """Validate connection and operational config fields.

    Raises:
        PulpError: If required credentials or parameters are invalid.

    """
    if config.task_timeout <= 0:
        raise PulpError(
            f"task_timeout must be positive, got {config.task_timeout}",
            status_code=0,
            response_body="",
        )
    _validate_auth(config)


class PulpClientBase:
    """Shared HTTP client logic for Pulp repository operations."""

    _repo_api_path_template: str
    _repo_not_found_message: str

    def __init__(self, config: PulpConfig, distribution: str) -> None:
        """Initialize with connection config and target distribution."""
        self._config = config
        self._distribution = distribution
        _validate_config(config)

        base_url = config.base_url
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"

        verify = create_ssl_context(config.ca_cert, config.verify_ssl, PulpError)

        if config.auth_type == AUTH_TYPE_CERT:
            if not isinstance(verify, ssl.SSLContext):
                verify = ssl.create_default_context()
                verify.verify_flags &= ~ssl.VERIFY_X509_STRICT
            try:
                verify.load_cert_chain(
                    certfile=str(config.client_cert),
                    keyfile=str(config.client_key),
                )
            except (ssl.SSLError, OSError) as e:
                raise PulpError(
                    f"Failed to load client certificate: {e}",
                    status_code=0,
                    response_body="",
                ) from e

        auth = None
        tbr_ready = config.auth_type == AUTH_TYPE_TBR
        if tbr_ready and config.username and config.password:
            auth = (config.username, config.password)

        self._client = httpx.Client(
            base_url=base_url,
            verify=verify,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            auth=auth,
        )

    def __enter__(self) -> Self:
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit context manager and close client."""
        self.close()

    def _request(
        self,
        method: str,
        url: str,
        operation: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an HTTP request with optional verbose logging."""
        if self._config.verbose:
            details: list[str] = []
            if "headers" in kwargs and kwargs["headers"]:
                safe_headers = {
                    k: (
                        "***"
                        if any(
                            s in k.lower()
                            for s in (
                                "auth",
                                "token",
                                "key",
                                "secret",
                                "credential",
                            )
                        )
                        else v
                    )
                    for k, v in kwargs["headers"].items()
                }
                details.append(f"headers={safe_headers}")
            if "params" in kwargs and kwargs["params"]:
                details.append(f"params={kwargs['params']}")
            if "data" in kwargs and kwargs["data"]:
                safe_data = {
                    k: (
                        "***"
                        if any(
                            s in k.lower()
                            for s in ("password", "secret", "token", "key")
                        )
                        else v
                    )
                    for k, v in kwargs["data"].items()
                }
                details.append(f"data={safe_data}")
            if "json" in kwargs and kwargs["json"]:
                details.append(f"json={kwargs['json']}")
            if "files" in kwargs and kwargs["files"]:
                details.append(f"files={list(kwargs['files'].keys())}")
            payload_str = f" [{', '.join(details)}]" if details else ""
            click.echo(
                f"[{utc_timestamp()}]  Pulp request: {method} {url}{payload_str}"
            )

        response = request(
            self._client,
            method,
            url,
            operation,
            PulpError,
            **kwargs,
        )

        if self._config.verbose:
            details = []
            try:
                data = response.json()
                if isinstance(data, dict):
                    if "task" in data:
                        details.append(f"task={data['task']}")
                    elif operation != "Blocker task lookup":
                        state = data.get("state")
                        if state:
                            details.append(f"state={state}")
                            if state == "waiting":
                                waiting_on = self._find_blocking_task(data)
                                if waiting_on.href:
                                    details.append(
                                        f"waiting_on={waiting_on.href}"
                                    )
            except Exception:
                pass
            extra = f" [{', '.join(details)}]" if details else ""
            click.echo(
                f"[{utc_timestamp()}]  Pulp response: "
                f"{response.status_code}{extra}"
            )

        return response

    def cancel_task(self, task_href: str) -> str:
        """Attempt to cancel a Pulp task.

        Sends a PATCH request setting the task state to 'canceled' using a
        short cancellation timeout (TASK_CANCEL_TIMEOUT_SECONDS).

        Args:
            task_href: The task href to cancel.

        Returns:
            A descriptive string of the cancellation outcome.

        """
        try:
            response = self._request(
                "PATCH",
                task_href,
                "Task cancel",
                timeout=TASK_CANCEL_TIMEOUT_SECONDS,
                json={"state": "canceled"},
            )
            if response.status_code in (200, 202):
                return "cancellation requested in Pulp"
            return f"cancellation returned HTTP {response.status_code}"
        except PulpError as e:
            if e.status_code == 409:
                return (
                    "cancellation returned 409 Conflict "
                    "(task may have already finished or canceled)"
                )
            if self._config.verbose:
                click.echo(f"  Failed to cancel task {task_href}: {e}")
            msg = f"HTTP {e.status_code}" if e.status_code else str(e)
            return f"cancellation attempt failed: {msg}"
        except Exception as e:
            if self._config.verbose:
                click.echo(f"  Failed to cancel task {task_href}: {e}")
            return f"cancellation attempt failed: {e}"

    def _find_blocking_task(
        self, task_data: dict[str, object] | None
    ) -> BlockerLookup:
        """Find the task that a waiting task is waiting on.

        Checks:
        1. Explicit parent task if set on task_data.
        2. Any active (running) task reserving the same resources.
        3. An earlier task in 'waiting' state that is ahead in queue for the
           same resources.

        Returns:
            Blocker identity with FOUND, NOT_FOUND, or UNKNOWN status.

        """
        if not task_data or not isinstance(task_data, dict):
            return BlockerLookup(None, BlockerLookupStatus.UNKNOWN)

        if "_cached_waiting_on" in task_data:
            cached = task_data["_cached_waiting_on"]
            return BlockerLookup(
                str(cached) if cached is not None else None,
                BlockerLookupStatus(
                    str(task_data.get("_cached_waiting_status", "unknown"))
                ),
            )

        blocker: str | None = None
        lookup_failed = False

        # 1. Direct parent task
        parent = task_data.get("parent_task")
        if parent and isinstance(parent, str):
            blocker = parent
        else:
            # 2. Check reserved resources
            resources = task_data.get("reserved_resources_record")
            current_task_href = str(task_data.get("pulp_href") or "")
            if isinstance(resources, list) and resources:
                if current_task_href and "/tasks/" in current_task_href:
                    tasks_base = current_task_href.split("/tasks/")[0] + "/tasks/"
                else:
                    domain = self._config.domain
                    tasks_base = (
                        f"/api/pulp/{domain}/api/v3/tasks/"
                        if domain
                        else "/api/v3/tasks/"
                    )

                res_filter = ",".join(str(r) for r in resources)

                try:
                    res = self._request(
                        "GET",
                        tasks_base,
                        "Blocker task lookup",
                        params={
                            "reserved_resources__in": res_filter,
                            "state": "running",
                            "limit": 1,
                        },
                        timeout=10.0,
                    )
                    data = res.json()
                    if isinstance(data, dict):
                        results = data.get("results", [])
                        if results and isinstance(results, list):
                            candidate = results[0].get("pulp_href")
                            if candidate and candidate != current_task_href:
                                blocker = str(candidate)
                except Exception:
                    lookup_failed = True

                # If no running blocker found, check earlier waiting tasks
                if not blocker:
                    pulp_created = task_data.get("pulp_created")
                    params: dict[str, Any] = {
                        "reserved_resources__in": res_filter,
                        "state": "waiting",
                        "ordering": "pulp_created",
                        "limit": 2,
                    }
                    if pulp_created and isinstance(pulp_created, str):
                        params["pulp_created__lt"] = pulp_created

                    try:
                        res = self._request(
                            "GET",
                            tasks_base,
                            "Blocker task lookup",
                            params=params,
                            timeout=10.0,
                        )
                        data = res.json()
                        if isinstance(data, dict):
                            results = data.get("results", [])
                            if results and isinstance(results, list):
                                for item in results:
                                    candidate = item.get("pulp_href")
                                    if (
                                        candidate
                                        and candidate != current_task_href
                                    ):
                                        blocker = str(candidate)
                                        break
                    except Exception:
                        lookup_failed = True

        status = (
            BlockerLookupStatus.FOUND
            if blocker is not None
            else (
                BlockerLookupStatus.UNKNOWN
                if lookup_failed
                else BlockerLookupStatus.NOT_FOUND
            )
        )
        task_data["_cached_waiting_on"] = blocker
        task_data["_cached_waiting_status"] = status.value
        return BlockerLookup(blocker, status)

    def _handle_timeout(
        self,
        task_href: str,
        timeout: float,
        state: str,
        response_text: str,
        waiting_on: BlockerLookup | None = None,
        is_total_timeout: bool = False,
    ) -> None:
        """Handle timeout by canceling if waiting and raising PulpError."""
        canceled_note = ""
        if state == "waiting":
            outcome = self.cancel_task(task_href)
            canceled_note = f" ({outcome})"
        elif state not in ("completed", "failed", "canceled"):
            canceled_note = f" (cancellation skipped: task state is {state})"
        state_str = state
        if state == "waiting" and waiting_on and waiting_on.href:
            state_str = f"waiting, waiting on: {waiting_on.href}"
        if is_total_timeout:
            prefix = (
                f"Task polling timed out: exceeded maximum total wall-clock "
                f"time of {timeout}s"
            )
        else:
            prefix = f"Task polling timed out after {timeout}s"
        msg = f"{prefix} (state: {state_str}){canceled_note}"
        raise PulpError(
            msg,
            status_code=0,
            response_body=response_text,
        )

    def _check_task_status(
        self,
        task_href: str,
        req_timeout: float,
    ) -> tuple[dict[str, object], str, str]:
        """Fetch and parse current task status.

        Returns:
            Tuple of (task_data, state, raw_response_text).

        """
        response = self._request(
            "GET",
            task_href,
            "Task polling",
            timeout=req_timeout,
        )
        task_data = parse_json_dict(response, "Task", PulpError)
        state = str(task_data.get("state", ""))
        return task_data, state, response.text

    def poll_task(
        self,
        task_href: str,
        timeout: float | None = None,
        max_total_timeout: float | None = None,
    ) -> dict[str, object]:
        """Poll a Pulp task until completion or timeout.

        Applies exponential backoff with random jitter between poll attempts.
        Resets wait deadline on state transitions and blocker changes, subject
        to an absolute total wall-clock ceiling. If timeout is exceeded,
        attempts to cancel the task in Pulp before raising PulpError.

        Args:
            task_href: The task href returned from an async operation.
            timeout: Maximum time to wait in seconds per state (defaults to
                config.task_timeout).
            max_total_timeout: Absolute maximum wall-clock time in seconds
                across all state transitions. Defaults to 2 * timeout.

        Returns:
            The completed task response as a dict.

        Raises:
            PulpError: If the task fails, is canceled, or times out.
            ValueError: If timeout or max_total_timeout is not positive.

        """
        poller = PulpTaskPoller(
            client=self,
            task_href=task_href,
            timeout=timeout,
            max_total_timeout=max_total_timeout,
            error_cls=PulpError,
        )
        return poller.poll()

    def orphan_cleanup(
        self,
        content_hrefs: list[str],
        *,
        protection_time: int = 0,
    ) -> None:
        """Clean up orphaned content units from the domain.

        Mirrors npm-pulp-upload::orphan_cleanup_content, generalized to
        always require explicit content_hrefs (never a bare "clean
        everything" call) so other ecosystems' orphans in the same domain
        are never swept.

        Args:
            content_hrefs: List of content unit pulp_href values to clean
                up.
            protection_time: Orphan protection time in seconds (default 0).

        Raises:
            PulpError: If the cleanup request fails or task polling fails.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for orphan cleanup. "
                "Set --pulp-domain or use legacy deploy endpoint.",
                status_code=0,
                response_body="",
            )

        url = f"/api/pulp/{self._config.domain}/api/v3/orphans/cleanup/"
        payload = {
            "content_hrefs": content_hrefs,
            "orphan_protection_time": protection_time,
        }

        response = self._request(
            "POST",
            url,
            "Orphan cleanup",
            json=payload,
            headers=self._config.custom_headers or None,
        )

        try:
            response_data = parse_json_dict(response, "Cleanup", PulpError)
            task_href = str(response_data["task"])
            if self._config.verbose:
                click.echo(f"[{utc_timestamp()}]  Pulp task queued: {task_href}")
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse cleanup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

        self.poll_task(task_href)

    def modify_repository(
        self,
        repository_href: str,
        content_unit_hrefs: list[str],
        *,
        remove_content_unit_hrefs: list[str] | None = None,
    ) -> ModifyResult:
        """Add (and optionally remove) content units in a single version.

        Args:
            repository_href: The pulp_href of the repository.
            content_unit_hrefs: List of content unit pulp_href values to add.
            remove_content_unit_hrefs: Optional list of content unit
                pulp_href values to remove in the same modify call (mirrors
                the bash scripts' ``remove_content_units`` payload field,
                used by the npm upload replace-on-digest-mismatch path).

        Returns:
            ModifyResult with task details and repository version.

        Raises:
            PulpError: If the modify request fails or task polling fails.

        """
        url = f"{repository_href}modify/"
        payload: dict[str, list[str]] = {}
        if content_unit_hrefs:
            payload["add_content_units"] = content_unit_hrefs
        if remove_content_unit_hrefs:
            payload["remove_content_units"] = remove_content_unit_hrefs

        response = self._request(
            "POST",
            url,
            "Repository modify",
            json=payload,
            headers=self._config.custom_headers or None,
        )

        try:
            response_data = parse_json_dict(response, "Modify", PulpError)
            task_href = str(response_data["task"])
            if self._config.verbose:
                click.echo(f"[{utc_timestamp()}]  Pulp task queued: {task_href}")
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse modify response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

        task_data = self.poll_task(task_href)

        repository_version = None
        created_resources = task_data.get("created_resources", [])
        if isinstance(created_resources, list) and created_resources:
            repository_version = str(created_resources[0])

        return ModifyResult(
            task_href=task_href,
            state=str(task_data.get("state", "")),
            repository_version=repository_version,
            content_units_added=len(content_unit_hrefs),
        )

    def resolve_repository(self, name: str) -> str:
        """Look up a repository by name, return its pulp_href.

        Args:
            name: The repository name to look up.

        Returns:
            The pulp_href of the repository.

        Raises:
            PulpError: If the repository is not found or domain is not configured.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for repository lookup. "
                "Set --pulp-domain or use legacy deploy endpoint.",
                status_code=0,
                response_body="",
            )

        url = self._repo_api_path_template.format(domain=self._config.domain)

        response = self._request(
            "GET",
            url,
            "Repository lookup",
            params={"name": name},
        )

        try:
            response_data = parse_json_dict(response, "Repository", PulpError)
            results = response_data.get("results", [])
            if not results:
                raise PulpError(
                    self._repo_not_found_message.format(name=name),
                    status_code=404,
                    response_body=response.text,
                )

            return str(results[0]["pulp_href"])
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse repository lookup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def get_labels(self, href: str) -> dict[str, str]:
        """Get labels attached to a Pulp resource.

        Args:
            href: The pulp_href of the resource.

        Returns:
            A dict mapping label keys to values. Empty dict if no labels.

        Raises:
            PulpError: If the GET request fails.

        """
        response = self._request(
            "GET",
            href,
            "Get labels",
            headers=self._config.custom_headers or None,
        )

        response_data = parse_json_dict(response, "Get labels", PulpError)
        labels = response_data.get("pulp_labels", {})
        if not isinstance(labels, dict):
            return {}
        return labels

    def set_label(
        self,
        href: str,
        key: str,
        value: str,
        *,
        cas_digest: str | None = None,
        cas_label_key: str = "",
    ) -> None:
        """Set a label on a Pulp resource with optional compare-and-swap.

        When cas_digest is provided, first checks that the current value of
        cas_label_key either does not exist or matches cas_digest. If the
        current value is non-empty and does not match, raises PulpError without
        making the write.

        Args:
            href: The pulp_href of the resource.
            key: The label key to set.
            value: The label value to set.
            cas_digest: Optional expected current value for CAS check. If the
                cas_label_key's current value is non-empty and does not equal
                this, PulpError is raised.
            cas_label_key: The label key to check for CAS (if cas_digest given).

        Raises:
            PulpError: If the request fails or CAS check fails.

        """
        # CAS check: if cas_digest is provided, validate current value first
        if cas_digest is not None:
            current_labels = self.get_labels(href)
            current_value = current_labels.get(cas_label_key, "")
            if current_value and current_value != cas_digest:
                raise PulpError(
                    f"CAS check failed for label '{cas_label_key}': "
                    f"expected '{cas_digest}', found '{current_value}'",
                    status_code=0,
                    response_body="",
                )

        # Write the label
        url = f"{href}set_label/"
        payload = {"key": key, "value": value}

        self._request(
            "POST",
            url,
            "Set label",
            json=payload,
            headers=self._config.custom_headers or None,
        )

    def set_labels(self, href: str, labels: dict[str, str]) -> None:
        """Set multiple labels on a Pulp resource in a single write.

        Pulp's ``set_label/`` action only accepts one key/value pair per
        call. The resource's ``pulp_labels`` field itself accepts a full
        dict, so this reads the current labels, merges in the given ones,
        and writes the merged dict back with one PATCH -- two requests
        total instead of one ``set_label`` POST per key.

        This read-modify-write is not atomic: a label written by a
        concurrent caller between the GET and the PATCH here is clobbered.
        Only use this for keys that are exclusively owned by one writer at
        this point in the flow. For labels that may be written
        concurrently or need compare-and-swap, use ``set_label`` instead,
        whose ``set_label/`` action is a server-side atomic upsert of a
        single key.

        Args:
            href: The pulp_href of the resource.
            labels: Mapping of label keys to values to set.

        Raises:
            PulpError: If the GET or PATCH request fails.

        """
        if not labels:
            return

        current_labels = self.get_labels(href)
        merged_labels = {**current_labels, **labels}

        self._request(
            "PATCH",
            href,
            "Set labels",
            json={"pulp_labels": merged_labels},
            headers=self._config.custom_headers or None,
        )

    def list_content(
        self, list_url: str, **filters: str
    ) -> list[dict[str, object]]:
        """List Pulp content with full pagination support.

        Fetches all pages of results from a Pulp list endpoint, appending
        results until a page returns fewer than page_size items. Filters
        are passed as query parameters alongside limit and offset.

        Args:
            list_url: The full endpoint URL (e.g.
                "/api/v3/content/npm/packages/").
            **filters: Optional keyword filters to pass as query params
                (e.g., name="my-package", version="1.0.0").

        Returns:
            Concatenated list of all result items from all pages.

        Raises:
            PulpError: If any request fails.

        """
        page_size = 100
        offset = 0
        all_results: list[dict[str, object]] = []

        while True:
            params = {**filters, "limit": page_size, "offset": offset}
            response = self._request(
                "GET",
                list_url,
                "Content list",
                params=params,
                headers=self._config.custom_headers or None,
            )

            response_data = parse_json_dict(response, "Content list", PulpError)
            page_results = response_data.get("results", [])
            if not isinstance(page_results, list):
                page_results = []

            all_results.extend(page_results)

            # Stop pagination if this page has fewer than page_size items
            if len(page_results) < page_size:
                break

            offset += page_size

        return all_results

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
