"""Pulp REST API clients for File repository operations."""

from __future__ import annotations

import json
from pathlib import Path

import click

from slan_cuan.http import parse_json_dict
from slan_cuan.pulp.clients.base import PulpClientBase
from slan_cuan.pulp.constants import (
    FILE_CONTENT_API_PATH_TEMPLATE,
    FILE_DISTRIBUTION_API_PATH_TEMPLATE,
    FILE_REPO_API_PATH_TEMPLATE,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import FileContentUnit
from slan_cuan.pulp.utils import utc_timestamp


class PulpFileClient(PulpClientBase):
    """HTTP client for Pulp File repository operations."""

    _repo_api_path_template = FILE_REPO_API_PATH_TEMPLATE
    _repo_not_found_message = (
        "File repository '{name}' not found. Check --pulp-file-repository."
    )

    def upload_content(
        self,
        file_path: Path,
        relative_path: str,
        sha256: str,
        repository_href: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> FileContentUnit:
        """Upload a file to the Pulp File content API.

        Args:
            file_path: Local path to the file.
            relative_path: Path within the file repository.
            sha256: SHA-256 hex digest of the file.
            repository_href: Optional repository href to associate
                the content unit with during creation.
            labels: Optional labels to attach to the content unit.

        Returns:
            FileContentUnit with pulp_href and metadata.

        Raises:
            PulpError: If the upload fails or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content API uploads. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = FILE_CONTENT_API_PATH_TEMPLATE.format(domain=self._config.domain)

        data: dict[str, str] = {
            "relative_path": relative_path,
            "sha256": sha256,
        }
        if repository_href:
            data["repository"] = repository_href
        if labels:
            data["pulp_labels"] = json.dumps(labels)

        with file_path.open("rb") as f:
            files = {
                "file": (
                    file_path.name,
                    f,
                    "application/octet-stream",
                ),
            }
            response = self._request(
                "POST",
                url,
                "File upload",
                data=data,
                files=files,
            )

        try:
            response_data = parse_json_dict(response, "File content", PulpError)

            if "task" in response_data:
                task_href = str(response_data["task"])
                if self._config.verbose:
                    click.echo(
                        f"[{utc_timestamp()}]  Pulp task queued: {task_href}"
                    )
                task_data = self.poll_task(task_href)
                created = task_data.get("created_resources", [])
                if not isinstance(created, list) or not created:
                    raise PulpError(
                        "File upload task completed but created no resources",
                        status_code=response.status_code,
                        response_body=response.text,
                    )
                content_href = next(
                    (str(r) for r in created if "/content/file/files/" in str(r)),
                    str(created[-1]),
                )
                content_response = self._request(
                    "GET",
                    content_href,
                    "File content lookup",
                )
                response_data = parse_json_dict(
                    content_response, "File content", PulpError
                )

            return FileContentUnit(
                pulp_href=str(response_data["pulp_href"]),
                relative_path=str(
                    response_data.get("relative_path", relative_path)
                ),
                sha256=str(response_data.get("sha256", sha256)),
            )
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse file content unit response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def get_content(
        self, repository_href: str, relative_path: str
    ) -> dict[str, object] | None:
        """Return the file content unit at *relative_path*, if present.

        Looks in the repository's latest version. A File repository holds
        one file per relative path, so uploading another file under an
        existing path would replace it in the new version.

        Returns:
            The content unit (``sha256``, ``pulp_labels``, ...), or None
            when the path is free.

        Raises:
            PulpError: If a lookup fails, returns invalid data, or the
                domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content lookup. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )
        repo_response = self._request("GET", repository_href, "Repository lookup")
        try:
            repo_data = parse_json_dict(repo_response, "Repository", PulpError)
            latest = repo_data.get("latest_version_href")
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse repository lookup response: {e}",
                status_code=repo_response.status_code,
                response_body=repo_response.text,
            ) from e
        if not latest:
            return None

        url = FILE_CONTENT_API_PATH_TEMPLATE.format(domain=self._config.domain)
        response = self._request(
            "GET",
            url,
            "File content lookup",
            params={
                "relative_path": relative_path,
                "repository_version": str(latest),
            },
        )
        try:
            data = parse_json_dict(response, "File content", PulpError)
            results = data.get("results", [])
            if not isinstance(results, list):
                raise ValueError("results is not a list")
            for unit in results:
                if unit.get("relative_path") == relative_path:
                    return {
                        "sha256": str(unit["sha256"]),
                        "pulp_labels": dict(unit.get("pulp_labels") or {}),
                    }
            return None
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise PulpError(
                f"Failed to parse file content lookup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def get_distribution_repository(self, name: str) -> str | None:
        """Return the repository href backing the File distribution named *name*.

        Returns None when the distribution exists but is pinned to a
        publication instead of serving a repository.

        Raises:
            PulpError: If no distribution has that name, the lookup fails,
                or the domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for distribution lookup. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = FILE_DISTRIBUTION_API_PATH_TEMPLATE.format(
            domain=self._config.domain
        )

        response = self._request(
            "GET",
            url,
            "Distribution lookup",
            params={"name": name},
        )

        try:
            response_data = parse_json_dict(response, "Distribution", PulpError)
            results = response_data.get("results", [])
            if not isinstance(results, list):
                raise ValueError("results is not a list")
            if not results:
                raise PulpError(
                    f"Distribution '{name}' not found. "
                    "Check --pulp-file-repository.",
                    status_code=404,
                    response_body=response.text,
                )

            repository = results[0].get("repository")
            return str(repository) if repository else None
        except (ValueError, KeyError, TypeError) as e:
            raise PulpError(
                f"Failed to parse distribution lookup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def get_repository_autopublish(self, repository_href: str) -> bool:
        """Return whether the File repository has autopublish enabled.

        Args:
            repository_href: The pulp_href of the repository.

        Returns:
            True when autopublish is enabled on the repository.

        Raises:
            PulpError: If the lookup fails or returns invalid data.

        """
        response = self._request(
            "GET",
            repository_href,
            "Repository lookup",
        )

        try:
            response_data = parse_json_dict(response, "Repository", PulpError)
            return bool(response_data.get("autopublish", False))
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse repository lookup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def get_distribution_base_path(self, name: str) -> str | None:
        """Return the ``base_path`` of the File distribution named *name*.

        Returns None when no distribution has that name.

        Raises:
            PulpError: If the lookup fails, returns invalid data, or the
                domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for distribution lookup. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )
        url = FILE_DISTRIBUTION_API_PATH_TEMPLATE.format(
            domain=self._config.domain
        )
        response = self._request(
            "GET",
            url,
            "Distribution lookup",
            params={"name": name},
        )
        try:
            response_data = parse_json_dict(response, "Distribution", PulpError)
            results = response_data.get("results", [])
            if not isinstance(results, list):
                raise ValueError("results is not a list")
            if not results:
                return None
            return str(results[0]["base_path"])
        except (ValueError, KeyError, TypeError) as e:
            raise PulpError(
                f"Failed to parse distribution lookup response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e
