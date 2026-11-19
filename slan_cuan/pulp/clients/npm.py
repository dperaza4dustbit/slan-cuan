"""Pulp REST API client for npm package upload/lookup operations."""

from __future__ import annotations

import json
from pathlib import Path

from slan_cuan.http import parse_json_dict
from slan_cuan.pulp.clients.base import PulpClientBase
from slan_cuan.pulp.constants import (
    FILE_CONTENT_API_PATH_TEMPLATE,
    NPM_CONTENT_API_PATH_TEMPLATE,
    NPM_REPO_API_PATH_TEMPLATE,
    NPM_VERSIONS_API_PATH_TEMPLATE,
)
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import NpmContentUnit


class PulpNpmClient(PulpClientBase):
    """HTTP client for Pulp npm package upload/lookup operations."""

    _repo_api_path_template = NPM_REPO_API_PATH_TEMPLATE
    _repo_not_found_message = (
        "npm repository '{name}' not found. Check --pulp-repository."
    )

    def upload_content(
        self,
        file_path: Path,
        name: str,
        version: str,
        *,
        labels: dict[str, str] | None = None,
    ) -> NpmContentUnit:
        """Upload an npm package tarball via the synchronous upload endpoint.

        The endpoint does not accept a ``repository`` field - the caller
        must add the returned content unit to a repository separately via
        the inherited ``modify_repository``.

        Args:
            file_path: Local path to the ``.tgz`` package file.
            name: npm package name.
            version: npm package version.
            labels: Optional dict of labels to attach to the content unit.

        Returns:
            NpmContentUnit with pulp_href, name, and version.

        Raises:
            PulpError: If the upload fails or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content API uploads. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        url = (
            NPM_CONTENT_API_PATH_TEMPLATE.format(domain=self._config.domain)
            + "upload/"
        )

        data: dict[str, str] = {
            "name": name,
            "version": version,
        }
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
                "npm package upload",
                data=data,
                files=files,
            )

        try:
            response_data = parse_json_dict(response, "npm content", PulpError)
            return NpmContentUnit(
                pulp_href=str(response_data["pulp_href"]),
                name=str(response_data.get("name") or name),
                version=str(response_data.get("version") or version),
            )
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse npm content unit response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e

    def find_by_name_version(
        self, name: str, version: str, repository_version_href: str
    ) -> dict[str, object] | None:
        """Find a content unit with an exact name and version match.

        The Pulp npm package list endpoint supports filtering by ``name``
        and ``repository_version`` but not ``version`` - rows are filtered
        locally for an exact version match after listing, using the full
        pagination of ``list_content``.

        Args:
            name: npm package name to match exactly.
            version: npm package version to match exactly.
            repository_version_href: Repository version href to scope the
                listing to.

        Returns:
            The matching content unit dict, or None if no row matches.

        Raises:
            PulpError: If more than one row matches exactly, the list
                request fails, or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content listing. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        list_url = NPM_CONTENT_API_PATH_TEMPLATE.format(
            domain=self._config.domain
        )
        rows = self.list_content(
            list_url,
            name=name,
            repository_version=repository_version_href,
        )

        matches = [
            row
            for row in rows
            if row.get("name") == name and row.get("version") == version
        ]

        if not matches:
            return None
        if len(matches) > 1:
            raise PulpError(
                f"Expected exactly one Pulp package for {name}@{version}, "
                f"got {len(matches)} matches",
                status_code=0,
                response_body="",
            )
        return matches[0]

    def list_versions_by_name(
        self, name: str, repository_version_href: str
    ) -> list[dict[str, object]]:
        """Return every version of an npm package in a repository version.

        Lists all content units named exactly ``name`` in
        ``repository_version_href``, whatever their version. Use this when
        the caller chooses the version itself, for example to resolve a
        semver range. Use ``find_by_name_version`` to look up one exact
        version.

        Rows are filtered again client-side on an exact ``name`` match,
        so only units with exactly that name are returned.

        Args:
            name: npm package name to match exactly.
            repository_version_href: Repository version href to scope the
                listing to.

        Returns:
            List of matching content unit dicts (possibly empty).

        Raises:
            PulpError: If the list request fails or domain is not set.

        """
        if self._config.domain is None:
            raise PulpError(
                "Domain is required for content listing. Set --pulp-domain.",
                status_code=0,
                response_body="",
            )

        list_url = NPM_CONTENT_API_PATH_TEMPLATE.format(
            domain=self._config.domain
        )
        rows = self.list_content(
            list_url,
            name=name,
            repository_version=repository_version_href,
        )
        return [row for row in rows if row.get("name") == name]

    def get_artifact_sha256(self, artifact_href: str) -> str:
        """Fetch the sha256 digest of an artifact.

        Args:
            artifact_href: The pulp_href of the artifact.

        Returns:
            The artifact's sha256 hex digest.

        Raises:
            PulpError: If the GET request fails, the response isn't a
                JSON object, or its ``sha256`` field is missing, null,
                empty, or not a string. Raising (rather than returning a
                sentinel) keeps a malformed response from being mistaken
                for a digest mismatch, which with --allow-content-replace
                would trigger the destructive replace path.

        """
        response = self._request(
            "GET",
            artifact_href,
            "Artifact lookup",
        )
        response_data = parse_json_dict(response, "Artifact", PulpError)
        sha256 = response_data.get("sha256")
        if not isinstance(sha256, str) or not sha256:
            raise PulpError(
                f"Artifact response for {artifact_href} has no usable "
                f"sha256 (got {sha256!r})",
                status_code=response.status_code,
                response_body=response.text,
            )
        return sha256

    def get_content(self, content_href: str) -> dict[str, object]:
        """Fetch the full detail record for an npm content unit.

        Used as a fallback when a content list response omits fields
        (e.g. ``artifact``) that the detail endpoint returns.

        Args:
            content_href: The pulp_href of the content unit.

        Returns:
            The full parsed JSON body of the content detail response.

        Raises:
            PulpError: If the GET request fails or the response isn't a
                JSON object.

        """
        response = self._request(
            "GET",
            content_href,
            "Content lookup",
        )
        return parse_json_dict(response, "Content", PulpError)

    def destroy_repository_version(self, version_href: str) -> None:
        """Delete a repository version, polling the task if one is returned.

        Mirrors the bash script's ``destroy_repository_versions_holding``
        per-version delete step.

        Args:
            version_href: The pulp_href of the repository version to
                delete.

        Raises:
            PulpError: If the delete request fails or task polling fails.

        """
        response = self._request(
            "DELETE",
            version_href,
            "Repository version delete",
        )

        try:
            response_data = response.json()
        except ValueError:
            response_data = None

        if isinstance(response_data, dict) and "task" in response_data:
            self.poll_task(str(response_data["task"]))

    def list_repository_versions_holding(
        self, repository_href: str, content_href: str
    ) -> list[str]:
        """List repository version hrefs that still hold a content unit.

        Args:
            repository_href: The pulp_href of the repository.
            content_href: The pulp_href of the content unit to search for.

        Returns:
            List of repository version pulp_href values, across all pages.

        Raises:
            PulpError: If any page request fails.

        """
        versions_url = NPM_VERSIONS_API_PATH_TEMPLATE.format(
            repository_href=repository_href
        )
        rows = self.list_content(versions_url, content=content_href)
        return [str(row["pulp_href"]) for row in rows]

    def upload_file_content(
        self, file_path: Path, repository_href: str, relative_path: str
    ) -> str:
        """Upload a compliance sidecar file to a Pulp File repository.

        Best-effort from the caller's side (the caller logs and continues
        on failure), but this method itself raises PulpError on a non-2xx
        response.

        Args:
            file_path: Local path to the sidecar file.
            repository_href: The pulp_href of the target File repository.
            relative_path: Path within the file repository.

        Returns:
            The pulp_href of the resulting content unit.

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
            "repository": repository_href,
            "relative_path": relative_path,
        }

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
                "Compliance sidecar upload",
                data=data,
                files=files,
            )

        try:
            response_data = parse_json_dict(response, "File content", PulpError)
            return str(response_data["pulp_href"])
        except (ValueError, KeyError) as e:
            raise PulpError(
                f"Failed to parse file content unit response: {e}",
                status_code=response.status_code,
                response_body=response.text,
            ) from e
