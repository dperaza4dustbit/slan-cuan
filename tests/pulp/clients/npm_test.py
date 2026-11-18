"""Tests for the Pulp npm client (slan_cuan/pulp/clients/npm.py)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from slan_cuan.pulp.clients.npm import PulpNpmClient
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import NpmContentUnit, PulpConfig

_REPO_HREF = "/api/v3/repositories/npm/npm/abc/"
_REPO_VERSION_HREF = "/api/v3/repositories/npm/npm/abc/versions/3/"


def _config(**overrides: object) -> PulpConfig:
    defaults: dict[str, object] = {
        "base_url": "https://pulp.example.com",
        "verify_ssl": True,
        "domain": "testdomain",
        "username": "testuser",
        "password": "testpass",
    }
    defaults.update(overrides)
    return PulpConfig(**defaults)  # type: ignore[arg-type]


def _client_with_transport(
    handler: object, config: PulpConfig | None = None
) -> PulpNpmClient:
    client = PulpNpmClient(config or _config(), "test-npm-dist")
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        base_url="https://pulp.example.com",
    )
    return client


class TestUploadContent:
    """Tests for upload_content()."""

    def test_upload_content_posts_multipart_with_name_version(
        self, tmp_path: Path
    ) -> None:
        """POST goes to the sync npm upload endpoint with multipart data."""
        pkg_file = tmp_path / "my-pkg-1.0.0.tgz"
        pkg_file.write_text("tgz content")

        captured_url: str | None = None
        captured_content_type: str | None = None
        captured_body = b""

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url, captured_content_type, captured_body
            captured_url = str(request.url)
            captured_content_type = request.headers.get("content-type", "")
            captured_body = request.content
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/npm/packages/abc123/",
                    "name": "my-pkg",
                    "version": "1.0.0",
                },
            )

        client = _client_with_transport(handler)

        result = client.upload_content(pkg_file, "my-pkg", "1.0.0")

        assert captured_url is not None
        assert (
            "/api/pulp/testdomain/api/v3/content/npm/packages/upload/"
            in captured_url
        )
        assert captured_content_type is not None
        assert "multipart" in captured_content_type.lower()

        body = captured_body.decode("utf-8", errors="replace")
        assert 'name="name"' in body
        assert 'name="version"' in body
        assert "my-pkg" in body
        assert "1.0.0" in body
        # Sync upload must NOT include a repository field.
        assert 'name="repository"' not in body

        assert result == NpmContentUnit(
            pulp_href="/api/v3/content/npm/packages/abc123/",
            name="my-pkg",
            version="1.0.0",
        )

    def test_upload_content_includes_pulp_labels_when_given(
        self, tmp_path: Path
    ) -> None:
        """Labels are passed as a JSON pulp_labels form field."""
        pkg_file = tmp_path / "my-pkg-1.0.0.tgz"
        pkg_file.write_text("tgz content")

        captured_body: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/npm/packages/abc123/",
                    "name": "my-pkg",
                    "version": "1.0.0",
                },
            )

        client = _client_with_transport(handler)

        client.upload_content(
            pkg_file,
            "my-pkg",
            "1.0.0",
            labels={"tl.compliance_level": "L2"},
        )

        assert captured_body is not None
        assert 'name="pulp_labels"' in captured_body

        import re

        pattern = r'name="pulp_labels".*?\r\n\r\n(.*?)\r\n--'
        match = re.search(pattern, captured_body, re.DOTALL)
        assert match is not None
        decoded_labels = json.loads(match.group(1))
        assert decoded_labels == {"tl.compliance_level": "L2"}

    def test_upload_content_without_labels_omits_pulp_labels(
        self, tmp_path: Path
    ) -> None:
        """No labels dict means no pulp_labels field at all."""
        pkg_file = tmp_path / "my-pkg-1.0.0.tgz"
        pkg_file.write_text("tgz content")

        captured_body: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/npm/packages/abc123/",
                    "name": "my-pkg",
                    "version": "1.0.0",
                },
            )

        client = _client_with_transport(handler)

        client.upload_content(pkg_file, "my-pkg", "1.0.0")

        assert captured_body is not None
        assert 'name="pulp_labels"' not in captured_body

    def test_upload_content_error_raises_pulp_error(self, tmp_path: Path) -> None:
        """A non-2xx response raises PulpError."""
        pkg_file = tmp_path / "my-pkg-1.0.0.tgz"
        pkg_file.write_text("tgz content")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        client = _client_with_transport(handler)

        with pytest.raises(PulpError) as exc_info:
            client.upload_content(pkg_file, "my-pkg", "1.0.0")

        assert exc_info.value.status_code == 500

    def test_upload_content_requires_domain(self, tmp_path: Path) -> None:
        """Config with domain=None raises PulpError about domain."""
        pkg_file = tmp_path / "my-pkg-1.0.0.tgz"
        pkg_file.write_text("tgz content")

        config = _config(domain=None)
        client = PulpNpmClient(config, "test-npm-dist")

        with pytest.raises(PulpError) as exc_info:
            client.upload_content(pkg_file, "my-pkg", "1.0.0")

        assert "Domain is required" in exc_info.value.message
        assert exc_info.value.status_code == 0


class TestFindByNameVersion:
    """Tests for find_by_name_version()."""

    def test_find_by_name_version_returns_matching_row(self) -> None:
        """A single exact name+version match is returned."""
        captured_params: dict[str, str] | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_params
            captured_params = {k: v for k, v in request.url.params.items()}
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/api/v3/content/npm/pk/1/",
                            "name": "my-pkg",
                            "version": "1.0.0",
                        },
                        {
                            "pulp_href": "/api/v3/content/npm/pk/2/",
                            "name": "my-pkg",
                            "version": "2.0.0",
                        },
                    ]
                },
            )

        client = _client_with_transport(handler)

        result = client.find_by_name_version(
            "my-pkg", "1.0.0", _REPO_VERSION_HREF
        )

        assert result == {
            "pulp_href": "/api/v3/content/npm/pk/1/",
            "name": "my-pkg",
            "version": "1.0.0",
        }
        assert captured_params is not None
        assert captured_params["name"] == "my-pkg"
        assert captured_params["repository_version"] == (_REPO_VERSION_HREF)
        # version is NOT a supported list filter - must not be sent.
        assert "version" not in captured_params

    def test_find_by_name_version_returns_none_when_absent(self) -> None:
        """No rows match name+version -> None, no error."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/api/v3/content/npm/pk/1/",
                            "name": "my-pkg",
                            "version": "2.0.0",
                        },
                    ]
                },
            )

        client = _client_with_transport(handler)

        result = client.find_by_name_version(
            "my-pkg", "1.0.0", _REPO_VERSION_HREF
        )

        assert result is None

    def test_find_by_name_version_raises_on_multiple_exact_matches(
        self,
    ) -> None:
        """More than one exact name+version row is a PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/api/v3/content/npm/pk/1/",
                            "name": "my-pkg",
                            "version": "1.0.0",
                        },
                        {
                            "pulp_href": "/api/v3/content/npm/pk/2/",
                            "name": "my-pkg",
                            "version": "1.0.0",
                        },
                    ]
                },
            )

        client = _client_with_transport(handler)

        with pytest.raises(PulpError) as exc_info:
            client.find_by_name_version("my-pkg", "1.0.0", _REPO_VERSION_HREF)

        assert "my-pkg" in exc_info.value.message
        assert "1.0.0" in exc_info.value.message

    def test_find_by_name_version_paginates_correctly(self) -> None:
        """find_by_name_version uses list_content's full pagination.

        Mirrors list_content's own full-page boundary test but driven
        through this method, to confirm it doesn't shortcut to a single
        page.
        """
        captured_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            url_str = str(request.url)
            if "offset=0" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {
                                "pulp_href": f"/api/v3/content/npm/pk/{i}/",
                                "name": "my-pkg",
                                "version": f"0.{i}.0",
                            }
                            for i in range(1, 101)
                        ]
                    },
                )
            if "offset=100" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {
                                "pulp_href": "/api/v3/content/npm/pk/101/",
                                "name": "my-pkg",
                                "version": "1.0.0",
                            },
                        ]
                    },
                )
            return httpx.Response(200, json={"results": []})

        client = _client_with_transport(handler)

        result = client.find_by_name_version(
            "my-pkg", "1.0.0", _REPO_VERSION_HREF
        )

        assert result == {
            "pulp_href": "/api/v3/content/npm/pk/101/",
            "name": "my-pkg",
            "version": "1.0.0",
        }
        assert len(captured_requests) == 2
        assert "offset=100" in str(captured_requests[1].url)


class TestListVersionsByName:
    """Tests for list_versions_by_name()."""

    def test_list_versions_by_name_returns_every_row_for_name(self) -> None:
        """All versions for an exact name are returned, unfiltered by version."""
        captured_params: dict[str, str] | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_params
            captured_params = {k: v for k, v in request.url.params.items()}
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/api/v3/content/npm/pk/1/",
                            "name": "my-pkg",
                            "version": "1.0.0",
                        },
                        {
                            "pulp_href": "/api/v3/content/npm/pk/2/",
                            "name": "my-pkg",
                            "version": "2.0.0",
                        },
                        {
                            "pulp_href": "/api/v3/content/npm/pk/3/",
                            "name": "other-pkg",
                            "version": "9.0.0",
                        },
                    ]
                },
            )

        client = _client_with_transport(handler)

        result = client.list_versions_by_name("my-pkg", _REPO_VERSION_HREF)

        assert [row["version"] for row in result] == ["1.0.0", "2.0.0"]
        assert captured_params is not None
        assert captured_params["name"] == "my-pkg"
        assert captured_params["repository_version"] == _REPO_VERSION_HREF

    def test_list_versions_by_name_returns_empty_list_when_absent(self) -> None:
        """No rows match the name -> an empty list, not None."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": []})

        client = _client_with_transport(handler)

        result = client.list_versions_by_name("my-pkg", _REPO_VERSION_HREF)

        assert result == []


class TestGetArtifactSha256:
    """Tests for get_artifact_sha256()."""

    def test_get_artifact_sha256_returns_digest(self) -> None:
        """GET of the artifact href returns its sha256 field."""
        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={"sha256": "deadbeef" * 8},
            )

        client = _client_with_transport(handler)

        sha256 = client.get_artifact_sha256("/api/v3/artifacts/abc123/")

        assert sha256 == "deadbeef" * 8
        assert captured_url is not None
        assert "/api/v3/artifacts/abc123/" in captured_url

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"pulp_href": "/api/v3/artifacts/abc/"}, id="missing"),
            pytest.param({"sha256": None}, id="null"),
            pytest.param({"sha256": ""}, id="empty"),
            pytest.param({"sha256": 12345}, id="non-string-int"),
        ],
    )
    def test_get_artifact_sha256_raises_on_missing_digest(
        self, body: dict[str, object]
    ) -> None:
        """A missing/null/empty/non-string sha256 raises, not a sentinel."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=body)

        client = _client_with_transport(handler)

        with pytest.raises(PulpError, match="sha256"):
            client.get_artifact_sha256("/api/v3/artifacts/abc/")


class TestGetContent:
    """Tests for get_content()."""

    def test_get_content_returns_full_body(self) -> None:
        """GET of the content href returns the full JSON body, not labels."""
        body = {
            "pulp_href": "/api/v3/content/npm/packages/xyz/",
            "name": "pkg",
            "version": "1.0.0",
            "artifact": "/api/v3/artifacts/abc/",
            "pulp_labels": {"tl.compliance_level": "L2"},
        }
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json=body)

        client = _client_with_transport(handler)

        result = client.get_content("/api/v3/content/npm/packages/xyz/")

        assert result == body
        assert len(captured) == 1
        assert captured[0].method == "GET"
        assert "/api/v3/content/npm/packages/xyz/" in str(captured[0].url)

    def test_get_content_raises_pulp_error_on_failure(self) -> None:
        """A non-2xx response raises PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"detail": "Not found."})

        client = _client_with_transport(handler)

        with pytest.raises(PulpError):
            client.get_content("/api/v3/content/npm/packages/xyz/")


class TestDestroyRepositoryVersion:
    """Tests for destroy_repository_version()."""

    def test_destroy_repository_version_deletes_and_polls_task(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DELETE returns a task href which gets polled to completion."""
        import slan_cuan.pulp.tasks as tasks_mod

        monkeypatch.setattr(tasks_mod.time, "sleep", lambda *_a: None)

        captured_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            if request.method == "DELETE":
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/delete-uuid/"},
                )
            return httpx.Response(200, json={"state": "completed"})

        client = _client_with_transport(handler)

        client.destroy_repository_version(_REPO_VERSION_HREF)

        assert len(captured_requests) == 2
        assert captured_requests[0].method == "DELETE"
        assert _REPO_VERSION_HREF in str(captured_requests[0].url)
        assert captured_requests[1].method == "GET"
        assert "delete-uuid" in str(captured_requests[1].url)

    def test_destroy_repository_version_no_task_in_response(self) -> None:
        """When the DELETE response has no task, no polling occurs."""
        captured_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(204)

        client = _client_with_transport(handler)

        client.destroy_repository_version(_REPO_VERSION_HREF)

        assert len(captured_requests) == 1
        assert captured_requests[0].method == "DELETE"


class TestListRepositoryVersionsHolding:
    """Tests for list_repository_versions_holding()."""

    def test_list_repository_versions_holding_paginates(self) -> None:
        """Full pagination over versions/?content=<href> is exercised."""
        captured_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            url_str = str(request.url)
            if "offset=0" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"pulp_href": (f"{_REPO_HREF}versions/{i}/")}
                            for i in range(1, 101)
                        ]
                    },
                )
            if "offset=100" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"pulp_href": f"{_REPO_HREF}versions/101/"},
                        ]
                    },
                )
            return httpx.Response(200, json={"results": []})

        client = _client_with_transport(handler)

        result = client.list_repository_versions_holding(
            _REPO_HREF, "/api/v3/content/npm/packages/abc/"
        )

        assert len(result) == 101
        assert result[0] == f"{_REPO_HREF}versions/1/"
        assert result[100] == f"{_REPO_HREF}versions/101/"
        assert len(captured_requests) == 2
        assert "content=" in str(captured_requests[0].url)
        assert f"{_REPO_HREF}versions/" in str(captured_requests[0].url)


class TestUploadFileContent:
    """Tests for upload_file_content()."""

    def test_upload_file_content_posts_and_returns_href(
        self, tmp_path: Path
    ) -> None:
        """POST sidecar file+repository+relative_path, returns pulp_href."""
        sidecar_file = tmp_path / "sidecar.json"
        sidecar_file.write_text('{"compliance_level": "L2"}')

        captured_url: str | None = None
        captured_body: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url, captured_body
            captured_url = str(request.url)
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={"pulp_href": "/api/v3/content/file/files/xyz/"},
            )

        client = _client_with_transport(handler)

        href = client.upload_file_content(
            sidecar_file,
            "/api/v3/repositories/file/file/fff/",
            "npm-tl-compliance/my-pkg/1.0.0/deadbeef/sidecar.json",
        )

        assert href == "/api/v3/content/file/files/xyz/"
        assert captured_url is not None
        assert "/api/pulp/testdomain/api/v3/content/file/files/" in captured_url
        assert captured_body is not None
        assert 'name="repository"' in captured_body
        assert "/api/v3/repositories/file/file/fff/" in captured_body
        assert 'name="relative_path"' in captured_body
        assert (
            "npm-tl-compliance/my-pkg/1.0.0/deadbeef/sidecar.json"
            in captured_body
        )

    def test_upload_file_content_raises_pulp_error_on_failure(
        self, tmp_path: Path
    ) -> None:
        """A non-2xx response raises PulpError."""
        sidecar_file = tmp_path / "sidecar.json"
        sidecar_file.write_text('{"compliance_level": "L2"}')

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="Bad Request")

        client = _client_with_transport(handler)

        with pytest.raises(PulpError) as exc_info:
            client.upload_file_content(
                sidecar_file,
                "/api/v3/repositories/file/file/fff/",
                "npm-tl-compliance/my-pkg/1.0.0/deadbeef/sidecar.json",
            )

        assert exc_info.value.status_code == 400
