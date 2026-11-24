"""Tests for the Pulp File client (slan_cuan/pulp/clients/file.py)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.pulp.clients.file import PulpFileClient
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig


def _file_content_handler(
    content_response: dict[str, object] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Create a handler for Pulp File content upload."""
    if content_response is None:
        content_response = {
            "pulp_href": "/api/v3/content/file/files/abc123/",
            "relative_path": "BUILD123/gav-index.osv.json",
            "sha256": "deadbeef" * 8,
        }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v3/content/file/files/" in url:
            return httpx.Response(200, json=content_response)
        return httpx.Response(404)

    return handler


class TestPulpFileClient:
    """Tests for PulpFileClient operations."""

    def test_close(self) -> None:
        """Verify close() doesn't raise."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client.close()

    def test_upload_content_success(self, tmp_path: Path) -> None:
        """Single POST returns FileContentUnit with correct fields."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        handler = _file_content_handler()
        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            test_file,
            "BUILD123/gav-index.osv.json",
            sha256="deadbeef" * 8,
        )

        assert result.pulp_href == "/api/v3/content/file/files/abc123/"
        assert result.relative_path == "BUILD123/gav-index.osv.json"
        assert result.sha256 == "deadbeef" * 8

    def test_upload_content_async_task(self, tmp_path: Path) -> None:
        """Async 202 response polls task and fetches created resource."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        task_href = "/api/pulp/testdomain/api/v3/tasks/task-uuid/"
        content_href = "/api/v3/content/file/files/new123/"

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/api/v3/content/file/files/" in url and request.method == "POST":
                return httpx.Response(202, json={"task": task_href})
            if task_href in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [content_href],
                    },
                )
            if content_href in url:
                return httpx.Response(
                    200,
                    json={
                        "pulp_href": content_href,
                        "relative_path": "BUILD123/gav-index.osv.json",
                        "sha256": "deadbeef" * 8,
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            test_file,
            "BUILD123/gav-index.osv.json",
            sha256="deadbeef" * 8,
        )

        assert result.pulp_href == content_href
        assert result.relative_path == "BUILD123/gav-index.osv.json"
        assert result.sha256 == "deadbeef" * 8

    def test_upload_content_async_task_with_repo_version_resource(
        self, tmp_path: Path
    ) -> None:
        """Async task creating repo version and content unit resolves content."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        task_href = "/api/pulp/testdomain/api/v3/tasks/task-uuid/"
        repo_ver_href = (
            "/api/pulp/testdomain/api/v3/repositories/file/file/uuid/versions/1/"
        )
        content_href = "/api/v3/content/file/files/new123/"

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/api/v3/content/file/files/" in url and request.method == "POST":
                return httpx.Response(202, json={"task": task_href})
            if task_href in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [repo_ver_href, content_href],
                    },
                )
            if content_href in url:
                return httpx.Response(
                    200,
                    json={
                        "pulp_href": content_href,
                        "relative_path": "BUILD123/gav-index.osv.json",
                        "sha256": "deadbeef" * 8,
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        result = client.upload_content(
            test_file,
            "BUILD123/gav-index.osv.json",
            sha256="deadbeef" * 8,
            repository_href="/api/pulp/testdomain/api/v3/repositories/file/file/uuid/",
        )

        assert result.pulp_href == content_href
        assert result.relative_path == "BUILD123/gav-index.osv.json"
        assert result.sha256 == "deadbeef" * 8

    def test_upload_content_async_task_no_resources(self, tmp_path: Path) -> None:
        """Async task that creates no resources raises PulpError."""
        test_file = tmp_path / "gav-index.osv.json"
        test_file.write_text("[]")

        task_href = "/api/pulp/testdomain/api/v3/tasks/task-uuid/"

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/api/v3/content/file/files/" in url and request.method == "POST":
                return httpx.Response(202, json={"task": task_href})
            if task_href in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [],
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError, match="created no resources"):
            client.upload_content(
                test_file,
                "BUILD123/gav-index.osv.json",
                sha256="deadbeef" * 8,
            )

    def test_upload_content_url(self, tmp_path: Path) -> None:
        """Upload hits the File content API path."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/file/files/abc/",
                    "relative_path": "B/test.osv.json",
                    "sha256": "abc",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(test_file, "B/test.osv.json", sha256="abc")

        assert captured_url is not None
        assert "/api/pulp/testdomain/api/v3/content/file/files/" in captured_url

    def test_upload_content_multipart_fields(self, tmp_path: Path) -> None:
        """Verify form data includes relative_path and sha256."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        captured_body: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = request.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/file/files/abc/",
                    "relative_path": "B/test.osv.json",
                    "sha256": "abcdef",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        client.upload_content(test_file, "B/test.osv.json", sha256="abcdef")

        assert captured_body is not None
        assert "relative_path" in captured_body
        assert "B/test.osv.json" in captured_body
        assert "sha256" in captured_body
        assert "abcdef" in captured_body

    def test_upload_content_error(self, tmp_path: Path) -> None:
        """Error response raises PulpError."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
        )

        with pytest.raises(PulpError, match="File upload failed"):
            client.upload_content(test_file, "B/test.osv.json", sha256="abc")

    def test_upload_content_domain_required(self, tmp_path: Path) -> None:
        """Missing domain raises PulpError."""
        test_file = tmp_path / "test.osv.json"
        test_file.write_text("[]")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")

        with pytest.raises(PulpError, match="Domain is required"):
            client.upload_content(test_file, "B/test.osv.json", sha256="abc")

    def test_resolve_repository_success(self) -> None:
        """Successful lookup returns pulp_href."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": ("/api/v3/repositories/file/file/uuid/")}
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.resolve_repository("my-file-repo")
        assert href == "/api/v3/repositories/file/file/uuid/"

    def test_resolve_repository_not_found(self) -> None:
        """Empty results raises PulpError with 404."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError, match="not found"):
            client.resolve_repository("nonexistent-repo")

    def test_resolve_repository_url(self) -> None:
        """Verify the File repository API path is used."""
        captured_url: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": ("/api/v3/repositories/file/file/uuid/")}
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="mydom",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.resolve_repository("my-file-repo")

        assert captured_url is not None
        assert "/api/pulp/mydom/api/v3/repositories/file/file/" in captured_url
        assert "name=my-file-repo" in captured_url

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_success(self, mock_sleep: Mock) -> None:
        """Modify adds content units and returns ModifyResult."""

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "modify" in url:
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            if "tasks" in url:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": [
                            "/api/v3/repositories/file/file/uuid/versions/1/"
                        ],
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/file/file/uuid/",
            ["/api/v3/content/file/files/abc/"],
        )

        assert result.content_units_added == 1
        assert result.state == "completed"
        assert result.repository_version is not None

    def test_get_repository_autopublish_enabled(self) -> None:
        """GET on the repository href returns the autopublish flag."""
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/repositories/file/file/uuid/",
                    "name": "osv-java-novel",
                    "autopublish": True,
                },
            )

        client = self._client_with(handler)
        assert client.get_repository_autopublish(
            "/api/v3/repositories/file/file/uuid/"
        )
        assert seen[0].method == "GET"
        assert seen[0].url.path.endswith("/api/v3/repositories/file/file/uuid/")

    def test_get_repository_autopublish_disabled(self) -> None:
        """Autopublish absent or false returns False."""
        client = self._client_with(
            lambda request: httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/repositories/file/file/uuid/",
                    "name": "osv-java-novel",
                },
            )
        )
        assert (
            client.get_repository_autopublish(
                "/api/v3/repositories/file/file/uuid/"
            )
            is False
        )

    def test_get_repository_autopublish_error(self) -> None:
        """Error response raises PulpError."""
        client = self._client_with(
            lambda request: httpx.Response(500, text="Internal Server Error")
        )
        with pytest.raises(PulpError, match="Repository lookup failed"):
            client.get_repository_autopublish(
                "/api/v3/repositories/file/file/uuid/"
            )

    @staticmethod
    def _client_with(handler: object) -> PulpFileClient:
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
            base_url="https://pulp.example.com",
        )
        return client

    _REPO = "/api/v3/repositories/file/file/vexuuid/"
    _VERSION = "/api/v3/repositories/file/file/vexuuid/versions/7/"

    def _vex_lookup_handler(
        self, results: list[dict[str, object]], latest: str | None = _VERSION
    ) -> tuple[Callable[[httpx.Request], httpx.Response], list[httpx.Request]]:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if request.url.path.endswith(self._REPO):
                return httpx.Response(200, json={"latest_version_href": latest})
            return httpx.Response(200, json={"results": results})

        return handler, seen

    def test_get_content_existing_path(self) -> None:
        """The file at the path in the latest version is reported."""
        name = "CVE-2024-1-2026-11-13T18:59:33Z.bom.json"
        handler, seen = self._vex_lookup_handler(
            [
                {
                    "relative_path": name,
                    "sha256": "ab" * 32,
                    "pulp_labels": {"source_image": "quay.io/x@sha256:1"},
                }
            ]
        )
        client = self._client_with(handler)

        assert client.get_content(self._REPO, name) == {
            "sha256": "ab" * 32,
            "pulp_labels": {"source_image": "quay.io/x@sha256:1"},
        }
        query = seen[1].url.params
        assert query["relative_path"] == name
        assert query["repository_version"] == self._VERSION

    def test_get_content_free_path(self) -> None:
        """No file at the path: None."""
        handler, _ = self._vex_lookup_handler([])
        client = self._client_with(handler)

        assert client.get_content(self._REPO, "x.bom.json") is None

    def test_get_content_empty_repository(self) -> None:
        """A repository without content versions has no files."""
        handler, seen = self._vex_lookup_handler([], latest=None)
        client = self._client_with(handler)

        assert client.get_content(self._REPO, "x.bom.json") is None
        assert len(seen) == 1

    def test_get_content_requires_domain(self) -> None:
        """The content API is domain-scoped."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        with pytest.raises(PulpError, match="Domain is required"):
            client.get_content(self._REPO, "x.bom.json")

    def test_upload_content_sends_labels(self, tmp_path: Path) -> None:
        """Labels are sent as the pulp_labels JSON field."""
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/content/file/files/abc/",
                    "relative_path": "v.bom.json",
                    "sha256": "00" * 32,
                },
            )

        path = tmp_path / "v.bom.json"
        path.write_text("{}")
        client = self._client_with(handler)
        client.upload_content(
            path, "v.bom.json", "00" * 32, labels={"source_image": "img@sha256:1"}
        )

        assert b'name="pulp_labels"' in seen[0].content
        assert b'{"source_image": "img@sha256:1"}' in seen[0].content

    def test_get_distribution_base_path_found(self) -> None:
        """Lookup by name returns the distribution base_path."""
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/d/1/",
                            "name": "osv-java-novel",
                            "base_path": "osv/java/predisclosure",
                        }
                    ]
                },
            )

        client = self._client_with(handler)
        assert (
            client.get_distribution_base_path("osv-java-novel")
            == "osv/java/predisclosure"
        )
        assert seen[0].url.path == (
            "/api/pulp/testdomain/api/v3/distributions/file/file/"
        )
        assert seen[0].url.params["name"] == "osv-java-novel"

    def test_get_distribution_base_path_missing(self) -> None:
        """No distribution with that name returns None."""
        client = self._client_with(
            lambda request: httpx.Response(200, json={"results": []})
        )
        assert client.get_distribution_base_path("nope") is None

    def test_get_distribution_base_path_malformed(self) -> None:
        """A result without base_path raises PulpError."""
        client = self._client_with(
            lambda request: httpx.Response(
                200, json={"results": [{"pulp_href": "/d/1/"}]}
            )
        )
        with pytest.raises(PulpError, match="Failed to parse distribution"):
            client.get_distribution_base_path("osv-java-novel")

    def test_get_distribution_repository_found(self) -> None:
        """Repository-backed distribution returns its repository href."""
        client = self._client_with(
            lambda request: httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/d/1/",
                            "name": "osv-java-novel",
                            "repository": "/api/v3/repositories/file/file/uuid/",
                        }
                    ]
                },
            )
        )
        assert (
            client.get_distribution_repository("osv-java-novel")
            == "/api/v3/repositories/file/file/uuid/"
        )

    def test_get_distribution_repository_pinned(self) -> None:
        """Publication-pinned distribution (no repository) returns None."""
        client = self._client_with(
            lambda request: httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/d/1/",
                            "name": "osv-java-novel",
                            "repository": None,
                            "publication": "/api/v3/publications/file/file/p/",
                        }
                    ]
                },
            )
        )
        assert client.get_distribution_repository("osv-java-novel") is None

    def test_get_distribution_repository_not_found(self) -> None:
        """No distribution with that name raises PulpError."""
        client = self._client_with(
            lambda request: httpx.Response(200, json={"results": []})
        )
        with pytest.raises(PulpError, match="not found"):
            client.get_distribution_repository("nonexistent")

    def test_get_distribution_repository_url(self) -> None:
        """Verify the distribution API path is used."""
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "pulp_href": "/d/1/",
                            "name": "my-file-repo",
                            "repository": "/api/v3/repositories/file/file/uuid/",
                        }
                    ]
                },
            )

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="mydom",
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")
        client._client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://pulp.example.com",
        )

        client.get_distribution_repository("my-file-repo")

        assert seen[0].url.path == (
            "/api/pulp/mydom/api/v3/distributions/file/file/"
        )
        assert seen[0].url.params["name"] == "my-file-repo"

    def test_get_distribution_repository_requires_domain(self) -> None:
        """Missing domain raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpFileClient(config, "test-dist")

        with pytest.raises(PulpError, match="Domain is required"):
            client.get_distribution_repository("my-file-repo")

    # _request() verbose logging is base.py behavior; see
    # tests/pulp/clients/base_test.py::TestRequestLogging.
