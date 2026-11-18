"""Tests for the shared Pulp client base (slan_cuan/pulp/clients/base.py)."""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from slan_cuan.pulp.clients.base import _validate_auth
from slan_cuan.pulp.clients.maven import PulpMavenClient
from slan_cuan.pulp.constants import AUTH_TYPE_CERT, AUTH_TYPE_TBR
from slan_cuan.pulp.exceptions import PulpError
from slan_cuan.pulp.models import PulpConfig


class TestClientConstruction:
    """Tests for PulpClientBase.__init__ (SSL, auth, base_url handling)."""

    def test_close(self) -> None:
        """Verify close() doesn't raise."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        # Should not raise
        client.close()

    @patch("slan_cuan.pulp.clients.base.ssl.create_default_context")
    def test_ca_cert_creates_ssl_context(
        self, mock_create_ctx: Mock, tmp_path: Path
    ) -> None:
        """When ca_cert is set, an SSLContext is built from it."""
        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("PEM data")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            ca_cert=ca_file,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        mock_create_ctx.assert_called_once_with(
            cafile=str(ca_file),
        )
        client.close()

    def test_ca_cert_invalid_pem_raises_pulp_error(self, tmp_path: Path) -> None:
        """Malformed CA cert raises PulpError, not ssl.SSLError."""
        ca_file = tmp_path / "bad-ca.crt"
        ca_file.write_text("not a real certificate")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            ca_cert=ca_file,
            username="testuser",
            password="testpass",
        )

        with pytest.raises(PulpError) as exc_info:
            PulpMavenClient(config, "test-dist")

        assert "Failed to load CA certificate" in exc_info.value.message

    def test_ca_cert_ignored_when_insecure(self) -> None:
        """When verify_ssl=False, ca_cert is ignored."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            ca_cert=Path("/some/ca.crt"),
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert config.verify_ssl is False
        client.close()

    def test_verify_ssl_propagates(self, tmp_path: Path) -> None:
        """Create client with verify_ssl=False, verify propagation."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        content_response = {
            "pulp_href": "/api/v3/content/maven/artifact/abc/",
            "relative_path": "org/example/test.jar",
            "group_id": "org.example",
            "artifact_id": "test",
            "version": "1.0.0",
            "filename": "test.jar",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=content_response)

        transport = httpx.MockTransport(handler)

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        assert config.verify_ssl is False

        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            verify=False,
        )

        result = client.upload_content(artifact_file, "org/example/test.jar")
        assert result.pulp_href == "/api/v3/content/maven/artifact/abc/"

    def test_base_url_without_scheme_gets_https(self) -> None:
        """A base_url without a scheme gets https:// prepended."""
        config = PulpConfig(
            base_url="packages.redhat.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "https://packages.redhat.com"
        client.close()

    def test_base_url_with_https_unchanged(self) -> None:
        """A base_url with https:// is not modified."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "https://pulp.example.com"
        client.close()

    def test_base_url_with_http_unchanged(self) -> None:
        """A base_url with http:// is not modified."""
        config = PulpConfig(
            base_url="http://pulp.example.com",
            verify_ssl=False,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        assert str(client._client._base_url) == "http://pulp.example.com"
        client.close()

    def test_pulp_config_invalid_task_timeout(self) -> None:
        """PulpConfig validates task_timeout > 0."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            task_timeout=0,
        )
        with pytest.raises(PulpError, match="task_timeout must be positive"):
            PulpMavenClient(config, "test-dist")


class TestValidateAuth:
    """Tests for _validate_auth authentication validation."""

    def test_validate_auth_tbr_missing_username(self) -> None:
        """TBR auth without username raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            password="testpass",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "TBR auth requires" in exc_info.value.message
        assert "--pulp-username" in exc_info.value.message
        assert "--pulp-password" in exc_info.value.message

    def test_validate_auth_tbr_missing_password(self) -> None:
        """TBR auth without password raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            username="testuser",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "TBR auth requires" in exc_info.value.message
        assert "--pulp-username" in exc_info.value.message
        assert "--pulp-password" in exc_info.value.message

    def test_validate_auth_cert_missing_cert(self, tmp_path: Path) -> None:
        """Certificate auth without client_cert raises PulpError."""
        key_file = tmp_path / "client.key"
        key_file.write_text("key content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_key=key_file,
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Certificate auth requires" in exc_info.value.message
        assert "--pulp-client-cert" in exc_info.value.message
        assert "--pulp-client-key" in exc_info.value.message

    def test_validate_auth_cert_missing_key(self, tmp_path: Path) -> None:
        """Certificate auth without client_key raises PulpError."""
        cert_file = tmp_path / "client.crt"
        cert_file.write_text("cert content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_cert=cert_file,
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Certificate auth requires" in exc_info.value.message
        assert "--pulp-client-cert" in exc_info.value.message
        assert "--pulp-client-key" in exc_info.value.message

    def test_validate_auth_invalid_type(self) -> None:
        """Invalid auth_type raises PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type="invalid",
        )

        with pytest.raises(PulpError) as exc_info:
            _validate_auth(config)

        assert "Invalid auth type 'invalid'" in exc_info.value.message
        assert "cert" in exc_info.value.message
        assert "tbr" in exc_info.value.message

    def test_tbr_auth_sends_basic_header(self, tmp_path: Path) -> None:
        """TBR auth configures httpx.Client with basic auth."""
        artifact_file = tmp_path / "test.jar"
        artifact_file.write_text("jar content")

        captured_auth_header = None

        content_response = {
            "pulp_href": "/api/v3/content/maven/artifact/abc/",
            "relative_path": "org/example/test.jar",
            "group_id": "org.example",
            "artifact_id": "test",
            "version": "1.0.0",
            "filename": "test.jar",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_auth_header
            captured_auth_header = request.headers.get("Authorization")
            return httpx.Response(200, json=content_response)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_TBR,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport,
            base_url="https://pulp.example.com",
            auth=("testuser", "testpass"),
        )

        client.upload_content(artifact_file, "org/example/test.jar")

        assert captured_auth_header is not None
        assert captured_auth_header.startswith("Basic ")

    def test_cert_auth_loads_ssl_context(self, tmp_path: Path) -> None:
        """Cert auth loads cert chain with correct paths."""
        cert_file = tmp_path / "client.crt"
        cert_file.write_text("cert content")
        key_file = tmp_path / "client.key"
        key_file.write_text("key content")

        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            auth_type=AUTH_TYPE_CERT,
            client_cert=cert_file,
            client_key=key_file,
        )

        with patch(
            "slan_cuan.pulp.clients.base.ssl.SSLContext.load_cert_chain"
        ) as mock_load:
            try:
                PulpMavenClient(config, "test-dist")
            except (ssl.SSLError, OSError):
                pass

            mock_load.assert_called_once_with(
                certfile=str(cert_file),
                keyfile=str(key_file),
            )


class TestModifyRepository:
    """Tests for modify_repository() method."""

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_success(self, mock_sleep: Mock) -> None:
        """Mock 202 with task href, then completed task, verify ModifyResult."""

        def handler(request: httpx.Request) -> httpx.Response:
            # First call is the modify POST
            if "modify/" in str(request.url):
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            # Second call is the task poll
            return httpx.Response(
                200,
                json={
                    "state": "completed",
                    "created_resources": [
                        "/api/v3/repositories/maven/maven/uuid/versions/2/",
                    ],
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            [
                "/api/v3/content/maven/artifact/abc/",
                "/api/v3/content/maven/artifact/def/",
            ],
        )

        assert result.task_href == "/api/v3/tasks/task-uuid/"
        assert result.state == "completed"
        repo_ver = "/api/v3/repositories/maven/maven/uuid/versions/2/"
        assert result.repository_version == repo_ver
        assert result.content_units_added == 2

    def test_modify_repository_error_status(self) -> None:
        """Mock 500, verify PulpError."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.modify_repository(
                "/api/v3/repositories/maven/maven/uuid/",
                ["/api/v3/content/maven/artifact/abc/"],
            )

        assert exc_info.value.status_code == 500
        assert "Repository modify failed" in exc_info.value.message

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_request_payload(self, mock_sleep: Mock) -> None:
        """Capture JSON body, verify add_content_units payload."""
        captured_payload = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload

            # Capture modify request
            if "modify/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/task-uuid/"},
                )
            # Task poll
            return httpx.Response(
                200,
                json={"state": "completed", "created_resources": []},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            [
                "/api/v3/content/maven/artifact/abc/",
                "/api/v3/content/maven/artifact/def/",
            ],
        )

        assert captured_payload is not None
        assert "add_content_units" in captured_payload
        assert len(captured_payload["add_content_units"]) == 2
        units = captured_payload["add_content_units"]
        assert "/api/v3/content/maven/artifact/abc/" in units

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_sends_custom_headers(
        self, mock_sleep: Mock
    ) -> None:
        """modify_repository attaches custom_headers to the POST request."""
        captured_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_headers
            if request.method == "POST" and "modify" in request.url.path:
                captured_headers = dict(request.headers)
                return httpx.Response(
                    200, json={"task": "/api/v3/tasks/modify-uuid/"}
                )
            if request.method == "GET" and "modify-uuid" in request.url.path:
                return httpx.Response(
                    200,
                    json={
                        "state": "completed",
                        "created_resources": ["/api/v3/versions/1/"],
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            custom_headers={"X-TASK-DIAGNOSTICS": "pyinstrument"},
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            ["/api/v3/content/maven/artifact/1/"],
        )

        assert result.repository_version == "/api/v3/versions/1/"
        assert captured_headers.get("x-task-diagnostics") == "pyinstrument"

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_remove_only_payload(
        self, mock_sleep: Mock
    ) -> None:
        """remove_content_unit_hrefs alone sends only remove_content_units."""
        captured_payload: dict[str, object] | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload
            if "modify/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202, json={"task": "/api/v3/tasks/task-uuid/"}
                )
            return httpx.Response(
                200, json={"state": "completed", "created_resources": []}
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            [],
            remove_content_unit_hrefs=["/api/v3/content/maven/artifact/abc/"],
        )

        assert captured_payload == {
            "remove_content_units": ["/api/v3/content/maven/artifact/abc/"]
        }

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_modify_repository_add_and_remove_combined_payload(
        self, mock_sleep: Mock
    ) -> None:
        """Both add and remove hrefs can be sent in a single modify call."""
        captured_payload: dict[str, object] | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload
            if "modify/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202, json={"task": "/api/v3/tasks/task-uuid/"}
                )
            return httpx.Response(
                200, json={"state": "completed", "created_resources": []}
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.modify_repository(
            "/api/v3/repositories/maven/maven/uuid/",
            ["/api/v3/content/maven/artifact/new/"],
            remove_content_unit_hrefs=["/api/v3/content/maven/artifact/old/"],
        )

        assert captured_payload == {
            "add_content_units": ["/api/v3/content/maven/artifact/new/"],
            "remove_content_units": ["/api/v3/content/maven/artifact/old/"],
        }


class TestResolveRepository:
    """Tests for resolve_repository() method."""

    def test_resolve_repository_success(self) -> None:
        """Mock 200 with results list, verify returned pulp_href."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "count": 1,
                    "results": [
                        {
                            "pulp_href": (
                                "/api/v3/repositories/maven/maven/uuid123/"
                            ),
                            "name": "lightwell-test",
                        }
                    ],
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        href = client.resolve_repository("lightwell-test")

        assert href == "/api/v3/repositories/maven/maven/uuid123/"

    def test_resolve_repository_not_found(self) -> None:
        """Mock 200 with empty results, verify PulpError(404)."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"count": 0, "results": []},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="lightwell",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.resolve_repository("nonexistent-repo")

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.message
        assert "nonexistent-repo" in exc_info.value.message

    def test_resolve_repository_requires_domain(self) -> None:
        """Config with domain=None, verify PulpError."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain=None,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")

        with pytest.raises(PulpError) as exc_info:
            client.resolve_repository("test-repo")

        assert "Domain is required" in exc_info.value.message
        assert exc_info.value.status_code == 0

    def test_resolve_repository_url_construction(self) -> None:
        """Capture URL, verify domain template and name param."""
        captured_url = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_url
            captured_url = str(request.url)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": "/api/v3/repositories/maven/maven/uuid/"}
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
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.resolve_repository("my-repo")

        assert captured_url is not None
        assert "/api/pulp/mydom/api/v3/repositories/maven/maven/" in captured_url
        assert "name=my-repo" in captured_url


class TestCancelTask:
    """Tests for cancel_task() method."""

    def test_cancel_task_short_timeout(self) -> None:
        """cancel_task uses short dedicated timeout."""
        captured_timeout = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_timeout
            captured_timeout = request.extensions.get("timeout", {}).get("read")
            return httpx.Response(200, json={"state": "canceled"})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        outcome = client.cancel_task("/api/v3/tasks/task-uuid/")
        assert outcome == "cancellation requested in Pulp"
        assert captured_timeout == 15.0


class TestFindBlockingTask:
    """Tests for _find_blocking_task() method."""

    def test_find_blocking_task_parent(self) -> None:
        """_find_blocking_task identifies parent_task when present."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        task_data = {
            "pulp_href": "/api/v3/tasks/child-task/",
            "parent_task": "/api/v3/tasks/parent-task/",
            "state": "waiting",
        }
        result = client._find_blocking_task(task_data)
        assert result.href == "/api/v3/tasks/parent-task/"
        assert result.status.value == "found"

    def test_find_blocking_task_unknown_on_lookup_failure(self) -> None:
        """Lookup failures are distinct from a confirmed absent blocker."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        task_data = {
            "pulp_href": "/api/v3/tasks/my-task/",
            "reserved_resources_record": ["/api/v3/repositories/maven/1/"],
            "state": "waiting",
        }
        client._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(503, text="unavailable")
            ),
            base_url="https://pulp.example.com",
        )

        result = client._find_blocking_task(task_data)
        assert result.href is None
        assert result.status.value == "unknown"

    def test_find_blocking_task_running_resource_holder(self) -> None:
        """_find_blocking_task finds running task reserving the same resource."""

        def handler(request: httpx.Request) -> httpx.Response:
            if "tasks" in request.url.path:
                assert "state=running" in str(request.url)
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"pulp_href": "/api/v3/tasks/running-blocker/"}
                        ]
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
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        task_data = {
            "pulp_href": "/api/v3/tasks/my-task/",
            "reserved_resources_record": ["/api/v3/repositories/maven/1/"],
            "state": "waiting",
        }
        result = client._find_blocking_task(task_data)
        assert result.href == "/api/v3/tasks/running-blocker/"
        assert result.status.value == "found"

    def test_find_blocking_task_not_found_without_resources(self) -> None:
        """A task without blocker resources confirms no blocker."""
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"results": []})
            ),
            base_url="https://pulp.example.com",
        )

        result = client._find_blocking_task(
            {
                "pulp_href": "/api/v3/tasks/my-task/",
                "reserved_resources_record": ["/api/v3/repositories/maven/1/"],
                "state": "waiting",
            }
        )
        assert result.href is None
        assert result.status.value == "not_found"


class TestRequestLogging:
    """Tests for _request() verbose logging."""

    def test_request_logging_when_verbose(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When verbose is enabled, Pulp requests and responses are logged."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": "/api/v3/repositories/file/file/uuid/"}
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
            verbose=True,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        repo_href = client.resolve_repository("test-dist")
        assert repo_href == "/api/v3/repositories/file/file/uuid/"

        captured = capsys.readouterr()
        assert "Pulp request: GET" in captured.out
        assert "Pulp response: 200" in captured.out

    def test_request_logging_when_not_verbose(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When verbose is disabled, requests and responses are not logged."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"pulp_href": "/api/v3/repositories/file/file/uuid/"}
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
            verbose=False,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        repo_href = client.resolve_repository("test-dist")
        assert repo_href == "/api/v3/repositories/file/file/uuid/"

        captured = capsys.readouterr()
        assert "Pulp request:" not in captured.out
        assert "Pulp response:" not in captured.out

    def test_verbose_logging_includes_state_and_waiting_on(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Verbose response logging outputs state and waiting_on metadata."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "pulp_href": "/api/v3/tasks/waiting-task/",
                    "parent_task": "/api/v3/tasks/parent-blocker/",
                    "state": "waiting",
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
            verbose=True,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client._request("GET", "/api/v3/tasks/waiting-task/", "Task status")
        captured = capsys.readouterr()
        assert "Pulp response: 200" in captured.out
        assert "state=waiting" in captured.out
        assert "waiting_on=/api/v3/tasks/parent-blocker/" in captured.out

    def test_request_logging_sanitizes_sensitive_headers(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Verbose request logging sanitizes sensitive header values."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            verbose=True,
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client._request(
            "GET",
            "/api/v3/status/",
            "Status",
            headers={"Authorization": "Bearer secret123", "X-Custom": "public"},
        )

        captured = capsys.readouterr()
        assert "Authorization': '***'" in captured.out
        assert "secret123" not in captured.out
        assert "X-Custom': 'public'" in captured.out


class TestLabels:
    """Tests for get_labels() and set_label() methods."""

    def test_get_labels_returns_pulp_labels_dict(self) -> None:
        """get_labels extracts pulp_labels dict from response."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"pulp_labels": {"a": "1"}},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.get_labels("/api/v3/repositories/maven/maven/uuid/")
        assert result == {"a": "1"}

    def test_get_labels_missing_pulp_labels_returns_empty_dict(self) -> None:
        """get_labels returns empty dict when pulp_labels key missing."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"other_field": "value"})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.get_labels("/api/v3/repositories/maven/maven/uuid/")
        assert result == {}

    def test_get_labels_sends_custom_headers(self) -> None:
        """get_labels attaches custom_headers to the GET request."""
        captured_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_headers
            captured_headers = dict(request.headers)
            return httpx.Response(200, json={"pulp_labels": {"a": "1"}})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            custom_headers={"X-TASK-DIAGNOSTICS": "pyinstrument"},
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.get_labels("/api/v3/repositories/maven/maven/uuid/")

        assert result == {"a": "1"}
        assert captured_headers.get("x-task-diagnostics") == "pyinstrument"

    def test_set_label_without_cas_posts_unconditionally(self) -> None:
        """set_label without CAS posts immediately without prior GET."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append((request.method, str(request.url)))
            if "set_label/" in str(request.url):
                return httpx.Response(200, json={})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.set_label(
            "/api/v3/repositories/maven/maven/uuid/",
            "k",
            "v",
        )

        # Should only have POST to set_label, no prior GET
        assert len(captured_requests) == 1
        assert captured_requests[0][0] == "POST"
        assert "set_label/" in captured_requests[0][1]

    def test_set_label_posts_with_correct_json_payload(self) -> None:
        """set_label sends correct JSON payload with key and value."""
        captured_payload = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload
            if "set_label/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(200, json={})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.set_label(
            "/api/v3/repositories/maven/maven/uuid/",
            "mykey",
            "myvalue",
        )

        assert captured_payload is not None
        assert captured_payload == {"key": "mykey", "value": "myvalue"}

    def test_set_label_with_cas_matching_current_proceeds(self) -> None:
        """set_label with matching CAS digest still posts (idempotent write)."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request.method)
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={"pulp_labels": {"cas_key": "digest123"}},
                )
            if "set_label/" in str(request.url):
                return httpx.Response(200, json={})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.set_label(
            "/api/v3/repositories/maven/maven/uuid/",
            "k",
            "v",
            cas_digest="digest123",
            cas_label_key="cas_key",
        )

        # Should have GET then POST
        assert captured_requests == ["GET", "POST"]

    def test_set_label_with_cas_mismatch_raises_pulp_error(self) -> None:
        """set_label raises PulpError when CAS mismatch, no POST made."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request.method)
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={"pulp_labels": {"cas_key": "different_value"}},
                )
            if "set_label/" in str(request.url):
                # If we get here, the test should fail
                msg = "POST should not have been called on CAS mismatch"
                raise AssertionError(msg)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError) as exc_info:
            client.set_label(
                "/api/v3/repositories/maven/maven/uuid/",
                "k",
                "v",
                cas_digest="digest123",
                cas_label_key="cas_key",
            )

        # Only GET should have been called
        assert captured_requests == ["GET"]
        assert "cas_key" in exc_info.value.message
        msg = exc_info.value.message
        assert "different_value" in msg or "digest123" in msg

    def test_set_label_with_cas_empty_current_proceeds(self) -> None:
        """set_label with empty current CAS value proceeds (first claim)."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request.method)
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={"pulp_labels": {}},  # cas_key not present
                )
            if "set_label/" in str(request.url):
                return httpx.Response(200, json={})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.set_label(
            "/api/v3/repositories/maven/maven/uuid/",
            "k",
            "v",
            cas_digest="digest123",
            cas_label_key="cas_key",
        )

        # Should have GET then POST
        assert captured_requests == ["GET", "POST"]

    def test_set_label_sends_custom_headers(self) -> None:
        """set_label attaches custom_headers to the POST request."""
        captured_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_headers
            if "set_label/" in str(request.url):
                captured_headers = dict(request.headers)
                return httpx.Response(200, json={})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            custom_headers={"X-TASK-DIAGNOSTICS": "pyinstrument"},
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.set_label(
            "/api/v3/repositories/maven/maven/uuid/",
            "k",
            "v",
        )

        assert captured_headers.get("x-task-diagnostics") == "pyinstrument"


class TestListContent:
    """Tests for list_content() paginated list method."""

    def test_list_content_single_page(self) -> None:
        """list_content returns results when fewer than page_size items."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"name": "item1", "id": 1},
                        {"name": "item2", "id": 2},
                    ]
                },
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.list_content("/api/v3/content/npm/packages/")

        assert result == [
            {"name": "item1", "id": 1},
            {"name": "item2", "id": 2},
        ]
        assert len(captured_requests) == 1
        assert "limit=100" in str(captured_requests[0].url)
        assert "offset=0" in str(captured_requests[0].url)

    def test_list_content_paginates_on_full_page(self) -> None:
        """list_content paginates when first page has exactly page_size."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            url_str = str(request.url)
            # First request: offset=0, return page_size items
            if "offset=0" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"name": f"item{i}", "id": i} for i in range(1, 101)
                        ]
                    },
                )
            # Second request: offset=100, return fewer items (3)
            elif "offset=100" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {"name": "item101", "id": 101},
                            {"name": "item102", "id": 102},
                            {"name": "item103", "id": 103},
                        ]
                    },
                )
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.list_content("/api/v3/content/npm/packages/")

        assert len(result) == 103
        assert result[0] == {"name": "item1", "id": 1}
        assert result[99] == {"name": "item100", "id": 100}
        assert result[100] == {"name": "item101", "id": 101}
        assert result[102] == {"name": "item103", "id": 103}
        assert len(captured_requests) == 2
        assert "offset=100" in str(captured_requests[1].url)

    def test_list_content_passes_filters_as_query_params(self) -> None:
        """list_content includes filters in query params."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(
                200,
                json={"results": [{"name": "filtered_item"}]},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.list_content(
            "/api/v3/content/npm/packages/",
            name="my-package",
            version="1.0.0",
        )

        assert result == [{"name": "filtered_item"}]
        assert len(captured_requests) == 1
        url_str = str(captured_requests[0].url)
        assert "name=my-package" in url_str
        assert "version=1.0.0" in url_str
        assert "limit=100" in url_str
        assert "offset=0" in url_str

    def test_list_content_empty_results(self) -> None:
        """list_content returns empty list when no results."""
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.list_content("/api/v3/content/npm/packages/")

        assert result == []
        assert len(captured_requests) == 1

    def test_list_content_sends_custom_headers(self) -> None:
        """list_content attaches custom_headers to the GET request."""
        captured_headers: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_headers
            captured_headers = dict(request.headers)
            return httpx.Response(200, json={"results": []})

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            username="testuser",
            password="testpass",
            custom_headers={"X-TASK-DIAGNOSTICS": "pyinstrument"},
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        result = client.list_content("/api/v3/content/npm/packages/")

        assert result == []
        assert captured_headers.get("x-task-diagnostics") == "pyinstrument"


class TestOrphanCleanup:
    """Tests for orphan_cleanup() method."""

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_orphan_cleanup_posts_content_hrefs_and_polls_task(
        self, mock_sleep: Mock
    ) -> None:
        """Mock POST cleanup and task poll; verify payload and poll."""
        captured_payload = None
        captured_requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            # First call is the cleanup POST
            if "orphans/cleanup/" in str(request.url):
                nonlocal captured_payload
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/cleanup-uuid/"},
                )
            # Second call is the task poll
            return httpx.Response(
                200,
                json={"state": "completed"},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        content_hrefs = [
            "/api/v3/content/maven/artifact/abc/",
            "/api/v3/content/maven/artifact/def/",
        ]
        client.orphan_cleanup(content_hrefs)

        # Verify POST payload
        assert captured_payload is not None
        assert captured_payload["content_hrefs"] == content_hrefs
        assert captured_payload["orphan_protection_time"] == 0

        # Verify task polling happened
        assert len(captured_requests) >= 2
        assert "orphans/cleanup/" in str(captured_requests[0].url)
        assert captured_requests[0].method == "POST"
        assert "cleanup-uuid" in str(captured_requests[1].url)
        assert captured_requests[1].method == "GET"

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_orphan_cleanup_uses_default_protection_time(
        self, mock_sleep: Mock
    ) -> None:
        """POST body includes orphan_protection_time=0 by default."""
        captured_payload = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload

            # Capture cleanup request
            if "orphans/cleanup/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/cleanup-uuid/"},
                )
            # Task poll
            return httpx.Response(
                200,
                json={"state": "completed"},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.orphan_cleanup(["/api/v3/content/maven/artifact/abc/"])

        assert captured_payload is not None
        assert "content_hrefs" in captured_payload
        assert "orphan_protection_time" in captured_payload
        assert captured_payload["orphan_protection_time"] == 0

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_orphan_cleanup_accepts_custom_protection_time(
        self, mock_sleep: Mock
    ) -> None:
        """orphan_cleanup accepts protection_time parameter."""
        captured_payload = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload

            # Capture cleanup request
            if "orphans/cleanup/" in str(request.url):
                captured_payload = json.loads(request.content)
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/cleanup-uuid/"},
                )
            # Task poll
            return httpx.Response(
                200,
                json={"state": "completed"},
            )

        transport = httpx.MockTransport(handler)
        config = PulpConfig(
            base_url="https://pulp.example.com",
            verify_ssl=True,
            domain="testdomain",
            username="testuser",
            password="testpass",
        )
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        client.orphan_cleanup(
            ["/api/v3/content/maven/artifact/abc/"],
            protection_time=3600,
        )

        assert captured_payload is not None
        assert captured_payload["orphan_protection_time"] == 3600

    @patch("slan_cuan.pulp.tasks.time.sleep")
    def test_orphan_cleanup_raises_on_task_failure(
        self, mock_sleep: Mock
    ) -> None:
        """Task polls to failed state; assert PulpError propagates."""

        def handler(request: httpx.Request) -> httpx.Response:
            # First call is the cleanup POST
            if "orphans/cleanup/" in str(request.url):
                return httpx.Response(
                    202,
                    json={"task": "/api/v3/tasks/cleanup-uuid/"},
                )
            # Second call is the task poll - return failed state
            return httpx.Response(
                200,
                json={
                    "state": "failed",
                    "error": {"description": "Cleanup failed"},
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
        client = PulpMavenClient(config, "test-dist")
        client._client = httpx.Client(
            transport=transport, base_url="https://pulp.example.com"
        )

        with pytest.raises(PulpError):
            client.orphan_cleanup(["/api/v3/content/maven/artifact/abc/"])
