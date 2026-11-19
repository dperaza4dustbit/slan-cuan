"""Tests for shared HTTP helpers (slan_cuan/http.py)."""

from __future__ import annotations

import ssl
from pathlib import Path

import httpx
import pytest

from slan_cuan.http import (
    MAX_BACKOFF_SECONDS,
    HttpApiError,
    compute_backoff,
    create_ssl_context,
    parse_custom_headers,
    parse_json_dict,
    raise_for_status,
    request,
)


class _TestError(HttpApiError):
    """Concrete subclass for testing error_cls dispatch."""


class TestHttpApiError:
    """Tests for HttpApiError base exception."""

    def test_attributes_preserved(self) -> None:
        """Verify message, status_code, response_body are stored."""
        error = HttpApiError(
            message="something broke",
            status_code=502,
            response_body="Bad Gateway",
        )
        assert error.message == "something broke"
        assert error.status_code == 502
        assert error.response_body == "Bad Gateway"
        assert str(error) == "something broke"

    def test_subclass_is_catchable_as_base(self) -> None:
        """A subclass instance is caught by except HttpApiError."""
        with pytest.raises(HttpApiError):
            raise _TestError("fail", status_code=500, response_body="")


class TestCreateSslContext:
    """Tests for create_ssl_context()."""

    def test_returns_bool_when_no_ca_cert(self) -> None:
        """No ca_cert returns verify_ssl unchanged."""
        result = create_ssl_context(None, True, _TestError)
        assert result is True

    def test_returns_false_when_insecure(self) -> None:
        """verify_ssl=False returns False even with ca_cert."""
        result = create_ssl_context(Path("/fake.crt"), False, _TestError)
        assert result is False

    def test_returns_ssl_context_with_valid_ca(self, tmp_path: Path) -> None:
        """Valid CA cert produces an SSLContext."""
        from unittest.mock import patch

        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("PEM data")

        with patch("slan_cuan.http.ssl.create_default_context") as mock_ctx:
            result = create_ssl_context(ca_file, True, _TestError)

        mock_ctx.assert_called_once_with(cafile=str(ca_file))
        assert (
            isinstance(result, ssl.SSLContext) or result is mock_ctx.return_value
        )

    def test_invalid_ca_raises_error_cls(self, tmp_path: Path) -> None:
        """Malformed CA cert raises the provided error_cls."""
        ca_file = tmp_path / "bad.crt"
        ca_file.write_text("not a certificate")

        with pytest.raises(_TestError) as exc_info:
            create_ssl_context(ca_file, True, _TestError)

        assert "Failed to load CA certificate" in exc_info.value.message
        assert exc_info.value.status_code == 0


class TestRaiseForStatus:
    """Tests for raise_for_status()."""

    def test_no_raise_on_success(self) -> None:
        """Status 200 does not raise."""
        response = httpx.Response(200, text="OK")
        raise_for_status(response, "Test op", _TestError)

    def test_no_raise_on_redirect(self) -> None:
        """Status 301 does not raise."""
        response = httpx.Response(301, text="Moved")
        raise_for_status(response, "Test op", _TestError)

    def test_raises_on_400(self) -> None:
        """Status 400 raises with operation in message."""
        response = httpx.Response(400, text="Bad Request")
        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Upload", _TestError)

        assert "Upload failed (400)" in exc_info.value.message
        assert exc_info.value.status_code == 400
        assert exc_info.value.response_body == "Bad Request"

    def test_raises_on_500(self) -> None:
        """Status 500 raises with status in message."""
        response = httpx.Response(500, text="Internal Server Error")
        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Fetch", _TestError)

        assert exc_info.value.status_code == 500

    def test_truncates_long_body(self) -> None:
        """Body longer than ERROR_BODY_MAX_LENGTH is truncated."""
        long_body = "x" * 300
        response = httpx.Response(500, text=long_body)

        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Op", _TestError)

        assert "... (truncated)" in exc_info.value.message
        assert exc_info.value.response_body == long_body

    def test_short_body_not_truncated(self) -> None:
        """Body shorter than limit is not truncated."""
        short_body = "short error"
        response = httpx.Response(500, text=short_body)

        with pytest.raises(_TestError) as exc_info:
            raise_for_status(response, "Op", _TestError)

        assert "... (truncated)" not in exc_info.value.message
        assert short_body in exc_info.value.message


class TestParseJsonDict:
    """Tests for parse_json_dict()."""

    def test_returns_dict_on_valid_json(self) -> None:
        """Valid JSON object returns dict."""
        response = httpx.Response(200, json={"key": "value"})
        result = parse_json_dict(response, "Test", _TestError)
        assert result == {"key": "value"}

    def test_raises_on_non_dict(self) -> None:
        """JSON array raises error."""
        response = httpx.Response(200, json=[1, 2, 3])
        with pytest.raises(_TestError) as exc_info:
            parse_json_dict(response, "Test", _TestError)

        assert "non-dict response" in exc_info.value.message

    def test_raises_on_invalid_json(self) -> None:
        """Non-JSON body raises error."""
        response = httpx.Response(
            200,
            text="not json",
            headers={"content-type": "application/json"},
        )
        with pytest.raises(_TestError) as exc_info:
            parse_json_dict(response, "Parse", _TestError)

        assert "Failed to parse" in exc_info.value.message


class TestRequest:
    """Tests for request()."""

    def test_success_returns_response(self) -> None:
        """Successful GET returns the response."""
        transport = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"ok": True})
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        response = request(client, "GET", "/test", "Fetch", _TestError)
        assert response.status_code == 200
        client.close()

    def test_raises_on_connect_error(self) -> None:
        """ConnectError is wrapped in error_cls."""
        transport = httpx.MockTransport(
            lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        with pytest.raises(_TestError) as exc_info:
            request(client, "GET", "/test", "Fetch", _TestError)

        assert "Connection failed" in exc_info.value.message
        assert exc_info.value.status_code == 0
        client.close()

    def test_raises_on_timeout(self) -> None:
        """TimeoutException is wrapped in error_cls."""
        transport = httpx.MockTransport(
            lambda req: (_ for _ in ()).throw(httpx.TimeoutException("timed out"))
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        with pytest.raises(_TestError) as exc_info:
            request(client, "GET", "/test", "Fetch", _TestError)

        assert "Request timed out" in exc_info.value.message
        assert exc_info.value.status_code == 0
        client.close()

    def test_raises_on_http_error(self) -> None:
        """HTTP 500 is caught by raise_for_status inside request()."""
        transport = httpx.MockTransport(
            lambda req: httpx.Response(500, text="Server Error")
        )
        client = httpx.Client(transport=transport, base_url="https://example.com")
        with pytest.raises(_TestError) as exc_info:
            request(client, "GET", "/test", "Fetch", _TestError)

        assert exc_info.value.status_code == 500
        client.close()

    def test_passes_kwargs_through(self) -> None:
        """Keyword args (json, params, etc.) reach the transport."""
        captured_body = None

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal captured_body
            captured_body = req.content
            return httpx.Response(200, text="ok")

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport, base_url="https://example.com")
        request(
            client,
            "POST",
            "/test",
            "Send",
            _TestError,
            json={"key": "value"},
        )
        assert captured_body is not None
        assert b"key" in captured_body
        client.close()


class TestParseCustomHeaders:
    """Tests for parse_custom_headers()."""

    def test_parse_custom_headers_empty(self) -> None:
        """Empty, None, or whitespace returns empty dict."""
        assert parse_custom_headers(None) == {}
        assert parse_custom_headers("") == {}
        assert parse_custom_headers("   ") == {}

    def test_parse_custom_headers_crlf_and_newlines(self) -> None:
        """CRLF and newline delimiters preserve spaces and commas in values."""
        raw = (
            "# Comment line\r\n"
            "X-TASK-DIAGNOSTICS: pyinstrument,memory\r\n"
            "Authorization: Bearer my secret token; version=1\n"
            "Correlation-ID=test-123\n"
        )
        assert parse_custom_headers(raw) == {
            "X-TASK-DIAGNOSTICS": "pyinstrument,memory",
            "Authorization": "Bearer my secret token; version=1",
            "Correlation-ID": "test-123",
        }

    def test_parse_custom_headers_escaped_newlines(self) -> None:
        r"""Literal escaped \n and \r\n in strings are supported."""
        raw = "X-Foo: bar\\r\\nX-Baz: qux,123; test\\nCorrelation-ID=cid"
        assert parse_custom_headers(raw) == {
            "X-Foo": "bar",
            "X-Baz": "qux,123; test",
            "Correlation-ID": "cid",
        }

    def test_parse_custom_headers_colon_style(self) -> None:
        """Single-line HTTP-style Key: Value is supported."""
        raw = "X-TASK-DIAGNOSTICS: pyinstrument,memory"
        assert parse_custom_headers(raw) == {
            "X-TASK-DIAGNOSTICS": "pyinstrument,memory",
        }

    def test_parse_custom_headers_json(self) -> None:
        """Valid JSON objects are parsed into dict."""
        raw = '{"X-TASK-DIAGNOSTICS": "memray", "Correlation-ID": "cid-789"}'
        assert parse_custom_headers(raw) == {
            "X-TASK-DIAGNOSTICS": "memray",
            "Correlation-ID": "cid-789",
        }

    def test_parse_custom_headers_single_line_equals(self) -> None:
        """Single-line Key=Value is supported."""
        raw = "X-TASK-DIAGNOSTICS=pyinstrument,memory"
        assert parse_custom_headers(raw) == {
            "X-TASK-DIAGNOSTICS": "pyinstrument,memory"
        }

    def test_parse_custom_headers_malformed_json_falls_through_to_lines(
        self,
    ) -> None:
        """A '{'-prefixed value that fails to parse falls through to line parsing.

        Regression test: previously this returned None directly, violating
        the documented dict[str, str] return type.
        """
        raw = "{not valid json}: still-a-header-value"
        assert parse_custom_headers(raw) == {
            "{not valid json}": "still-a-header-value"
        }


def _sequenced_client(responses: list[object]) -> tuple[httpx.Client, list[int]]:
    """Client whose transport replays *responses* (status ints or exceptions)."""
    calls: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        item = responses[min(len(calls), len(responses) - 1)]
        calls.append(1)
        if isinstance(item, Exception):
            raise item
        return httpx.Response(item, text=f"status {item}")

    transport = httpx.MockTransport(handler)
    return httpx.Client(
        transport=transport, base_url="https://example.com"
    ), calls


class TestRequestRetry:
    """Tests for request() retry-with-backoff on transient errors."""

    def test_5xx_then_success(self) -> None:
        """500, 500, 201 succeeds after two sleeps."""
        client, calls = _sequenced_client([500, 500, 201])
        sleeps: list[float] = []
        response = request(
            client,
            "POST",
            "/u",
            "Upload",
            _TestError,
            retries=3,
            sleep=sleeps.append,
        )
        assert response.status_code == 201
        assert len(calls) == 3
        assert len(sleeps) == 2
        client.close()

    @pytest.mark.parametrize("status", [404, 401])
    def test_4xx_not_retried(self, status: int) -> None:
        """Client errors raise immediately without retry."""
        client, calls = _sequenced_client([status, 201])
        sleeps: list[float] = []
        with pytest.raises(_TestError) as exc_info:
            request(client, "GET", "/u", "Fetch", _TestError, sleep=sleeps.append)
        assert exc_info.value.status_code == status
        assert len(calls) == 1
        assert sleeps == []
        client.close()

    def test_5xx_exhausts_attempts(self) -> None:
        """Persistent 500 raises the normal error after 3 attempts."""
        client, calls = _sequenced_client([500])
        sleeps: list[float] = []
        with pytest.raises(_TestError) as exc_info:
            request(
                client,
                "GET",
                "/u",
                "Fetch",
                _TestError,
                retries=3,
                sleep=sleeps.append,
            )
        assert exc_info.value.status_code == 500
        assert exc_info.value.message == "Fetch failed (500): status 500"
        assert len(calls) == 3
        assert len(sleeps) == 2
        client.close()

    def test_connect_error_retried(self) -> None:
        """ConnectError followed by success is retried."""
        client, calls = _sequenced_client([httpx.ConnectError("refused"), 200])
        sleeps: list[float] = []
        response = request(
            client, "GET", "/u", "Fetch", _TestError, sleep=sleeps.append
        )
        assert response.status_code == 200
        assert len(calls) == 2
        assert len(sleeps) == 1
        client.close()

    def test_timeout_not_retried(self) -> None:
        """TimeoutException is not retried."""
        client, calls = _sequenced_client([httpx.TimeoutException("slow"), 200])
        sleeps: list[float] = []
        with pytest.raises(_TestError, match="Request timed out"):
            request(client, "GET", "/u", "Fetch", _TestError, sleep=sleeps.append)
        assert len(calls) == 1
        assert sleeps == []
        client.close()

    def test_files_rewound_on_retry(self) -> None:
        """Multipart file objects are re-read from the start on retry."""
        import io

        bodies: list[bytes] = []

        def handler(req: httpx.Request) -> httpx.Response:
            bodies.append(req.read())
            return httpx.Response(500 if len(bodies) == 1 else 201)

        client = httpx.Client(
            transport=httpx.MockTransport(handler), base_url="https://example.com"
        )
        f = io.BytesIO(b"payload-bytes")
        request(
            client,
            "POST",
            "/u",
            "Upload",
            _TestError,
            files={"file": ("a.jar", f, "application/octet-stream")},
            sleep=lambda _s: None,
        )
        assert len(bodies) == 2
        assert b"payload-bytes" in bodies[1]
        client.close()

    def test_backoff_exponential_without_jitter(self) -> None:
        """Delays double per attempt."""
        delays = [
            compute_backoff(n, base=1.0, rand=lambda: 0.0) for n in (1, 2, 3)
        ]
        assert delays == [1.0, 2.0, 4.0]

    def test_backoff_jitter_bounded(self) -> None:
        """Jitter adds at most 25% of the delay."""
        assert compute_backoff(2, base=1.0, rand=lambda: 1.0) == pytest.approx(
            2.5
        )

    def test_backoff_respects_cap(self) -> None:
        """No single sleep exceeds the cap, even with jitter."""
        assert (
            compute_backoff(10, base=1.0, rand=lambda: 1.0) == MAX_BACKOFF_SECONDS
        )
        assert compute_backoff(5, base=1.0, cap=10.0, rand=lambda: 0.0) == 10.0
