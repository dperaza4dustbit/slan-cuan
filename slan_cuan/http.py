"""Shared HTTP request helpers for REST API clients."""

from __future__ import annotations

import os
import random
import ssl
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import httpx

from slan_cuan.utils import safe_json_load

ERROR_BODY_MAX_LENGTH = 200

# Retry policy for transient server-side failures (HTTP 5xx and connection
# errors).  A single transient error during a long run of content uploads
# should not fail the whole release, so request() retries with exponential
# backoff and only gives up after consecutive failures.
DEFAULT_RETRIES = int(os.getenv("SLAN_CUAN_PULP_RETRIES", "3"))
"""Total attempts per request (initial attempt + retries)."""
DEFAULT_BACKOFF_SECONDS = float(
    os.getenv("SLAN_CUAN_PULP_BACKOFF_SECONDS", "1.0")
)
"""Base backoff; attempt N sleeps ``base * 2**(N-1)`` plus jitter."""
MAX_BACKOFF_SECONDS = 30.0
"""Upper bound on any single sleep between attempts."""
BACKOFF_JITTER_RATIO = 0.25
"""Up to this fraction of the delay is added as random jitter."""

_sleep = time.sleep  # module seam so tests can disable real backoff sleeps


def _utc_timestamp() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_backoff(
    attempt: int,
    base: float = DEFAULT_BACKOFF_SECONDS,
    cap: float = MAX_BACKOFF_SECONDS,
    jitter: float = BACKOFF_JITTER_RATIO,
    rand: Callable[[], float] = random.random,
) -> float:
    """Return the sleep before retrying after failed *attempt* (1-based).

    Exponential (``base * 2**(attempt-1)``) with up to *jitter* fraction of
    random extra delay, so concurrent runs do not retry in lockstep.  The
    result never exceeds *cap*.
    """
    delay = min(base * (2 ** (attempt - 1)), cap)
    return min(delay + delay * jitter * rand(), cap)


def _rewind_files(files: Any) -> None:
    """Seek multipart file objects back to the start before a retry."""
    if not isinstance(files, dict):
        return
    for value in files.values():
        fobj = value[1] if isinstance(value, tuple) and len(value) > 1 else value
        seek = getattr(fobj, "seek", None)
        if callable(seek):
            seek(0)


class HttpApiError(Exception):
    """Base exception for HTTP API failures."""

    def __init__(
        self,
        message: str,
        status_code: int,
        response_body: str,
    ) -> None:
        """Initialize with structured error context."""
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_body = response_body


def create_ssl_context(
    ca_cert: Path | None,
    verify_ssl: bool,
    error_cls: type[HttpApiError],
) -> ssl.SSLContext | bool:
    """Build an SSL verification context from a CA certificate.

    Args:
        ca_cert: Path to a CA certificate file, or None.
        verify_ssl: Whether SSL verification is enabled.
        error_cls: Exception class to raise on failure.

    Returns:
        An SSLContext when ca_cert is provided and verify_ssl is True,
        otherwise the boolean verify_ssl value.

    Raises:
        error_cls: If the CA certificate cannot be loaded.

    """
    verify: ssl.SSLContext | bool = verify_ssl
    if verify and ca_cert is not None:
        try:
            verify = ssl.create_default_context(cafile=str(ca_cert))
            # Internal CAs may omit the "critical" flag on Basic
            # Constraints; Python 3.14+ rejects them by default.
            verify.verify_flags &= ~ssl.VERIFY_X509_STRICT
        except (ssl.SSLError, OSError) as e:
            raise error_cls(
                f"Failed to load CA certificate from {ca_cert}: {e}",
                status_code=0,
                response_body="",
            ) from e
    return verify


def raise_for_status(
    response: httpx.Response,
    operation: str,
    error_cls: type[HttpApiError],
) -> None:
    """Raise if the response has an HTTP error status.

    Args:
        response: The HTTP response to check.
        operation: Human-readable name for error messages.
        error_cls: Exception class to raise on failure.

    Raises:
        error_cls: If status_code >= 400.

    """
    if response.status_code >= 400:
        body = response.text
        summary = body[:ERROR_BODY_MAX_LENGTH]
        if len(body) > ERROR_BODY_MAX_LENGTH:
            summary += "... (truncated)"
        raise error_cls(
            f"{operation} failed ({response.status_code}): {summary}",
            status_code=response.status_code,
            response_body=body,
        )


def parse_json_dict(
    response: httpx.Response,
    operation: str,
    error_cls: type[HttpApiError],
) -> dict[str, object]:
    """Parse a JSON response body and validate it is a dict.

    Args:
        response: The HTTP response to parse.
        operation: Human-readable name for error messages.
        error_cls: Exception class to raise on failure.

    Returns:
        The parsed JSON object as a dict.

    Raises:
        error_cls: If the body is not valid JSON or not a dict.

    """
    try:
        data = response.json()
    except ValueError as e:
        raise error_cls(
            f"Failed to parse {operation} response: {e}",
            status_code=response.status_code,
            response_body=response.text,
        ) from e

    if not isinstance(data, dict):
        raise error_cls(
            f"{operation} returned non-dict response",
            status_code=response.status_code,
            response_body=response.text,
        )
    return data


def request(
    client: httpx.Client,
    method: str,
    url: str,
    operation: str,
    error_cls: type[HttpApiError],
    *,
    retries: int | None = None,
    backoff_seconds: float | None = None,
    sleep: Callable[[float], None] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Send an HTTP request with standardised error handling and retry.

    Wraps ``client.request()`` to catch transport errors and check the
    response status, converting both into *error_cls* instances.

    Transient failures -- HTTP 5xx responses and ``httpx.ConnectError`` --
    are retried with exponential backoff and jitter.  4xx responses are
    never retried (the request itself is wrong), and timeouts are not
    retried (the server may still be processing a non-idempotent request).
    After the final attempt the same error as a non-retried failure is
    raised.

    Args:
        client: The httpx client to use.
        method: HTTP method (GET, POST, PATCH, ...).
        url: Request URL (absolute or relative to client base_url).
        operation: Human-readable name for error messages.
        error_cls: Exception class to raise on failure.
        retries: Total attempts (default ``DEFAULT_RETRIES``, env
            ``SLAN_CUAN_PULP_RETRIES``).  Values < 1 are treated as 1.
        backoff_seconds: Base backoff (default ``DEFAULT_BACKOFF_SECONDS``,
            env ``SLAN_CUAN_PULP_BACKOFF_SECONDS``).
        sleep: Sleep function, injectable for tests (default
            ``time.sleep``).
        **kwargs: Forwarded to ``client.request()``.

    Returns:
        The HTTP response (status < 400).

    Raises:
        error_cls: On transport errors or HTTP error status.

    """
    sleep = sleep or _sleep
    attempts = max(1, DEFAULT_RETRIES if retries is None else retries)
    base = DEFAULT_BACKOFF_SECONDS if backoff_seconds is None else backoff_seconds

    for attempt in range(1, attempts + 1):
        if attempt > 1:
            _rewind_files(kwargs.get("files"))
        try:
            response = client.request(method, url, **kwargs)
        except httpx.ConnectError as e:
            if attempt < attempts:
                _log_retry(
                    operation,
                    f"connection error ({e})",
                    attempt,
                    attempts,
                    base,
                    sleep,
                )
                continue
            raise error_cls(
                f"Connection failed: {e}",
                status_code=0,
                response_body="",
            ) from e
        except httpx.TimeoutException as e:
            raise error_cls(
                f"Request timed out: {e}",
                status_code=0,
                response_body="",
            ) from e

        if response.status_code >= 500 and attempt < attempts:
            _log_retry(
                operation,
                f"HTTP {response.status_code}",
                attempt,
                attempts,
                base,
                sleep,
            )
            continue

        raise_for_status(response, operation, error_cls)
        return response

    raise AssertionError("unreachable")  # pragma: no cover


def _log_retry(
    operation: str,
    reason: str,
    attempt: int,
    attempts: int,
    base: float,
    sleep: Callable[[float], None],
) -> None:
    """Log a retry in the timestamped click style and sleep the backoff."""
    delay = compute_backoff(attempt, base=base)
    click.echo(
        f"[{_utc_timestamp()}]  {operation} got {reason}, retrying in "
        f"{delay:.1f}s (attempt {attempt + 1} of {attempts})",
        err=True,
    )
    sleep(delay)


def parse_custom_headers(raw: str | None) -> dict[str, str]:
    r"""Parse custom HTTP headers delimited by CRLF or newline.

    Supports:
        - CRLF / newline-separated lines (e.g. 'Header1: val1\nHeader2: val2')
        - Escaped literal newlines ('\n' or '\r\n')
        - Both 'Header: Value' and 'Header=Value' syntax
        - Single-line header definitions
        - JSON object string fallback (e.g. '{"Header": "Value"}')

    Args:
        raw: Header string with newline/CRLF delimiters or JSON format.

    Returns:
        Dictionary mapping header names to header values.

    """
    if not raw or not raw.strip():
        return {}
    raw = raw.strip()
    if raw.startswith("{"):
        data = safe_json_load(raw, expected_type=dict, raise_on_err=False)
        if data is not None:
            return {str(k).strip(): str(v).strip() for k, v in data.items()}
        # Malformed JSON-looking input falls through to line parsing below.

    # Normalize real and escaped newlines (CRLF, LF, \r\n, \n)
    normalized = (
        raw.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n")
    )
    headers: dict[str, str] = {}
    for line in normalized.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        elif "=" in line:
            k, v = line.split("=", 1)
            headers[k.strip()] = v.strip()
    return headers
