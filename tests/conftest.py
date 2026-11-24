"""Shared test configuration and fixtures."""

import sys
from unittest.mock import MagicMock

import pytest

if "requests" not in sys.modules:
    try:
        import requests  # noqa: F401
    except ImportError:
        _requests = MagicMock()

        class _RequestException(Exception):
            pass

        class _ConnectionError(_RequestException):
            pass

        _requests.exceptions.RequestException = _RequestException
        _requests.exceptions.ConnectionError = _ConnectionError
        sys.modules["requests"] = _requests

_krbticket = MagicMock()
sys.modules.setdefault("krbticket", _krbticket)

_requests_gssapi = MagicMock()
sys.modules.setdefault("requests_gssapi", _requests_gssapi)

sys.modules.setdefault("fath_cuan.osidb", MagicMock())


@pytest.fixture(autouse=True)
def _no_http_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable real backoff sleeps in slan_cuan.http retries."""
    monkeypatch.setattr("slan_cuan.http._sleep", lambda _s: None)


@pytest.fixture(autouse=True)
def _clear_fath_cuan_caches():
    """Start each test with empty fath-cuan lookup caches.

    fath-cuan > 0.10 caches osv.dev/NVD lookups per process (LWLP-6012);
    tests that mock the same IDs differently must not see each other's
    answers. A no-op with fath-cuan versions without the caches.
    """
    from fath_cuan.converters import osv as fath_osv

    clear = getattr(fath_osv, "clear_caches", None)
    if clear is not None:
        clear()
    yield
    if clear is not None:
        clear()
