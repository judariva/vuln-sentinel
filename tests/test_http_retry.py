"""Reintentos acotados de `UrllibTransport` (T13). Sin red: `_get_once` simulado."""

import pytest

from vs.sources.http import NetworkError, Response, UrllibTransport


def transport(statuses: list[int]) -> tuple[UrllibTransport, list[float], list[str]]:
    sleeps: list[float] = []
    calls: list[str] = []
    t = UrllibTransport(sleep=sleeps.append)

    def once(url, *, headers=None, timeout=None):
        calls.append(url)
        return Response(statuses.pop(0), b"")

    t._get_once = once  # type: ignore[method-assign]
    return t, sleeps, calls


def test_transient_503_is_retried():
    t, sleeps, calls = transport([503, 200])
    assert t.get("https://example.invalid/x").status == 200
    assert len(calls) == 2 and sleeps == [1.0]


def test_persistent_5xx_gives_up_and_returns_the_error():
    t, sleeps, calls = transport([503, 502, 504])
    assert t.get("https://example.invalid/x").status == 504
    assert len(calls) == 3 and sleeps == [1.0, 4.0]


def test_network_errors_are_retried_then_raised():
    sleeps: list[float] = []
    calls: list[int] = []
    t = UrllibTransport(sleep=sleeps.append)

    def once(url, *, headers=None, timeout=None):
        calls.append(1)
        raise NetworkError("error de red: handshake timed out")

    t._get_once = once  # type: ignore[method-assign]
    with pytest.raises(NetworkError):
        t.get("https://example.invalid/x")
    assert len(calls) == 3 and sleeps == [1.0, 4.0]


def test_network_error_then_ok():
    results: list = [NetworkError("timeout"), Response(200, b"ok")]
    t = UrllibTransport(sleep=lambda _s: None)

    def once(url, *, headers=None, timeout=None):
        r = results.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    t._get_once = once  # type: ignore[method-assign]
    assert t.get("https://example.invalid/x").body == b"ok"


def test_rate_limits_are_not_retried():
    for status in (403, 429, 404):
        t, sleeps, calls = transport([status])
        assert t.get("https://example.invalid/x").status == status
        assert len(calls) == 1 and not sleeps
