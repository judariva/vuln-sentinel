"""Transporte HTTP simulado para los tests de conectores: sin red, con fixtures."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from vs.sources.http import Response

FIXTURES = Path(__file__).resolve().parent / "fixtures"

Route = Response | BaseException | Callable[[Mapping[str, str]], Response]


def fixture_bytes(*parts: str) -> bytes:
    return FIXTURES.joinpath(*parts).read_bytes()


def ok(body: bytes, status: int = 200, headers: Mapping[str, str] | None = None) -> Response:
    return Response(status, body, dict(headers or {}))


class FakeTransport:
    """Sirve respuestas por URL exacta. Una URL sin ruta da 404; una excepción se lanza tal cual."""

    def __init__(self, routes: Mapping[str, Route] | None = None) -> None:
        self.routes: dict[str, Route] = dict(routes or {})
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, *, headers=None, timeout: float = 0.0) -> Response:
        hdrs = dict(headers or {})
        self.calls.append((url, hdrs))
        route = self.routes.get(url)
        if route is None:
            return Response(404, b"not found", {})
        if isinstance(route, BaseException):
            raise route
        if callable(route):
            return route(hdrs)
        return route

    def urls(self) -> list[str]:
        return [u for u, _ in self.calls]
