"""Ayudas comunes para los conectores que leen la API de GitHub (PoC-in-GitHub, búsqueda).

- El token se lee de la variable de entorno que nombra la configuración (`token_env`), nunca de un
  fichero ni del valor en la configuración.
- `RateLimiter` respeta un tope de peticiones por minuto (la búsqueda: 30/min con token y 10/min
  sin él, PLAN.md §4). No comparte tokens ni los rota para saltarse el límite (ToS §H, ADR-0020).
"""

from __future__ import annotations

import os
import time
from collections import deque
from collections.abc import Callable, Mapping
from typing import Any

API_VERSION = "2022-11-28"


def github_headers(config: Mapping[str, Any]) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION}
    token = github_token(config)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_token(config: Mapping[str, Any]) -> str | None:
    env = config.get("token_env")
    return os.environ.get(env) or None if env else None


class RateLimiter:
    """Ventana deslizante de 60 s: espera antes de pasar de `per_minute` peticiones."""

    def __init__(
        self,
        per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if per_minute < 1:
            raise ValueError("per_minute tiene que ser al menos 1")
        self.per_minute = per_minute
        self.clock = clock
        self.sleep = sleep
        self._calls: deque[float] = deque()
        self.waited = 0.0

    def acquire(self) -> None:
        now = self.clock()
        while self._calls and now - self._calls[0] >= 60.0:
            self._calls.popleft()
        if len(self._calls) >= self.per_minute:
            wait = 60.0 - (now - self._calls[0])
            if wait > 0:
                self.sleep(wait)
                self.waited += wait
            now = self.clock()
            while self._calls and now - self._calls[0] >= 60.0:
                self._calls.popleft()
        self._calls.append(now)
