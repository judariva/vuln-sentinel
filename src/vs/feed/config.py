"""Configuración del feed (ADR-0016, ADR-0019).

Los hosts y el `kid` salen de la configuración de marca (`config/brand.*.yaml` o las variables del
pipeline), nunca del código. Aquí solo hay valores por defecto que no son hosts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

FEED_SCHEMA_VERSION = "1.0.0"  # cabecera X-VS-Schema y schema/feed-1.0.0.json
OSV_SCHEMA_VERSION = "1.9.2"  # ADR-0007
DEFAULT_RETENTION_DAYS = 30  # ADR-0019, punto 4
DEFAULT_PAGE_LIMIT = 1000  # ADR-0019, punto 2
MAX_PAGE_LIMIT = 5000
HEAD_TTL_SECONDS = 60  # ADR-0019, punto 3


class FeedConfigError(ValueError):
    """La configuración del feed no es válida."""


@dataclass(frozen=True)
class FeedConfig:
    """Lo que el feed necesita saber de la instancia.

    `api_base` es la URL pública de la API (`feed.issuer` en la configuración de marca); de ella
    salen los enlaces absolutos, como el del snapshot en un `410`. `key_id` es el `kid` de la firma.
    """

    api_base: str
    key_id: str
    retention_days: int = DEFAULT_RETENTION_DAYS
    page_limit: int = DEFAULT_PAGE_LIMIT
    max_page_limit: int = MAX_PAGE_LIMIT
    # Datos CC-BY-SA en origen (OSV de Ubuntu y Alpine): fuera del feed hasta la revisión legal
    # (ADR-0020). Cambiarlo es decisión de Juan.
    include_share_alike: bool = False

    def __post_init__(self) -> None:
        parts = urlsplit(self.api_base)
        if parts.scheme != "https" or not parts.netloc or parts.query or parts.fragment:
            raise FeedConfigError(f"api_base debe ser una URL https sin query: {self.api_base!r}")
        object.__setattr__(self, "api_base", self.api_base.rstrip("/"))
        if not self.key_id or not self.key_id.strip():
            raise FeedConfigError("key_id vacío")
        if self.retention_days < 1:
            raise FeedConfigError("retention_days debe ser positivo")
        if not 1 <= self.page_limit <= self.max_page_limit:
            raise FeedConfigError("page_limit fuera de rango")

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            raise ValueError(f"ruta relativa: {path!r}")
        return self.api_base + path


def parse_feed_config(brand: Mapping[str, Any], **overrides: Any) -> FeedConfig:
    try:
        feed = brand["feed"]
        return FeedConfig(api_base=feed["issuer"], key_id=feed["key_id"], **overrides)
    except (KeyError, TypeError) as exc:
        raise FeedConfigError(
            f"configuración de marca sin 'feed.issuer' o 'feed.key_id': {exc}"
        ) from exc


def load_feed_config(path: str | Path, **overrides: Any) -> FeedConfig:
    with Path(path).open(encoding="utf-8") as fh:
        return parse_feed_config(yaml.safe_load(fh), **overrides)
