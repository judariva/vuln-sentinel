"""Configuración de los jobs y de la API por variables de entorno. Sin secretos en el repo.

| Variable | Por defecto | Qué es |
|---|---|---|
| `VS_DATABASE_URL` | (obligatoria) | PostgreSQL |
| `VS_CONFIG_DIR` | `config/` del repo | instancia, marca y listas |
| `VS_INSTANCE` | `instance.public.yaml` | configuración de instancia (ADR-0022) |
| `VS_BRAND` | `brand.example.yaml` | hosts y `kid` (ADR-0016) |
| `VS_SIGNING_KEY` | `.cache/signing/dev-es256.pem` | clave de `LocalDevSigner` (nunca en git) |
| `VS_FEED_DIR` | `.cache/feed` | dónde escribe el job de publicación |
| `VS_WEB_DIST` | (vacío) | build del portal que sirve la API en el mismo origen |
| `VS_CONNECTORS` | (todos) | lista separada por comas para limitar los conectores |
| `VS_AGENT_ENABLED` | `0` | `1` activa el job de investigación |
| `VS_GITHUB_TOKEN` | (vacío) | token opcional; lo leen los conectores por su `token_env` |

En Azure, la firma pasará a `KeyVaultSigner` y la escritura del feed, a R2 (F1b).
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vs.feed.config import FeedConfig, load_feed_config
from vs.feed.sign import LocalDevSigner
from vs.instance import Instance, load_instance
from vs.rules.lists import RuleLists, load_lists

ROOT = Path(__file__).resolve().parents[3]

# Conectores que no son de ingesta: `github_search` solo busca para los candidatos B/C que le pasa
# el job de investigación.
NOT_INGEST = frozenset({"github_search"})


class SettingsError(ValueError):
    """Configuración del entorno no válida (código de salida 2)."""


def _path(env: Mapping[str, str], name: str, default: Path, base: Path | None = None) -> Path:
    raw = env.get(name)
    if not raw:
        return default
    p = Path(raw)
    return p if p.is_absolute() or base is None else base / p


@dataclass(frozen=True)
class Settings:
    database_url: str | None
    config_dir: Path
    instance_path: Path
    brand_path: Path
    signing_key: Path
    feed_dir: Path
    web_dist: Path | None
    connectors: frozenset[str] | None
    agent_enabled: bool

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        config_dir = _path(env, "VS_CONFIG_DIR", ROOT / "config")
        names = env.get("VS_CONNECTORS", "").strip()
        dist = env.get("VS_WEB_DIST", "").strip()
        return cls(
            database_url=env.get("VS_DATABASE_URL") or None,
            config_dir=config_dir,
            instance_path=_path(
                env, "VS_INSTANCE", config_dir / "instance.public.yaml", config_dir
            ),
            brand_path=_path(env, "VS_BRAND", config_dir / "brand.example.yaml", config_dir),
            signing_key=_path(env, "VS_SIGNING_KEY", ROOT / ".cache" / "signing" / "dev-es256.pem"),
            feed_dir=_path(env, "VS_FEED_DIR", ROOT / ".cache" / "feed"),
            web_dist=Path(dist) if dist else None,
            connectors=frozenset(n.strip() for n in names.split(",") if n.strip()) or None,
            agent_enabled=env.get("VS_AGENT_ENABLED", "0").strip() == "1",
        )

    def require_db(self) -> str:
        if not self.database_url:
            raise SettingsError("falta VS_DATABASE_URL")
        return self.database_url

    def instance(self) -> Instance:
        return load_instance(self.instance_path)

    def lists(self) -> RuleLists:
        return load_lists(
            self.config_dir / "exposed-products.yaml",
            self.config_dir / "trusted-exploit-authors.yaml",
        )

    def feed_config(self) -> FeedConfig:
        return load_feed_config(self.brand_path)

    def signer(self, feed: FeedConfig) -> LocalDevSigner:
        try:
            return LocalDevSigner.load_or_create(self.signing_key, feed.key_id)
        except FileExistsError:  # otro proceso (la API o un job) la creó a la vez: se lee
            return LocalDevSigner.load_or_create(self.signing_key, feed.key_id)


def log(event: str, **fields) -> None:
    """Una línea JSON por evento en stdout (la recoge Container Apps o `docker compose logs`)."""
    doc = {"at": datetime.now(UTC).isoformat(), "event": event, **fields}
    print(json.dumps(doc, ensure_ascii=False, default=str), flush=True)


def run_main(fn) -> int:
    """Ejecuta un job: 0 si va bien, 2 si la configuración no vale, 1 en cualquier otro fallo."""
    try:
        return int(fn(Settings.from_env()) or 0)
    except SettingsError as exc:
        log("config_error", error=str(exc))
        return 2
    except Exception as exc:
        log("failed", error=f"{type(exc).__name__}: {exc}"[:500])
        return 1


def exit_with(fn) -> None:
    sys.exit(run_main(fn))
