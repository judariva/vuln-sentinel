"""Vigilante externo (PLAN §11, R8, CMP-013): comprueba el feed público desde fuera de Azure.

Lo ejecuta `.github/workflows/watchdog.yml` cada 30 min (`python -m vs.watchdog`):

1. lee el índice «head» de `/v1/feed/all/changes` y su `.jws` a través del borde;
2. verifica la firma JWS detached con la clave pública: la fijada en `VS_FEED_JWKS` (variable del
   repo) o, si no está, la del JWKS publicado (`/.well-known/vuln-sentinel/keys.json`);
3. comprueba que `modified` tenga menos de 30 min y que ninguna fuente lleve más de 2 h en UNKNOWN.

Fail-closed: un índice sin firma válida, sin `modified` o sin `sources`, o que no se puede leer, es
un fallo. Si la firma falla no se mira nada más: el contenido no es de fiar.

Salida: 0 si todo está bien; 1 si algo falla (el workflow falla y avisa); 2 si falta configuración.
Nunca imprime la URL del feed: solo rutas (los logs de Actions serán públicos, THR-019).
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from vs.feed.sign import SignatureError, verify_detached
from vs.sources.http import SourceError, Transport, UrllibTransport

HEAD_PATH = "/v1/feed/all/changes"
KEYS_PATH = "/.well-known/vuln-sentinel/keys.json"
MAX_AGE = timedelta(minutes=30)
MAX_UNKNOWN = timedelta(hours=2)
MAX_SKEW = timedelta(minutes=5)  # `modified` en el futuro más allá de esto es un reloj roto
ATTEMPTS = 3  # el .json y el .jws son dos peticiones: pueden salir de instantes distintos
RETRY_PAUSE_S = 5.0
TIMEOUT_S = 20.0
MAX_BYTES = 16 * 1024 * 1024

ENV_BASE_URL = "VS_FEED_BASE_URL"
ENV_JWKS = "VS_FEED_JWKS"


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.detail}"


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        when = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return when.astimezone(UTC)


def _minutes(delta: timedelta) -> str:
    return f"{delta.total_seconds() / 60:.0f} min"


def check_head(
    body: bytes,
    jws: str,
    jwks: Mapping[str, Any],
    now: datetime,
    *,
    max_age: timedelta = MAX_AGE,
    max_unknown: timedelta = MAX_UNKNOWN,
) -> list[Finding]:
    """Comprobaciones sobre los bytes del índice «head». Lista vacía si todo está bien."""
    try:
        verify_detached(jws, body, jwks)
    except SignatureError as exc:
        return [Finding("signature", f"la firma de {HEAD_PATH} no es válida: {exc}")]

    try:
        doc = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return [Finding("malformed", f"{HEAD_PATH} no es JSON")]
    if not isinstance(doc, dict) or doc.get("kind") != "changes" or doc.get("feed") != "all":
        return [Finding("malformed", f"{HEAD_PATH} no es el índice del feed 'all'")]
    if doc.get("sealed") is not False:
        return [Finding("malformed", f"{HEAD_PATH} no es el índice «head» (sealed != false)")]

    findings: list[Finding] = []
    modified = _parse_ts(doc.get("modified"))
    if modified is None:
        findings.append(Finding("no_status", "el índice no lleva un 'modified' válido"))
    elif modified - now > MAX_SKEW:
        findings.append(
            Finding("clock", f"'modified' está {_minutes(modified - now)} en el futuro")
        )
    elif now - modified >= max_age:
        findings.append(
            Finding(
                "stale", f"'modified' tiene {_minutes(now - modified)} (máximo {_minutes(max_age)})"
            )
        )

    sources = doc.get("sources")
    if not isinstance(sources, list) or not sources:
        findings.append(Finding("no_status", "el índice no lleva el estado de las fuentes"))
        return findings
    for src in sources:
        if not isinstance(src, dict) or not isinstance(src.get("name"), str):
            findings.append(Finding("malformed", "entrada de 'sources' no válida"))
            continue
        if src.get("status") not in ("ok", "partial", "unknown"):
            findings.append(Finding("malformed", f"estado no válido en la fuente {src['name']}"))
            continue
        if src["status"] != "unknown":
            continue
        since = _parse_ts(src.get("since"))
        if since is None:
            findings.append(Finding("source_unknown", f"{src['name']} en UNKNOWN sin 'since'"))
        elif now - since > max_unknown:
            findings.append(
                Finding(
                    "source_unknown",
                    f"{src['name']} lleva {_minutes(now - since)} en UNKNOWN "
                    f"(máximo {_minutes(max_unknown)})",
                )
            )
    return findings


# -- lectura -------------------------------------------------------------------------------------


class FetchError(RuntimeError):
    pass


def _get(transport: Transport, base: str, path: str) -> bytes:
    """GET que nunca pone la URL completa en el error (solo la ruta)."""
    try:
        resp = transport.get(base + path, timeout=TIMEOUT_S)
    except (SourceError, OSError) as exc:
        raise FetchError(f"no se pudo leer {path} ({type(exc).__name__})") from None
    if resp.status != 200:
        raise FetchError(f"{path} respondió HTTP {resp.status}")
    return resp.body


def load_jwks(text: str) -> dict[str, Any]:
    try:
        jwks = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JWKS no es JSON: {exc}") from exc
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
        raise ValueError("JWKS sin claves")
    return jwks


def run_checks(
    base_url: str,
    transport: Transport,
    now: Callable[[], datetime],
    *,
    pinned_jwks: Mapping[str, Any] | None = None,
    attempts: int = ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Finding]:
    base = base_url.rstrip("/")
    try:
        jwks = pinned_jwks or load_jwks(_get(transport, base, KEYS_PATH).decode("utf-8"))
    except (FetchError, ValueError, UnicodeDecodeError) as exc:
        return [Finding("fetch", f"clave pública: {exc}")]
    findings: list[Finding] = []
    for attempt in range(attempts):
        if attempt:
            sleep(RETRY_PAUSE_S)
        try:
            body = _get(transport, base, HEAD_PATH)
            jws = _get(transport, base, HEAD_PATH + ".jws").decode("ascii")
        except FetchError as exc:
            return [Finding("fetch", str(exc))]
        except UnicodeDecodeError:
            return [Finding("signature", f"{HEAD_PATH}.jws no es ASCII")]
        findings = check_head(body, jws, jwks, now())
        # Solo se reintenta una firma que no casa: puede ser un .json y un .jws de instantes
        # distintos. Un fallo persistente sigue fallando en el último intento.
        if not any(f.code == "signature" for f in findings):
            return findings
    return findings


def _check_base_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc or parts.query or parts.fragment:
        raise ValueError(f"{ENV_BASE_URL} debe ser una URL https sin query")


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    transport: Transport | None = None,
    clock: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    env = os.environ if env is None else env
    base = env.get(ENV_BASE_URL, "").strip()
    if not base:
        print(f"falta la variable {ENV_BASE_URL}: no hay nada que vigilar", file=sys.stderr)
        return 2
    try:
        _check_base_url(base)
        pinned = load_jwks(env[ENV_JWKS]) if env.get(ENV_JWKS, "").strip() else None
    except ValueError as exc:
        print(f"configuración no válida: {exc}", file=sys.stderr)
        return 2
    findings = run_checks(
        base,
        transport or UrllibTransport(timeout=TIMEOUT_S, max_bytes=MAX_BYTES),
        clock or (lambda: datetime.now(UTC)),
        pinned_jwks=pinned,
        sleep=sleep,
    )
    origin = "fijada" if pinned else "publicada"
    if findings:
        print(f"vigilante: {len(findings)} problema(s) (clave {origin})")
        for f in findings:
            print(f"  {f}")
        return 1
    print(f"vigilante: feed al día, firma válida (clave {origin}), ninguna fuente en UNKNOWN > 2 h")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
