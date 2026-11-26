"""Cliente de modelo detrás de una interfaz (ADR-0009, ADR-0010).

- `ModelClient` es la interfaz: recibe la conversación y las herramientas y devuelve una
  `ModelResponse` (texto, llamadas a herramientas y uso de tokens).
- `FakeModel` reproduce respuestas guionizadas. Es lo que usan los tests y `eval --model fake`.
  Puede simular un modelo comprometido por una inyección: eso es lo que prueban los controles.
- `MessagesApiClient` habla con la API Messages de Claude, directa (Anthropic) o en Microsoft
  Foundry, según la configuración. Ni el endpoint ni el modelo ni la credencial están en el código:
  la configuración nombra variables de entorno (ADR-0016, regla 4 de `CLAUDE.md`). El envío pasa
  por un `Poster` inyectable; los tests solo comprueban la petición y la lectura de la respuesta,
  **sin ninguna llamada real**.

El formato de la API Messages (cabeceras, bloques `tool_use`/`tool_result`, `usage`) y la ruta en
Foundry están SIN VERIFICAR contra la documentación en esta tarea: se comprueban en G-6, antes de la
primera llamada real.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

import yaml


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    input: Mapping[str, Any]


@dataclass(frozen=True)
class ModelResponse:
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: str = "end_turn"
    tokens_in: int = 0
    tokens_out: int = 0


@dataclass(frozen=True)
class ModelRequest:
    system: str
    messages: Sequence[Mapping[str, Any]]
    tools: Sequence[Mapping[str, Any]]
    max_tokens: int = 4096


class ModelClient(Protocol):
    provider: str  # gen_ai.provider.name
    model: str

    def complete(self, request: ModelRequest) -> ModelResponse: ...


class ModelError(RuntimeError):
    """El proveedor no ha dado una respuesta utilizable."""


# -- modelo simulado --------------------------------------------------------------------------


Scripted = ModelResponse | Callable[[ModelRequest], ModelResponse]


class FakeModel:
    """Devuelve las respuestas del guion en orden. Ninguna llamada de red.

    Con `repeat_last=True`, al acabar el guion repite la última respuesta para siempre (el caso
    «bucle sin fin»). Sin él, pedir más respuestas que las del guion es un error del test.
    """

    provider = "fake"

    def __init__(
        self, script: Sequence[Scripted], *, model: str = "fake", repeat_last: bool = False
    ) -> None:
        if not script:
            raise ValueError("el guion del FakeModel está vacío")
        self.script = list(script)
        self.model = model
        self.repeat_last = repeat_last
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        i = len(self.requests)
        self.requests.append(request)
        if i >= len(self.script):
            if not self.repeat_last:
                raise ModelError("el guion del FakeModel se ha agotado")
            i = len(self.script) - 1
        item = self.script[i]
        resp = item(request) if callable(item) else item
        if isinstance(resp, ModelResponse) and resp.tool_calls:
            # Ids únicos por paso aunque se repita la misma respuesta.
            calls = tuple(
                ToolCall(f"{c.id}-{len(self.requests)}", c.name, c.input) for c in resp.tool_calls
            )
            resp = ModelResponse(
                resp.text, calls, resp.stop_reason, resp.tokens_in, resp.tokens_out
            )
        return resp


# -- API Messages (Anthropic o Foundry) -------------------------------------------------------


class Poster(Protocol):
    def post(self, url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> bytes: ...


class UrllibPoster:  # pragma: no cover - red real; nunca en tests
    def post(self, url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> bytes:
        if not url.startswith("https://"):
            raise ModelError("el endpoint del modelo tiene que ser HTTPS")
        req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise ModelError(f"HTTP {exc.code} del proveedor del modelo") from exc
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            raise ModelError(f"error de red con el proveedor del modelo: {exc}") from exc


PROVIDERS = {"anthropic": "anthropic", "foundry": "azure.ai.foundry"}
ANTHROPIC_VERSION = "2023-06-01"


@dataclass(frozen=True)
class RealModelConfig:
    """Configuración explícita del modelo real. Sin secretos: nombres de variables de entorno."""

    provider: str  # anthropic | foundry
    model: str
    endpoint_env: str  # variable con la URL completa del endpoint Messages
    credential_env: str  # variable con la clave (anthropic) o el token Bearer (foundry)
    timeout_s: float = 120.0

    @classmethod
    def load(cls, path: Path) -> RealModelConfig:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        missing = [
            k for k in ("provider", "model", "endpoint_env", "credential_env") if not doc.get(k)
        ]
        if missing:
            raise ValueError(f"configuración del modelo real incompleta: faltan {missing}")
        if doc["provider"] not in PROVIDERS:
            raise ValueError(f"proveedor desconocido: {doc['provider']!r}")
        return cls(
            provider=str(doc["provider"]),
            model=str(doc["model"]),
            endpoint_env=str(doc["endpoint_env"]),
            credential_env=str(doc["credential_env"]),
            timeout_s=float(doc.get("timeout_s", 120.0)),
        )


class MessagesApiClient:
    def __init__(
        self,
        config: RealModelConfig,
        *,
        env: Mapping[str, str] | None = None,
        poster: Poster | None = None,
    ) -> None:
        env = os.environ if env is None else env
        endpoint = env.get(config.endpoint_env, "")
        credential = env.get(config.credential_env, "")
        if not endpoint.startswith("https://"):
            raise ValueError(f"{config.endpoint_env} no está definida o no es HTTPS")
        if not credential:
            raise ValueError(f"{config.credential_env} no está definida")
        self.config = config
        self.provider = PROVIDERS[config.provider]
        self.model = config.model
        self._endpoint = endpoint
        self._credential = credential
        self._poster = poster or UrllibPoster()

    def headers(self) -> dict[str, str]:
        h = {"content-type": "application/json", "anthropic-version": ANTHROPIC_VERSION}
        if self.config.provider == "anthropic":
            h["x-api-key"] = self._credential
        else:  # Foundry con identidad gestionada: token de Entra ID
            h["authorization"] = f"Bearer {self._credential}"
        return h

    def payload(self, request: ModelRequest) -> dict[str, Any]:
        return {
            "model": self.model,
            "max_tokens": request.max_tokens,
            "system": request.system,
            "messages": list(request.messages),
            "tools": list(request.tools),
        }

    @staticmethod
    def parse(raw: bytes) -> ModelResponse:
        try:
            doc = json.loads(raw)
            text = "".join(b.get("text", "") for b in doc["content"] if b.get("type") == "text")
            calls = tuple(
                ToolCall(str(b["id"]), str(b["name"]), dict(b.get("input") or {}))
                for b in doc["content"]
                if b.get("type") == "tool_use"
            )
            usage = doc.get("usage") or {}
            return ModelResponse(
                text=text,
                tool_calls=calls,
                stop_reason=str(doc.get("stop_reason") or ""),
                tokens_in=int(usage.get("input_tokens", 0)),
                tokens_out=int(usage.get("output_tokens", 0)),
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ModelError("respuesta del modelo ilegible") from exc

    def complete(self, request: ModelRequest) -> ModelResponse:
        body = json.dumps(self.payload(request)).encode()
        raw = self._poster.post(self._endpoint, self.headers(), body, self.config.timeout_s)
        return self.parse(raw)


# -- precio ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Price:
    input_per_mtok: Decimal
    output_per_mtok: Decimal

    def cost(self, tokens_in: int, tokens_out: int) -> Decimal:
        m = Decimal(1_000_000)
        return (tokens_in * self.input_per_mtok + tokens_out * self.output_per_mtok) / m


@dataclass(frozen=True)
class Pricing:
    """USD por millón de tokens y modelo (`config/agent.yaml`, PLAN.md §7)."""

    prices: Mapping[str, Price] = field(default_factory=dict)

    def for_model(self, model: str) -> Price:
        try:
            return self.prices[model]
        except KeyError:
            # Sin precio no se puede aplicar el tope de USD: no se llama al modelo.
            raise ValueError(f"no hay precio configurado para el modelo {model!r}") from None

    @classmethod
    def parse(cls, doc: Mapping[str, Any]) -> Pricing:
        return cls(
            {
                str(name): Price(Decimal(str(p["input"])), Decimal(str(p["output"])))
                for name, p in (doc or {}).items()
            }
        )
