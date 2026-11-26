"""Trazas del agente con la convención GenAI de OpenTelemetry (ADR-0010, CMP-014).

El agente no depende de OpenTelemetry: habla con una interfaz `Tracer` mínima. En los tests y en
la evaluación se usa `NullTracer` (no exporta nada) o `RecordingTracer` (guarda los spans en
memoria para comprobarlos). En producción, `OTelTracer` adapta la API de OpenTelemetry si el
paquete está instalado; el exportador a Application Insights se configura fuera de este módulo.

Atributos que se usan (convención semántica GenAI de OpenTelemetry; la versión exacta se fija al
cablear el exportador en F2):
- `gen_ai.operation.name`: `invoke_agent`, `chat` o `execute_tool`;
- `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.agent.name`;
- `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`;
- `gen_ai.tool.name`, `gen_ai.tool.call.id`.

Nunca se pone en un span el contenido de los mensajes ni el de las páginas descargadas: solo
metadatos (nombres, recuentos, decisiones de los controles).
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol

AttrValue = str | int | float | bool


class Span(Protocol):
    def set_attribute(self, key: str, value: AttrValue) -> None: ...


class Tracer(Protocol):
    def new_trace_id(self) -> str: ...

    def span(self, name: str, attributes: Mapping[str, AttrValue] | None = None): ...


def _trace_id() -> str:
    """32 caracteres hexadecimales, como un trace id de W3C."""
    return secrets.token_hex(16)


class _NullSpan:
    def set_attribute(self, key: str, value: AttrValue) -> None:
        return None


class NullTracer:
    """Exportador nulo: no guarda ni envía nada."""

    def new_trace_id(self) -> str:
        return _trace_id()

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, AttrValue] | None = None) -> Iterator[Span]:
        yield _NullSpan()


@dataclass
class RecordedSpan:
    name: str
    attributes: dict[str, AttrValue] = field(default_factory=dict)

    def set_attribute(self, key: str, value: AttrValue) -> None:
        self.attributes[key] = value


class RecordingTracer:
    """Guarda los spans en memoria. Para tests."""

    def __init__(self) -> None:
        self.spans: list[RecordedSpan] = []

    def new_trace_id(self) -> str:
        return _trace_id()

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, AttrValue] | None = None) -> Iterator[Span]:
        s = RecordedSpan(name, dict(attributes or {}))
        self.spans.append(s)
        yield s

    def named(self, name: str) -> list[RecordedSpan]:
        return [s for s in self.spans if s.name == name]


class OTelTracer:  # pragma: no cover - solo con opentelemetry instalado (F2)
    """Adaptador a la API de OpenTelemetry. Importa el paquete al crearse, no al importar."""

    def __init__(self, instrumentation_name: str = "vs.agent") -> None:
        from opentelemetry import trace  # type: ignore[import-not-found]

        self._trace = trace
        self._tracer = trace.get_tracer(instrumentation_name)

    def new_trace_id(self) -> str:
        ctx = self._trace.get_current_span().get_span_context()
        return format(ctx.trace_id, "032x") if ctx.is_valid else _trace_id()

    @contextmanager
    def span(self, name: str, attributes: Mapping[str, Any] | None = None) -> Iterator[Span]:
        with self._tracer.start_as_current_span(name, attributes=dict(attributes or {})) as s:
            yield s
