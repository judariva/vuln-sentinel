"""Salida del agente: el expediente (dossier) y su JSON Schema (PLAN.md §7, «Salida mal formada»).

El agente entrega el expediente llamando a la herramienta `submit_dossier`, cuyo `input_schema` es
`DOSSIER_SCHEMA`. El código **no se fía** de que el modelo respete el esquema: lo valida otra vez
con `validate` y, si no valida, rechaza la salida entera y el nivel se queda en el determinista.

`validate` implementa el subconjunto de JSON Schema 2020-12 que usa `DOSSIER_SCHEMA` (`type`,
`properties`, `required`, `additionalProperties: false`, `enum`, `items`, `minItems`, `maxItems`,
`minLength`, `maxLength`, `pattern`, `minimum`). Un test comprueba que da el mismo resultado que
la biblioteca `jsonschema` (dependencia de desarrollo) sobre casos válidos y no válidos, y que un
esquema con una palabra clave fuera del subconjunto se rechaza en vez de ignorarse.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

LEVELS = ("none", "C", "B", "A")
IMPACT_CLASSES = ("rce", "auth_bypass", "arbitrary_rw", "other")
CLAIM_KINDS = (
    "exploited",  # un aviso oficial dice que se explota (puede llevar a A)
    "exploit_impact",  # el código del PoC implementa el impacto de la CVE (E5: solo C → B)
    "affected_range",  # versiones afectadas
    "fix",  # versión o parche que corrige
    "exposure",  # el producto está expuesto a Internet
    "other",
)

_CITATION = {
    "type": "object",
    "additionalProperties": False,
    "required": ["url", "quote"],
    "properties": {
        "url": {"type": "string", "pattern": "^https://", "maxLength": 2000},
        "quote": {"type": "string", "minLength": 1, "maxLength": 1000},
        # Para código (E5): líneas, empezando en 1, entre las que está la cita.
        "line_start": {"type": "integer", "minimum": 1},
        "line_end": {"type": "integer", "minimum": 1},
    },
}

DOSSIER_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "vuln-sentinel agent dossier",
    "type": "object",
    "additionalProperties": False,
    "required": ["cve_id", "proposed_level", "impact_class", "claims", "summary"],
    "properties": {
        "cve_id": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"},
        "proposed_level": {"type": "string", "enum": list(LEVELS)},
        "impact_class": {"type": "string", "enum": list(IMPACT_CLASSES)},
        "claims": {
            "type": "array",
            "maxItems": 30,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "statement", "citations"],
                "properties": {
                    "kind": {"type": "string", "enum": list(CLAIM_KINDS)},
                    "statement": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "citations": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 5,
                        "items": _CITATION,
                    },
                },
            },
        },
        "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
    },
}

_SUPPORTED = frozenset(
    {
        "$schema",
        "title",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
    }
)


class SchemaError(ValueError):
    """El esquema usa algo que `validate` no sabe comprobar: mejor fallar que ignorarlo."""


def _type_ok(value: Any, expected: str) -> bool:
    match expected:
        case "object":
            return isinstance(value, Mapping)
        case "array":
            return isinstance(value, list)
        case "string":
            return isinstance(value, str)
        case "boolean":
            return isinstance(value, bool)
        case "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        case "number":
            return isinstance(value, int | float) and not isinstance(value, bool)
        case "null":
            return value is None
    raise SchemaError(f"tipo no admitido: {expected}")


def validate(instance: Any, schema: Mapping[str, Any], path: str = "$") -> list[str]:
    """Errores de validación (lista vacía si valida). Ver el subconjunto en el docstring."""
    unknown = set(schema) - _SUPPORTED
    if unknown:
        raise SchemaError(f"palabras clave no admitidas en {path}: {sorted(unknown)}")
    errors: list[str] = []
    expected = schema.get("type")
    if expected is not None:
        types = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(instance, t) for t in types):
            return [f"{path}: se esperaba {expected}"]
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: valor fuera de enum")
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            errors.append(f"{path}: demasiado corto")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: demasiado largo")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: no cumple el patrón")
    is_number = isinstance(instance, int | float) and not isinstance(instance, bool)
    if is_number and "minimum" in schema and instance < schema["minimum"]:
        errors.append(f"{path}: menor que el mínimo")
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            errors.append(f"{path}: pocos elementos")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: demasiados elementos")
        if "items" in schema:
            for i, item in enumerate(instance):
                errors += validate(item, schema["items"], f"{path}[{i}]")
    if isinstance(instance, Mapping):
        props: Mapping[str, Any] = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: falta '{key}'")
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    errors.append(f"{path}: propiedad no permitida '{key}'")
        elif "additionalProperties" in schema:
            raise SchemaError(f"{path}: solo se admite additionalProperties: false")
        for key, sub in props.items():
            if key in instance:
                errors += validate(instance[key], sub, f"{path}.{key}")
    return errors
