"""Configuración de instancia y guardas de licencia (ADR-0022).

El mismo código sirve a tres tipos de instancia:

- `public`: solo fuentes redistribuibles (`open`). Nunca carga un conector `restricted` ni guarda
  un dato `restricted`.
- `clients`: las abiertas y las de pago que tenga licenciadas el operador.
- `third_party`: igual que `clients`, con las licencias de quien la opere.

La configuración vive en `config/instance.*.yaml`. No lleva secretos: si un conector necesita una
clave, la configuración nombra la variable de entorno, nunca el valor.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from vs.sources.base import (
    REGISTRY,
    Connector,
    LicenseClass,
    LicenseError,
    Record,
    Registry,
    check_license,
)


class InstanceKind(StrEnum):
    PUBLIC = "public"
    CLIENTS = "clients"
    THIRD_PARTY = "third_party"


class InstanceConfigError(ValueError):
    """La configuración de instancia no es válida."""


@dataclass(frozen=True)
class ConnectorSpec:
    name: str
    config: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Instance:
    name: str
    kind: InstanceKind
    allowed_license_classes: frozenset[LicenseClass]
    licenses: frozenset[str] = frozenset()
    connectors: tuple[ConnectorSpec, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", InstanceKind(self.kind))
        object.__setattr__(
            self,
            "allowed_license_classes",
            frozenset(LicenseClass(x) for x in self.allowed_license_classes),
        )
        object.__setattr__(self, "licenses", frozenset(self.licenses))
        if self.kind is InstanceKind.PUBLIC and (
            self.allowed_license_classes != {LicenseClass.OPEN} or self.licenses
        ):
            raise InstanceConfigError(
                "una instancia pública solo admite la clase 'open' y no tiene licencias"
            )
        if LicenseClass.OPEN not in self.allowed_license_classes:
            raise InstanceConfigError("toda instancia admite la clase 'open'")
        if self.licenses and LicenseClass.RESTRICTED not in self.allowed_license_classes:
            raise InstanceConfigError("hay licencias declaradas, pero 'restricted' no se admite")
        names = [c.name for c in self.connectors]
        if len(names) != len(set(names)):
            raise InstanceConfigError(f"conectores repetidos: {names}")

    # -- guardas ---------------------------------------------------------------------------------

    def admits(self, license_class: LicenseClass | str, licensee: str | None) -> bool:
        """Si esta instancia puede guardar un dato con esa licencia."""
        lc = LicenseClass(license_class)
        check_license(lc, licensee)
        if lc not in self.allowed_license_classes:
            return False
        return lc is LicenseClass.OPEN or licensee in self.licenses

    def check_connector(self, cls: type[Connector]) -> None:
        """Lanza `LicenseError` si esta instancia no puede cargar el conector."""
        if not self.admits(cls.license_class, cls.licensee):
            raise LicenseError(
                f"la instancia '{self.name}' ({self.kind}) no puede cargar el conector "
                f"'{cls.name}' ({cls.license_class}/{cls.licensee})"
            )

    def build_connectors(self, registry: Registry = REGISTRY) -> list[Connector]:
        """Instancia los conectores activos. Falla antes de crear ninguno si uno no se admite."""
        classes = [(registry.get(spec.name), spec) for spec in self.connectors]
        for cls, _ in classes:
            self.check_connector(cls)
        return [cls(spec.config) for cls, spec in classes]


def _row_license(row: Record | Mapping[str, Any]) -> tuple[str, str | None]:
    if isinstance(row, Record):
        return row.license_class, row.licensee
    return row["license_class"], row.get("licensee")


def audit(instance: Instance, rows: Iterable[Record | Mapping[str, Any]]) -> None:
    """Comprueba lo que hay en el almacenamiento. Falla si alguna fila no se admite.

    Sirve para filas de la base de datos (mapeos con `license_class` y `licensee`) y para
    registros. En una instancia pública, cualquier fila `restricted` la hace fallar.
    """
    bad = []
    for row in rows:
        lc, licensee = _row_license(row)
        try:
            ok = instance.admits(lc, licensee)
        except (LicenseError, ValueError):
            ok = False
        if not ok:
            bad.append((lc, licensee))
    if bad:
        raise LicenseError(f"la instancia '{instance.name}' guarda datos no admitidos: {bad}")


class GuardedStore:
    """Almacenamiento en memoria, solo inserción, que rechaza lo que la instancia no admite.

    Esbozo: en T2 la base de datos real aplica la misma guarda al insertar.
    """

    def __init__(self, instance: Instance) -> None:
        self.instance = instance
        self._rows: list[Record] = []

    def add(self, record: Record) -> None:
        audit(self.instance, [record])
        self._rows.append(record)

    def extend(self, records: Iterable[Record]) -> None:
        for rec in records:
            self.add(rec)

    def rows(self) -> tuple[Record, ...]:
        return tuple(self._rows)


# -- carga ---------------------------------------------------------------------------------------


def parse_instance(data: Mapping[str, Any]) -> Instance:
    try:
        body = data["instance"]
        connectors = tuple(
            ConnectorSpec(name=c["name"], config=dict(c.get("config") or {}))
            for c in body.get("connectors") or []
        )
        return Instance(
            name=body["name"],
            kind=InstanceKind(body["kind"]),
            allowed_license_classes=frozenset(
                LicenseClass(x) for x in body["allowed_license_classes"]
            ),
            licenses=frozenset(body.get("licenses") or []),
            connectors=connectors,
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, InstanceConfigError):
            raise
        raise InstanceConfigError(f"configuración de instancia no válida: {exc}") from exc


def load_instance(path: str | Path) -> Instance:
    with Path(path).open(encoding="utf-8") as fh:
        return parse_instance(yaml.safe_load(fh))
