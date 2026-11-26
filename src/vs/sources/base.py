"""Interfaz común de los conectores de fuentes y su registro (ADR-0022).

Un conector es un plugin: declara su nombre, la licencia de los datos que produce y la
configuración que necesita, y sabe descargar (`fetch`) y normalizar (`normalize`). Añadir uno no
toca el núcleo: basta con registrarlo y activarlo en la configuración de la instancia.

El código de un conector no es el dato de la fuente. Todos los conectores se publican; cada
instancia activa solo aquellos para los que tiene licencia (`vs.instance`).
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from vs.sources.http import Transport


class LicenseClass(StrEnum):
    """Qué se puede hacer con un dato según la licencia de su fuente."""

    OPEN = "open"  # redistribuible en un feed público
    RESTRICTED = "restricted"  # solo para quien tenga la licencia indicada en `licensee`


class LicenseError(ValueError):
    """Un dato o un conector no cumple las reglas de licencia."""


def check_license(license_class: LicenseClass, licensee: str | None) -> None:
    """Misma regla que el CHECK del esquema: `restricted` exige `licensee`; `open` lo prohíbe."""
    if license_class is LicenseClass.RESTRICTED and not licensee:
        raise LicenseError("un dato 'restricted' necesita 'licensee'")
    if license_class is LicenseClass.OPEN and licensee is not None:
        raise LicenseError("un dato 'open' no lleva 'licensee'")


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def is_cve_id(value: Any) -> bool:
    return isinstance(value, str) and CVE_RE.fullmatch(value) is not None


class Entity(StrEnum):
    """Tabla del modelo (T2) a la que va un registro."""

    VULNERABILITY = "vulnerability"
    AFFECTED_PRODUCT = "affected_product"
    SIGNAL = "signal"


# Columnas que un registro rellena en cada tabla. `id` y las columnas que calculan las reglas
# (p. ej. `impact_class`, `category`) no salen de un conector. Un test las contrasta con el modelo.
ENTITY_COLUMNS: dict[Entity, frozenset[str]] = {
    Entity.VULNERABILITY: frozenset(
        {
            "cve_id",
            "cna",
            "cvss_vector",
            "cvss_source",
            "cwe",
            "vendor",
            "product",
            "source_published_at",
            "observed_at",
            "withdrawn_at",
            "baseline",
            "source",
            "license_class",
            "licensee",
        }
    ),
    Entity.AFFECTED_PRODUCT: frozenset(
        {
            "cve_id",
            "vendor",
            "product",
            "cpe",
            "purl",
            "ecosystem",
            "ranges",
            "range_source",
            "source_published_at",
            "observed_at",
            "source",
            "license_class",
            "licensee",
        }
    ),
    Entity.SIGNAL: frozenset(
        {
            "cve_id",
            "kind",
            "value",
            "source",
            "url",
            "baseline",
            "source_published_at",
            "observed_at",
            "license_class",
            "licensee",
        }
    ),
}

# Lo que va en `value` y se reparte en columnas (vulnerability, affected_product).
_FLAT_ENTITIES = (Entity.VULNERABILITY, Entity.AFFECTED_PRODUCT)
_STAMPED = {
    "cve_id",
    "source",
    "license_class",
    "licensee",
    "observed_at",
    "baseline",
    "source_published_at",
}


@dataclass(frozen=True)
class Record:
    """Un hecho normalizado de una fuente, con la licencia que lo acompaña hasta el feed.

    `entity` dice a qué tabla del modelo va. En `signal`, `kind` es el tipo de señal y `value` su
    contenido (JSONB). En `vulnerability` y `affected_product`, `value` lleva las columnas propias
    de la tabla. `observed_at` y `baseline` los sella el ejecutor (`vs.sources.run`), no el
    conector: la fuente no sabe cuándo la vimos ni si es la carga inicial (ADR-0012).
    """

    source: str
    cve_id: str
    kind: str
    license_class: LicenseClass
    licensee: str | None = None
    value: Mapping[str, Any] = field(default_factory=dict)
    entity: Entity = Entity.SIGNAL
    source_published_at: datetime | None = None
    observed_at: datetime | None = None
    baseline: bool = False
    url: str | None = None
    # Licencia CC-BY-SA en origen (OSV de Ubuntu y Alpine): pendiente de revisión legal (ADR-0020).
    share_alike: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "license_class", LicenseClass(self.license_class))
        object.__setattr__(self, "entity", Entity(self.entity))
        check_license(self.license_class, self.licensee)
        if self.entity in _FLAT_ENTITIES:
            extra = set(self.value) - ENTITY_COLUMNS[self.entity] | (set(self.value) & _STAMPED)
            if extra:
                raise ValueError(f"columnas no válidas para {self.entity}: {sorted(extra)}")

    def key(self) -> tuple[str, str, str, str, str]:
        """Identidad del hecho, para saber si ya se había visto (`items_new`)."""
        body = json.dumps(self.value, sort_keys=True, default=str)
        return (self.source, self.entity.value, self.cve_id, self.kind, body)

    def to_row(self) -> dict[str, Any]:
        """Fila de la tabla `entity` del modelo. Exige `observed_at` (lo sella el ejecutor)."""
        if self.observed_at is None:
            raise ValueError("registro sin 'observed_at': no ha pasado por el ejecutor")
        row: dict[str, Any] = {
            "cve_id": self.cve_id,
            "source": self.source,
            "license_class": self.license_class,
            "licensee": self.licensee,
            "observed_at": self.observed_at,
            "source_published_at": self.source_published_at,
        }
        if self.entity is Entity.SIGNAL:
            row.update(kind=self.kind, value=dict(self.value), url=self.url, baseline=self.baseline)
        else:
            row.update(self.value)
            if self.entity is Entity.VULNERABILITY:
                row["baseline"] = self.baseline
        return row


class Connector(ABC):
    """Base de todos los conectores.

    Las subclases fijan `name`, `license_class`, `licensee` y `required_config`, e implementan
    `fetch()` y `normalize()`. El núcleo solo llama a `records()`, que sella cada registro con la
    licencia declarada por el conector: un conector no puede emitir datos con otra licencia.
    """

    name: ClassVar[str]
    license_class: ClassVar[LicenseClass]
    licensee: ClassVar[str | None] = None
    required_config: ClassVar[tuple[str, ...]] = ()
    # Antigüedad máxima del dato antes de dar la fuente por UNKNOWN (fail-closed). Se puede
    # cambiar por instancia con `freshness_hours` en la configuración del conector.
    freshness_threshold: ClassVar[timedelta | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__abstractmethods__", None):
            return
        for attr in ("name", "license_class"):
            if not hasattr(cls, attr):
                raise TypeError(f"el conector {cls.__name__} no declara '{attr}'")
        cls.license_class = LicenseClass(cls.license_class)
        check_license(cls.license_class, cls.licensee)

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        transport: Transport | None = None,
    ) -> None:
        self.config: Mapping[str, Any] = dict(config or {})
        missing = [k for k in self.required_config if k not in self.config]
        if missing:
            raise ValueError(f"al conector '{self.name}' le falta configuración: {missing}")
        self._transport = transport
        # Cursor: lo fija el ejecutor antes de `fetch()`. None = carga inicial.
        self.since: datetime | None = None
        # Fecha del dato según la fuente; la fija `fetch()`. El ejecutor la compara con el umbral.
        self.data_as_of: datetime | None = None
        # Contadores informativos del conector (excluidos por licencia, sin CVE, …).
        self.stats: dict[str, int] = {}

    @property
    def transport(self) -> Transport:
        if self._transport is None:
            from vs.sources.http import UrllibTransport

            self._transport = UrllibTransport()
        return self._transport

    def threshold(self) -> timedelta | None:
        hours = self.config.get("freshness_hours")
        if hours is not None:
            return timedelta(hours=float(hours))
        return self.freshness_threshold

    def count(self, stat: str, n: int = 1) -> None:
        self.stats[stat] = self.stats.get(stat, 0) + n

    @abstractmethod
    def fetch(self) -> Iterable[Any]:
        """Descarga los datos en bruto de la fuente."""

    @abstractmethod
    def normalize(self, raw: Any) -> Iterable[Record]:
        """Convierte un dato en bruto en registros normalizados."""

    def records(self) -> Iterator[Record]:
        """Descarga, normaliza y comprueba que cada registro lleva la licencia del conector."""
        for raw in self.fetch():
            for rec in self.normalize(raw):
                if rec.source != self.name:
                    raise LicenseError(
                        f"'{self.name}' emitió un registro de otra fuente: '{rec.source}'"
                    )
                if (rec.license_class, rec.licensee) != (self.license_class, self.licensee):
                    raise LicenseError(
                        f"'{self.name}' emitió un registro con otra licencia: "
                        f"{rec.license_class}/{rec.licensee}"
                    )
                yield rec


class Registry:
    """Registro de conectores por nombre."""

    def __init__(self) -> None:
        self._by_name: dict[str, type[Connector]] = {}

    def register(self, cls: type[Connector]) -> type[Connector]:
        """Registra un conector. Se puede usar como decorador."""
        if cls.name in self._by_name and self._by_name[cls.name] is not cls:
            raise ValueError(f"ya hay un conector registrado con el nombre '{cls.name}'")
        self._by_name[cls.name] = cls
        return cls

    def get(self, name: str) -> type[Connector]:
        try:
            return self._by_name[name]
        except KeyError:
            raise KeyError(f"conector no registrado: '{name}'") from None

    def names(self) -> list[str]:
        return sorted(self._by_name)


REGISTRY = Registry()
"""Registro por defecto. Los conectores reales (F1a) se registran aquí al importarse."""

register = REGISTRY.register
