"""Interfaz común de los conectores de fuentes y su registro (ADR-0022).

Un conector es un plugin: declara su nombre, la licencia de los datos que produce y la
configuración que necesita, y sabe descargar (`fetch`) y normalizar (`normalize`). Añadir uno no
toca el núcleo: basta con registrarlo y activarlo en la configuración de la instancia.

El código de un conector no es el dato de la fuente. Todos los conectores se publican; cada
instancia activa solo aquellos para los que tiene licencia (`vs.instance`).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar


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


@dataclass(frozen=True)
class Record:
    """Un hecho normalizado de una fuente, con la licencia que lo acompaña hasta el feed.

    Corresponde a una fila de `signal` (y, en F1a, de las demás tablas con datos de fuentes).
    """

    source: str
    cve_id: str
    kind: str
    license_class: LicenseClass
    licensee: str | None = None
    value: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "license_class", LicenseClass(self.license_class))
        check_license(self.license_class, self.licensee)


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

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__abstractmethods__", None):
            return
        for attr in ("name", "license_class"):
            if not hasattr(cls, attr):
                raise TypeError(f"el conector {cls.__name__} no declara '{attr}'")
        cls.license_class = LicenseClass(cls.license_class)
        check_license(cls.license_class, cls.licensee)

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self.config: Mapping[str, Any] = dict(config or {})
        missing = [k for k in self.required_config if k not in self.config]
        if missing:
            raise ValueError(f"al conector '{self.name}' le falta configuración: {missing}")

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
