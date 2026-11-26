"""Listas que usan las reglas: productos expuestos y autores de exploits de confianza.

Se leen con el formato que generan los scripts de `vs.lists` (F1a-0, R7). Solo cuentan las
secciones aprobadas: `products`, `deployment_leg.products` (si está activa; criterio v4) y
`authors`. Lo que está en `needs_review` o `below_threshold` no
decide nada hasta que Juan lo revise.

Las reglas no saben de dónde salen las listas: los tests usan listas de fixture
(`tests/fixtures/lists/`) y producción, las de `config/`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def norm(value: Any) -> str:
    """Comparación sin mayúsculas ni espacios sobrantes."""
    return " ".join(str(value or "").split()).casefold()


def purl_base(purl: str | None) -> str:
    """`pkg:npm/%40scope/x@1.2?a=b#c` → `pkg:npm/%40scope/x`: sin versión, calificadores ni ruta."""
    if not purl:
        return ""
    base = purl.split("#", 1)[0].split("?", 1)[0]
    # La versión va tras la última `@` del nombre; un `@` en el espacio de nombres va codificado.
    head, sep, _version = base.rpartition("@")
    if sep and "/" in head:
        base = head
    return base.casefold()


@dataclass(frozen=True)
class ExposedProduct:
    id: str
    category: str
    names: frozenset[tuple[str, str]]  # (vendor, product) normalizados, incluidos los alias
    cpe_prefixes: tuple[str, ...]
    purls: frozenset[str]


@dataclass(frozen=True)
class TrustedAuthor:
    name: str
    # Cuentas de GitHub del autor. Si la lista no las trae, se compara con el nombre (ver
    # `RuleLists.trusted_account`).
    github: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RuleLists:
    exposed: tuple[ExposedProduct, ...] = ()
    authors: tuple[TrustedAuthor, ...] = ()
    _accounts: frozenset[str] = field(default=frozenset(), repr=False)

    def __post_init__(self) -> None:
        accounts: set[str] = set()
        for a in self.authors:
            accounts |= {norm(g) for g in a.github} if a.github else {norm(a.name)}
        object.__setattr__(self, "_accounts", frozenset(accounts))

    def trusted_account(self, account: str | None) -> bool:
        """¿La cuenta dueña de un repositorio está en la lista de autores de confianza?

        Con `github` en la entrada, se compara con esas cuentas; sin él, con el nombre. Cómo se
        relacionan nombres y cuentas está abierto (pregunta 2 del PR de las listas).
        """
        return bool(account) and norm(account) in self._accounts


EMPTY_LISTS = RuleLists()


def _exposed(item: Mapping[str, Any]) -> ExposedProduct:
    names = {(norm(item.get("vendor")), norm(item.get("product")))}
    for alias in item.get("aliases") or []:
        if isinstance(alias, Mapping):
            names.add((norm(alias.get("vendor")), norm(alias.get("product"))))
    names = {n for n in names if n[1]}
    return ExposedProduct(
        id=str(item["id"]),
        category=str(item["category"]),
        names=frozenset(names),
        cpe_prefixes=tuple(sorted(norm(c) for c in item.get("cpe") or [] if c)),
        purls=frozenset(purl_base(p) for p in item.get("purl") or [] if p),
    )


def _deployment(item: Mapping[str, Any]) -> ExposedProduct:
    """Entrada de `deployment_leg` (criterio v4): casa por sus pares del CNA y sus prefijos CPE.

    No tiene `vendor`/`product` propios: su nombre sale de la cabecera `Server`. Sin pares ni CPE,
    no casa nada.
    """
    names = {
        (norm(c.get("vendor")), norm(c.get("product")))
        for c in item.get("cna") or []
        if isinstance(c, Mapping)
    }
    return ExposedProduct(
        id=str(item["id"]),
        category=str(item["category"]),
        names=frozenset(n for n in names if n[1]),
        cpe_prefixes=tuple(sorted(norm(c) for c in item.get("cpe") or [] if c)),
        purls=frozenset(),
    )


def _author(item: Mapping[str, Any]) -> TrustedAuthor:
    gh = item.get("github") or []
    if isinstance(gh, str):
        gh = [gh]
    return TrustedAuthor(name=str(item["name"]), github=frozenset(str(g) for g in gh))


def parse_lists(
    exposed_doc: Mapping[str, Any] | None, authors_doc: Mapping[str, Any] | None
) -> RuleLists:
    products = (exposed_doc or {}).get("products") or []
    categories = set((exposed_doc or {}).get("categories") or [])
    exposed = []
    for p in products:
        if categories and p.get("category") not in categories:
            raise ValueError(f"producto {p.get('id')!r} con categoría desconocida")
        exposed.append(_exposed(p))
    # Criterio v4: la pata de despliegue activa también es `producto_expuesto`.
    leg = (exposed_doc or {}).get("deployment_leg") or {}
    if leg.get("status") == "active":
        for p in leg.get("products") or []:
            if categories and p.get("category") not in categories:
                raise ValueError(f"producto {p.get('id')!r} con categoría desconocida")
            exposed.append(_deployment(p))
    authors = [_author(a) for a in (authors_doc or {}).get("authors") or []]
    return RuleLists(
        exposed=tuple(sorted(exposed, key=lambda e: e.id)),
        authors=tuple(authors),
    )


def load_lists(exposed_path: Path, authors_path: Path) -> RuleLists:
    return parse_lists(
        yaml.safe_load(exposed_path.read_text(encoding="utf-8")),
        yaml.safe_load(authors_path.read_text(encoding="utf-8")),
    )


@dataclass(frozen=True)
class ProductRef:
    """Lo que dice una CVE de un producto: vendor/product del CNA, CPE o purl."""

    vendor: str | None = None
    product: str | None = None
    cpe: str | None = None
    purl: str | None = None


def _cpe_matches(cpe: str, prefix: str) -> bool:
    return cpe == prefix or cpe.startswith(prefix + ":")


def producto_expuesto(refs: Iterable[ProductRef], lists: RuleLists) -> ExposedProduct | None:
    """Primer producto de la lista (por `id`) que coincide con alguna referencia, o None (§5.2)."""
    names: set[tuple[str, str]] = set()
    cpes: set[str] = set()
    purls: set[str] = set()
    for r in refs:
        if r.product:
            names.add((norm(r.vendor), norm(r.product)))
        if r.cpe:
            cpes.add(norm(r.cpe))
        if r.purl:
            purls.add(purl_base(r.purl))
    for e in lists.exposed:
        if names & e.names:
            return e
        if any(_cpe_matches(c, p) for c in cpes for p in e.cpe_prefixes):
            return e
        if purls & e.purls:
            return e
    return None
