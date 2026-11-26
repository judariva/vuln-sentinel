"""El modelo y las consultas de métricas (R5), sin base de datos.

Desde la F1a el esquema es el modelo de SQLAlchemy (`vs.model.schema`); el borrador
`schema-draft.sql` se retiró. Estas pruebas son estáticas: parsean las consultas con el parser de
PostgreSQL (pglast) y miran el modelo. Las que ejecutan las consultas contra PostgreSQL de verdad
están en `tests/test_db.py`.
"""

import re
from pathlib import Path

import pglast
from pglast.visitors import Visitor
from sqlalchemy import CheckConstraint

from vs.model import metadata

METRICS = Path(__file__).resolve().parents[1] / "docs" / "metrics"
EXPECTED_QUERIES = {
    "funnel_daily",
    "detection_time_by_level",
    "lead_over_kev",
    "misses",
    "ai_blocked_downgrades",
    "cost_vs_donations_monthly",
}


def queries() -> dict[str, str]:
    text = (METRICS / "queries.sql").read_text(encoding="utf-8")
    parts = re.split(r"^-- name: (\w+)\s*$", text, flags=re.MULTILINE)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def test_donations_table_has_no_donor_data():
    """ADR-0021: la tabla de donaciones no guarda nada que identifique al donante."""
    forbidden = ("name", "email", "ip", "address", "message", "memo", "donor", "payer", "from_")
    columns = [c.name for c in metadata.tables["donation_received"].columns]
    leaked = [c for c in columns if any(f in c for f in forbidden)]
    assert not leaked, f"Columnas que podrían identificar al donante: {leaked}"


LICENSED_TABLES = {"source", "vulnerability", "affected_product", "signal", "ai_call"}
# Tienen columna `source` pero no guardan datos de la fuente, solo su estado operativo.
OPERATIONAL_TABLES = {"source_run"}


def test_source_data_tables_carry_license():
    """ADR-0022: toda tabla con datos de fuentes lleva license_class, licensee y su CHECK."""
    with_source = {t.name for t in metadata.sorted_tables if "source" in t.columns}
    with_source -= OPERATIONAL_TABLES
    assert with_source <= LICENSED_TABLES, f"Tablas con 'source' sin licencia: {with_source}"
    for name in LICENSED_TABLES:
        table = metadata.tables[name]
        assert not table.c.license_class.nullable, name
        assert table.c.license_class.type.name == "license_class", name
        assert table.c.licensee.nullable, name
        checks = {
            c.name: str(c.sqltext) for c in table.constraints if isinstance(c, CheckConstraint)
        }
        check = checks.get(f"{name}_license_ck", "")
        assert "license_class = 'restricted' AND licensee IS NOT NULL" in check, name
        assert "license_class = 'open' AND licensee IS NULL" in check, name


def test_facts_carry_both_timestamps():
    """Todo hecho lleva source_published_at y observed_at."""
    for name in ("vulnerability", "affected_product", "signal", "cost_daily"):
        columns = metadata.tables[name].columns
        assert "source_published_at" in columns and "observed_at" in columns, name
        assert not columns["observed_at"].nullable, name


def test_all_main_metrics_have_a_query():
    assert set(queries()) == EXPECTED_QUERIES


def _bind(sql: str) -> str:
    # pglast no conoce los parámetros con nombre; se sustituyen por un literal para parsear.
    return sql.replace(":day", "'2026-11-18'")


def test_queries_parse():
    for name, sql in queries().items():
        try:
            pglast.parse_sql(_bind(sql))
        except pglast.parser.ParseError as exc:  # pragma: no cover - el mensaje es la ayuda
            raise AssertionError(f"La consulta {name} no parsea: {exc}") from exc


class _Relations(Visitor):
    def __init__(self) -> None:
        super().__init__()
        self.tables: set[str] = set()
        self.ctes: set[str] = set()

    def visit_RangeVar(self, ancestors, node):  # noqa: N802 - nombre impuesto por pglast
        self.tables.add(node.relname)

    def visit_CommonTableExpr(self, ancestors, node):  # noqa: N802
        self.ctes.add(node.ctename)


def test_queries_only_use_declared_tables():
    tables = set(metadata.tables)
    for name, sql in queries().items():
        rel = _Relations()
        for stmt in pglast.parse_sql(_bind(sql)):
            rel(stmt)
        unknown = rel.tables - tables - rel.ctes
        assert not unknown, f"{name} usa tablas que no están en el modelo: {unknown}"
