"""El esquema y las consultas de métricas son SQL válido de PostgreSQL (R5).

En F0 solo se parsean con el parser de PostgreSQL (pglast). Desde F1a se ejecutan contra una base
de datos real en CI.
"""

import re
from pathlib import Path

import pglast
from pglast.visitors import Visitor

METRICS = Path(__file__).resolve().parents[1] / "docs" / "metrics"
EXPECTED_QUERIES = {
    "funnel_daily",
    "detection_time_by_level",
    "lead_over_kev",
    "misses",
    "ai_blocked_downgrades",
}


def _queries() -> dict[str, str]:
    text = (METRICS / "queries.sql").read_text(encoding="utf-8")
    parts = re.split(r"^-- name: (\w+)\s*$", text, flags=re.MULTILINE)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def _bind(sql: str) -> str:
    # pglast no conoce los parámetros con nombre; se sustituyen por un literal para parsear.
    return sql.replace(":day", "'2026-11-18'")


def test_schema_parses():
    pglast.parse_sql((METRICS / "schema-draft.sql").read_text(encoding="utf-8"))


def test_all_main_metrics_have_a_query():
    assert set(_queries()) == EXPECTED_QUERIES


def test_queries_parse():
    for name, sql in _queries().items():
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
    schema = (METRICS / "schema-draft.sql").read_text(encoding="utf-8")
    tables = set(re.findall(r"CREATE TABLE (\w+)", schema))
    for name, sql in _queries().items():
        rel = _Relations()
        for stmt in pglast.parse_sql(_bind(sql)):
            rel(stmt)
        unknown = rel.tables - tables - rel.ctes
        assert not unknown, f"{name} usa tablas que no están en el esquema: {unknown}"
