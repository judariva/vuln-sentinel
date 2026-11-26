"""Migraciones y consultas de métricas contra PostgreSQL real (marca `db`).

Se ejecutan si existe `VS_TEST_DATABASE_URL` y se saltan si no. Nunca tocan la base de datos de
esa URL: crean una base de datos desechable al lado, trabajan en ella y la borran al terminar.

En local:
    docker run -d --rm --name vs-pg-test -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17
    VS_TEST_DATABASE_URL=postgresql://postgres:test@localhost:55432/postgres uv run pytest -m db
    docker stop vs-pg-test
"""

import os
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from tests.test_metrics_sql import queries
from vs.model import metadata
from vs.model.migrate import downgrade, normalize_url, upgrade

URL = os.environ.get("VS_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URL, reason="sin VS_TEST_DATABASE_URL"),
]

ENUM_TYPES = {"alert_level", "impact_class", "run_status", "license_class"}
DAY = date(2026, 11, 18)


def _at(hour: int, minute: int = 0, day: date = DAY) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=UTC)


@pytest.fixture(scope="module")
def db_url():
    admin_url = make_url(normalize_url(URL))
    name = f"vs_test_{uuid.uuid4().hex[:12]}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = admin_url.set(database=name).render_as_string(hide_password=False)
    try:
        yield url
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def migrated(db_url):
    upgrade(db_url)
    engine = create_engine(db_url)
    try:
        yield engine
    finally:
        engine.dispose()
        downgrade(db_url)


def _enum_types(conn) -> set[str]:
    rows = conn.execute(text("SELECT typname FROM pg_type WHERE typtype = 'e'"))
    return {r[0] for r in rows}


def _user_tables(conn) -> set[str]:
    return set(inspect(conn).get_table_names()) - {"alembic_version"}


def test_upgrade_and_downgrade(db_url):
    upgrade(db_url)
    engine = create_engine(db_url)
    try:
        with engine.connect() as conn:
            assert _user_tables(conn) == set(metadata.tables)
            assert _enum_types(conn) >= ENUM_TYPES
        downgrade(db_url)
        with engine.connect() as conn:
            assert _user_tables(conn) == set()
            assert not (ENUM_TYPES & _enum_types(conn))
        # Y se puede volver a subir sobre una base limpia.
        upgrade(db_url)
        downgrade(db_url)
    finally:
        engine.dispose()


def test_migration_matches_model(migrated):
    """La migración y el modelo no divergen: autogenerate no encuentra diferencias."""
    with migrated.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(ctx, metadata)
    assert diff == [], diff


def _seed_source(conn) -> None:
    conn.execute(
        text(
            "INSERT INTO source (name, freshness_threshold, license_class)"
            " VALUES ('cvelist', interval '1 hour', 'open'), ('kev', interval '1 hour', 'open')"
        )
    )


@pytest.mark.parametrize(
    ("license_class", "licensee", "ok"),
    [
        ("open", None, True),
        ("restricted", "lic-1", True),
        ("open", "lic-1", False),
        ("restricted", None, False),
    ],
)
def test_license_check(migrated, license_class, licensee, ok):
    """ADR-0022: el CHECK de licencia vive en la base de datos, no solo en el código."""
    sql = text(
        "INSERT INTO source (name, freshness_threshold, license_class, licensee)"
        " VALUES ('x', interval '1 hour', :lc, :licensee)"
    )
    with migrated.connect() as conn:
        if ok:
            conn.execute(sql, {"lc": license_class, "licensee": licensee})
        else:
            with pytest.raises(IntegrityError, match="source_license_ck"):
                conn.execute(sql, {"lc": license_class, "licensee": licensee})
        conn.rollback()


def test_donation_amount_must_be_positive(migrated):
    with migrated.connect() as conn, pytest.raises(IntegrityError):
        conn.execute(
            text(
                "INSERT INTO donation_received"
                " (channel, amount_sats, received_at, observed_at, external_ref)"
                " VALUES ('onchain', 0, now(), now(), 'ref-0')"
            )
        )


def _seed_metrics(conn) -> None:
    """Datos sintéticos (CVE ficticias) para el día DAY."""
    _seed_source(conn)
    vulns = [
        # cve_id, baseline, observed_at
        ("CVE-2099-0001", False, _at(8)),
        ("CVE-2099-0002", False, _at(8, 30)),
        ("CVE-2099-0003", True, _at(1)),  # carga inicial: no cuenta como ingerida
        ("CVE-2099-0004", False, _at(7)),
    ]
    for cve, baseline, observed in vulns:
        conn.execute(
            text(
                "INSERT INTO vulnerability (cve_id, impact_class, source_published_at,"
                " observed_at, baseline, source, license_class)"
                " VALUES (:cve, 'rce', :pub, :obs, :baseline, 'cvelist', 'open')"
            ),
            {
                "cve": cve,
                "pub": observed - timedelta(hours=2),
                "obs": observed,
                "baseline": baseline,
            },
        )
    for cve in ("CVE-2099-0001", "CVE-2099-0004"):
        conn.execute(
            text(
                "INSERT INTO affected_product (cve_id, vendor, product, range_source, category,"
                " source_published_at, observed_at, source, license_class)"
                " VALUES (:cve, 'acme', 'webd', 'cna', 'web_server', :at, :at, 'cvelist', 'open')"
            ),
            {"cve": cve, "at": _at(8)},
        )
    signal_ids = {}
    for key, cve, kind, published, observed in [
        ("exploit1", "CVE-2099-0001", "exploit", _at(8, 45), _at(8, 50)),
        ("kev1", "CVE-2099-0001", "kev_cisa", None, _at(12)),
        ("kev4", "CVE-2099-0004", "kev_cisa", None, _at(13)),
    ]:
        signal_ids[key] = conn.execute(
            text(
                "INSERT INTO signal (cve_id, kind, value, source, source_published_at,"
                " observed_at, license_class)"
                " VALUES (:cve, :kind, '{}', 'kev', :pub, :obs, 'open') RETURNING id"
            ),
            {"cve": cve, "kind": kind, "pub": published, "obs": observed},
        ).scalar_one()
    for cve, at, eligible, exposed, impact, level in [
        ("CVE-2099-0001", _at(8, 5), True, True, "rce", "none"),
        ("CVE-2099-0001", _at(9), True, True, "rce", "B"),  # la última del día cuenta
        ("CVE-2099-0002", _at(8, 35), True, False, "other", "none"),
        ("CVE-2099-0004", _at(7, 5), False, True, "rce", "none"),
    ]:
        conn.execute(
            text(
                "INSERT INTO rule_evaluation (cve_id, evaluated_at, eligible, exposed,"
                " impact_class, result_level, rules_version)"
                " VALUES (:cve, :at, :eligible, :exposed, :impact, :level, 'test')"
            ),
            {
                "cve": cve,
                "at": at,
                "eligible": eligible,
                "exposed": exposed,
                "impact": impact,
                "level": level,
            },
        )
    conn.execute(
        text(
            "INSERT INTO alert (alert_id, cve_id, level, reason, status, first_published_at,"
            " modified_at) VALUES ('VS-CVE-2099-0001', 'CVE-2099-0001', 'B', '{E1}',"
            " 'published', :first, :mod)"
        ),
        {"first": _at(9), "mod": _at(10)},
    )
    for level_from, level_to, signal, at in [
        ("none", "C", None, _at(9)),
        ("C", "B", signal_ids["exploit1"], _at(10)),
    ]:
        conn.execute(
            text(
                "INSERT INTO alert_level_history (alert_id, level_from, level_to, reason,"
                " trigger_signal_id, decided_by, at)"
                " VALUES ('VS-CVE-2099-0001', :f, :t, '{test}', :sig, 'rules', :at)"
            ),
            {"f": level_from, "t": level_to, "sig": signal, "at": at},
        )
    conn.execute(
        text(
            "INSERT INTO ai_call (alert_id, kind, model, proposed_level, final_level, tokens_in,"
            " tokens_out, cost_usd, blocked_downgrade, at, license_class)"
            " VALUES ('VS-CVE-2099-0001', 'agent', 'test-model', 'none', 'B', 100, 50, 0.01,"
            " true, :at, 'open')"
        ),
        {"at": _at(9, 30)},
    )
    conn.execute(
        text(
            "INSERT INTO cost_daily (day, provider, service, amount_eur, observed_at) VALUES"
            " ('2026-11-01', 'azure', 'postgres', 10.5, now()),"
            " ('2026-11-02', 'cloudflare', '', 1.25, now()),"
            " ('2026-10-31', 'azure', 'postgres', 99, now())"
        )
    )
    conn.execute(
        text(
            "INSERT INTO donation_received (channel, amount_sats, received_at, observed_at,"
            " external_ref) VALUES ('onchain', 21000, :at, :at, 'txid-ficticio')"
        ),
        {"at": _at(15)},
    )


def test_metric_queries_run_against_migrated_schema(migrated):
    """Las consultas de docs/metrics/queries.sql se ejecutan y dan lo esperado (R5)."""
    with migrated.connect() as conn:
        _seed_metrics(conn)
        results = {
            name: conn.execute(text(sql), {"day": DAY}).mappings().all()
            for name, sql in queries().items()
        }
        conn.rollback()

    funnel = results["funnel_daily"][0]
    assert dict(funnel) == {
        "ingested": 3,
        "eligible": 2,
        "candidates": 1,
        "level_a": 0,
        "level_b": 1,
        "level_c": 0,
    }

    detection = {r["level"]: r for r in results["detection_time_by_level"]}
    assert set(detection) == {"C", "B"}
    # C: 09:00 menos la publicación de la CVE (06:00) = 3 h. B: 10:00 menos la señal (08:45).
    assert detection["C"]["p50_seconds"] == 3 * 3600
    assert detection["B"]["p50_seconds"] == 75 * 60

    lead = results["lead_over_kev"]
    assert [r["cve_id"] for r in lead] == ["CVE-2099-0001"]
    assert float(lead[0]["lead_hours"]) == 3.0  # KEV 12:00, primera B/C 09:00

    assert [r["cve_id"] for r in results["misses"]] == ["CVE-2099-0004"]

    cost = results["cost_vs_donations_monthly"]
    assert len(cost) == 1
    assert float(cost[0]["cost_eur"]) == 11.75
    assert cost[0]["received_sats"] == 21000
    assert cost[0]["donations"] == 1

    assert results["ai_blocked_downgrades"][0]["blocked"] == 1
