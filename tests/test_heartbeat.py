"""Latido (PLAN §11, G-7, CMP-033) con cliente simulado y transporte falso. Sin red ni Azure."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vs.heartbeat import (
    FakeHeartbeatClient,
    Heartbeat,
    HeartbeatError,
    LogsIngestionClient,
    ManagedIdentityTokenProvider,
    Outcome,
    emit,
)
from vs.heartbeat.client import MONITOR_SCOPE
from vs.sources.health import SourceHealth, source_health, unknown_sources
from vs.sources.run import RunStatus, SourceRunResult

ROOT = Path(__file__).resolve().parents[1]
# Esquema de referencia de la tabla del latido. La tabla y la DCR las crea la plataforma (ADR-0025);
# este fichero queda como contrato de columnas en infra/bicep-legacy/.
BICEP = ROOT / "infra" / "bicep-legacy" / "platform" / "modules" / "heartbeat.bicep"
T0 = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)
ENDPOINT = "https://dce.example.invalid"
DCR = "dcr-" + "0" * 31 + "1"
STREAM = "Custom-VsHeartbeat_CL"


def run(source: str, minutes: int, status: RunStatus) -> SourceRunResult:
    at = T0 + timedelta(minutes=minutes)
    return SourceRunResult(source, at, at + timedelta(seconds=3), status)


def beat(**kw) -> Heartbeat:
    args = {
        "job": "ingest",
        "run_id": "run-1",
        "outcome": Outcome.OK,
        "started_at": T0,
        "finished_at": T0 + timedelta(seconds=42, milliseconds=5),
    }
    args.update(kw)
    return Heartbeat(**args)


# -- salud de las fuentes -------------------------------------------------------------------------


def test_source_health_tracks_current_streak():
    runs = [
        run("epss", 0, RunStatus.OK),
        run("epss", 5, RunStatus.UNKNOWN),
        run("epss", 10, RunStatus.OK),
        run("epss", 15, RunStatus.UNKNOWN),
        run("epss", 20, RunStatus.UNKNOWN),
        run("cisa-kev", 20, RunStatus.OK),
        run("cisa-kev", 0, RunStatus.OK),  # desordenado a propósito
        run("ghsa", 3, RunStatus.UNKNOWN),
    ]
    health = {h.source: h for h in source_health(runs)}
    assert list(health) == ["cisa-kev", "epss", "ghsa"]
    assert health["epss"].status is RunStatus.UNKNOWN
    assert health["epss"].since == T0 + timedelta(minutes=15)  # racha final, no el primer fallo
    assert health["epss"].last_ok_at == T0 + timedelta(minutes=10, seconds=3)
    assert health["cisa-kev"].since == T0 and not health["cisa-kev"].unknown
    assert health["ghsa"].last_ok_at is None
    assert [h.source for h in unknown_sources(health.values())] == ["epss", "ghsa"]


# -- contenido del latido -------------------------------------------------------------------------


def _bicep_columns() -> list[str]:
    text = BICEP.read_text(encoding="utf-8")
    block = text[text.index("var columns = [") :]
    block = block[: block.index("]")]
    return re.findall(r"name: '(\w+)'", block)


def test_row_matches_dcr_columns():
    """Las columnas del latido son exactamente las de la tabla de G-7."""
    assert sorted(beat().to_row()) == sorted(_bicep_columns())


def test_row_content():
    health = source_health(
        [
            run("epss", 0, RunStatus.UNKNOWN),
            run("osv", 0, RunStatus.UNKNOWN),
            run("ghsa", 0, RunStatus.OK),
        ]
    )
    row = Heartbeat.from_health(
        health,
        job="publish",
        run_id="run-7",
        outcome=Outcome.PARTIAL,
        started_at=T0,
        finished_at=T0 + timedelta(seconds=1, milliseconds=250),
        ai_cost_usd_today=1.2345678,
        version="sha256:" + "a" * 64,
    ).to_row()
    assert row == {
        "TimeGenerated": "2099-03-01T12:00:01.250000Z",
        "Job": "publish",
        "RunId": "run-7",
        "Outcome": "partial",
        "StartedAt": "2099-03-01T12:00:00Z",
        "DurationMs": 1250,
        "UnknownSources": [
            {"source": "epss", "since": "2099-03-01T12:00:00Z"},
            {"source": "osv", "since": "2099-03-01T12:00:00Z"},
        ],
        "AiCostUsdToday": 1.234568,
        "Version": "sha256:" + "a" * 64,
    }
    json.dumps(row)  # serializable tal cual


@pytest.mark.parametrize(
    "kw",
    [
        {"job": "otro"},
        {"run_id": ""},
        {"started_at": datetime(2099, 3, 1, 12, 0)},
        {"finished_at": T0 - timedelta(seconds=1)},
        {"ai_cost_usd_today": -0.1},
        {"ai_cost_usd_today": float("nan")},
        {"unknown_sources": (SourceHealth("epss", RunStatus.OK, T0),)},
        {"version": ""},
    ],
)
def test_invalid_heartbeat_rejected(kw):
    with pytest.raises(ValueError):
        beat(**kw)


# -- envío con el cliente simulado -----------------------------------------------------------------


def test_emit_with_fake_client():
    client = FakeHeartbeatClient()
    assert emit(client, beat()) is True
    assert client.rows == [beat().to_row()]


def test_emit_failure_does_not_crash_job(caplog):
    assert emit(FakeHeartbeatClient(fail=True), beat()) is False
    assert "latido de ingest no enviado" in caplog.text


# -- cliente de la Logs Ingestion API con transporte falso -----------------------------------------


class FakeTokens:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.scopes: list[str] = []

    def token(self, scope: str) -> str:
        self.scopes.append(scope)
        if self.fail:
            raise RuntimeError("detalle interno de la identidad")
        return "token-de-prueba"


class FakePost:
    def __init__(self, status: int = 204, error: Exception | None = None) -> None:
        self.status = status
        self.error = error
        self.calls: list[dict] = []

    def post(self, url, *, headers, body, timeout):
        self.calls.append({"url": url, "headers": headers, "body": body, "timeout": timeout})
        if self.error:
            raise self.error
        return self.status


def client(transport=None, tokens=None) -> LogsIngestionClient:
    return LogsIngestionClient(ENDPOINT + "/", DCR, STREAM, tokens or FakeTokens(), transport)


def test_logs_ingestion_request():
    tokens, transport = FakeTokens(), FakePost()
    c = client(transport, tokens)
    assert emit(c, beat()) is True
    (call,) = transport.calls
    assert call["url"] == (
        f"{ENDPOINT}/dataCollectionRules/{DCR}/streams/{STREAM}?api-version=2023-01-01"
    )
    assert call["headers"] == {
        "Authorization": "Bearer token-de-prueba",
        "Content-Type": "application/json",
    }
    assert json.loads(call["body"]) == [beat().to_row()]  # array JSON, como pide la API
    assert tokens.scopes == [MONITOR_SCOPE] == ["https://monitor.azure.com/.default"]


def test_logs_ingestion_empty_batch_sends_nothing():
    transport = FakePost()
    client(transport).send([])
    assert transport.calls == []


@pytest.mark.parametrize(
    ("transport", "tokens", "message"),
    [
        (FakePost(status=403), FakeTokens(), "HTTP 403"),
        (FakePost(status=500), FakeTokens(), "HTTP 500"),
        (FakePost(error=TimeoutError("lento")), FakeTokens(), "TimeoutError"),
        (FakePost(), FakeTokens(fail=True), "RuntimeError"),
    ],
)
def test_logs_ingestion_errors(transport, tokens, message):
    with pytest.raises(HeartbeatError, match=message) as exc:
        client(transport, tokens).send([beat().to_row()])
    assert "detalle interno" not in str(exc.value)
    assert "token-de-prueba" not in str(exc.value)
    assert emit(client(transport, tokens), beat()) is False


@pytest.mark.parametrize(
    ("endpoint", "dcr", "stream"),
    [
        ("http://dce.example.invalid", DCR, STREAM),
        ("https://dce.example.invalid?x=1", DCR, STREAM),
        (ENDPOINT, "dcr-123", STREAM),
        (ENDPOINT, DCR, "VsHeartbeat_CL"),
        (ENDPOINT, DCR, "Custom-Vs/../x"),
    ],
)
def test_logs_ingestion_config_validated(endpoint, dcr, stream):
    with pytest.raises(ValueError):
        LogsIngestionClient(endpoint, dcr, stream, FakeTokens(), FakePost())


def test_managed_identity_is_interface_only():
    provider = ManagedIdentityTokenProvider("client-id-de-prueba")
    with pytest.raises(NotImplementedError):
        provider.token(MONITOR_SCOPE)
    with pytest.raises(ValueError):
        ManagedIdentityTokenProvider("")
