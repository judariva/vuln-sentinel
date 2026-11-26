"""Vigilante externo (PLAN §11, CMP-013, CTL-023) con un feed de fixture y sin red.

La clave de firma se genera en cada test y no se guarda. El índice de fixture es ficticio
(CVE-2099-*); los hosts son `.invalid`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from vs import watchdog
from vs.feed.osv import canonical_bytes
from vs.feed.sign import LocalDevSigner, jwks, sign_detached
from vs.sources.http import Response, SourceError

ROOT = Path(__file__).resolve().parents[1]
HEAD = json.loads((ROOT / "tests" / "fixtures" / "watchdog" / "head.json").read_text("utf-8"))
SCHEMA = json.loads((ROOT / "schema" / "feed-1.0.0.json").read_text(encoding="utf-8"))
NOW = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)
BASE = "https://feed.example.invalid"


@pytest.fixture(scope="module")
def signer() -> LocalDevSigner:
    return LocalDevSigner.generate("watchdog-test")


def doc(**changes) -> dict:
    d = json.loads(json.dumps(HEAD))
    for k, v in changes.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return d


def signed(d: dict, signer: LocalDevSigner) -> tuple[bytes, str]:
    body = canonical_bytes(d)
    return body, sign_detached(body, signer)


def codes(findings) -> list[str]:
    return sorted(f.code for f in findings)


# -- el fixture es un índice «head» válido según el contrato --------------------------------------


def test_fixture_matches_feed_schema():
    v = Draft202012Validator(
        {"$ref": "#/$defs/changes_page", "$defs": SCHEMA["$defs"]}, format_checker=FormatChecker()
    )
    errors = list(v.iter_errors(HEAD))
    assert not errors, [e.message for e in errors]


def test_schema_rejects_status_on_sealed_page_and_half_status():
    v = Draft202012Validator({"$ref": "#/$defs/changes_page", "$defs": SCHEMA["$defs"]})
    sealed = {k: HEAD[k] for k in ("schema_version", "kind", "feed", "entries")}
    sealed.update(sealed=True, hour="2099-03-01T11", modified=HEAD["modified"])
    sealed["sources"] = HEAD["sources"]
    assert list(v.iter_errors(sealed))
    assert list(v.iter_errors(doc(sources=None)))


# -- los cuatro casos de la tarea -----------------------------------------------------------------


def test_valid_signature_fresh_feed_passes(signer):
    body, jws = signed(doc(), signer)
    assert watchdog.check_head(body, jws, jwks([signer]), NOW) == []


def test_broken_signature_fails(signer):
    body, jws = signed(doc(), signer)
    tampered = body.replace(b'"level":"B"', b'"level":"A"')
    assert tampered != body
    assert codes(watchdog.check_head(tampered, jws, jwks([signer]), NOW)) == ["signature"]
    # Firma con otra clave que tenga el mismo kid: tampoco vale.
    other = LocalDevSigner.generate("watchdog-test")
    assert codes(watchdog.check_head(body, sign_detached(body, other), jwks([signer]), NOW)) == [
        "signature"
    ]
    # Basura en lugar del JWS.
    assert codes(watchdog.check_head(body, "no-es-un-jws", jwks([signer]), NOW)) == ["signature"]


def test_broken_signature_hides_content_checks(signer):
    """Con la firma rota no se informa nada del contenido: no es de fiar."""
    body, jws = signed(doc(modified="2099-01-01T00:00:00Z"), signer)
    other = jwks([LocalDevSigner.generate("watchdog-test")])
    assert codes(watchdog.check_head(body, jws, other, NOW)) == ["signature"]


def test_old_feed_fails(signer):
    body, jws = signed(doc(modified="2099-03-01T11:30:00Z"), signer)  # justo 30 min
    findings = watchdog.check_head(body, jws, jwks([signer]), NOW)
    assert codes(findings) == ["stale"]
    assert "30 min" in str(findings[0])
    body, jws = signed(doc(modified="2099-03-01T11:30:01Z"), signer)
    assert watchdog.check_head(body, jws, jwks([signer]), NOW) == []


def test_source_unknown_too_long_fails(signer):
    sources = [
        *HEAD["sources"][:2],
        {"name": "epss", "status": "unknown", "since": "2099-03-01T09:59:00Z"},
    ]
    body, jws = signed(doc(sources=sources), signer)
    findings = watchdog.check_head(body, jws, jwks([signer]), NOW)
    assert codes(findings) == ["source_unknown"]
    assert "epss" in str(findings[0])
    # Una fuente en UNKNOWN menos de 2 h (la del fixture, 1 h) no es un fallo.
    body, jws = signed(doc(), signer)
    assert watchdog.check_head(body, jws, jwks([signer]), NOW) == []


# -- fail-closed ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"modified": None, "sources": None}, ["no_status", "no_status"]),
        ({"sources": []}, ["no_status"]),
        ({"modified": "ayer"}, ["no_status"]),
        ({"modified": "2099-03-01T12:30:00Z"}, ["clock"]),
        ({"sealed": True}, ["malformed"]),
        ({"feed": "alerts"}, ["malformed"]),
        ({"sources": [{"name": "epss", "status": "unknown"}]}, ["source_unknown"]),
        (
            {"sources": [{"name": "epss", "status": "rara", "since": "2099-03-01T11:00:00Z"}]},
            ["malformed"],
        ),
        ({"sources": ["epss"]}, ["malformed"]),
    ],
)
def test_incomplete_or_odd_head_fails(signer, changes, expected):
    body, jws = signed(doc(**changes), signer)
    assert codes(watchdog.check_head(body, jws, jwks([signer]), NOW)) == expected


def test_signed_non_json_fails(signer):
    body = b"<html>mantenimiento</html>"
    assert codes(watchdog.check_head(body, sign_detached(body, signer), jwks([signer]), NOW)) == [
        "malformed"
    ]


# -- lectura por HTTP (transporte simulado) -------------------------------------------------------


class FakeTransport:
    def __init__(self, routes: dict[str, list[Response] | Response | Exception]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url, *, headers=None, timeout=None):
        assert url.startswith(BASE + "/")
        path = url[len(BASE) :]
        self.calls.append(path)
        route = self.routes[path]
        if isinstance(route, Exception):
            raise route
        if isinstance(route, list):
            return route.pop(0) if len(route) > 1 else route[0]
        return route


def routes(signer, d=None, keys=True) -> dict:
    body, jws = signed(d or doc(), signer)
    r = {
        watchdog.HEAD_PATH: Response(200, body),
        watchdog.HEAD_PATH + ".jws": Response(200, jws.encode()),
    }
    if keys:
        r[watchdog.KEYS_PATH] = Response(200, json.dumps(jwks([signer])).encode())
    return r


def test_run_checks_with_published_keys(signer):
    t = FakeTransport(routes(signer))
    assert watchdog.run_checks(BASE, t, lambda: NOW, sleep=lambda _s: None) == []
    assert t.calls == [watchdog.KEYS_PATH, watchdog.HEAD_PATH, watchdog.HEAD_PATH + ".jws"]


def test_pinned_key_detects_swapped_published_key(signer):
    """Si alguien cambia la clave publicada y firma con ella, la clave fijada lo detecta."""
    attacker = LocalDevSigner.generate("watchdog-test")
    t = FakeTransport(routes(attacker))
    assert watchdog.run_checks(BASE, t, lambda: NOW, sleep=lambda _s: None) == []
    findings = watchdog.run_checks(
        BASE, t, lambda: NOW, pinned_jwks=jwks([signer]), sleep=lambda _s: None
    )
    assert codes(findings) == ["signature"]


def test_signature_race_is_retried_then_passes(signer):
    """El .json y el .jws de instantes distintos: se reintenta y el segundo intento casa."""
    good_body, good_jws = signed(doc(), signer)
    old_body, _ = signed(doc(generated_at="2099-03-01T11:59:00Z"), signer)
    t = FakeTransport(
        {
            watchdog.HEAD_PATH: [Response(200, old_body), Response(200, good_body)],
            watchdog.HEAD_PATH + ".jws": Response(200, good_jws.encode()),
        }
    )
    pauses = []
    findings = watchdog.run_checks(
        BASE, t, lambda: NOW, pinned_jwks=jwks([signer]), sleep=pauses.append
    )
    assert findings == [] and len(pauses) == 1


def test_persistent_bad_signature_fails_after_all_attempts(signer):
    r = routes(signer, keys=False)
    r[watchdog.HEAD_PATH] = Response(200, canonical_bytes(doc(has_more=True)))
    t = FakeTransport(r)
    findings = watchdog.run_checks(
        BASE, t, lambda: NOW, pinned_jwks=jwks([signer]), sleep=lambda _s: None
    )
    assert codes(findings) == ["signature"]
    assert t.calls.count(watchdog.HEAD_PATH) == watchdog.ATTEMPTS


@pytest.mark.parametrize(
    "failure",
    [Response(503, b"down"), Response(404, b""), SourceError(f"error de red en {BASE}/x")],
)
def test_unreachable_feed_fails_without_leaking_url(signer, failure):
    r = routes(signer)
    r[watchdog.HEAD_PATH] = failure
    findings = watchdog.run_checks(BASE, FakeTransport(r), lambda: NOW, sleep=lambda _s: None)
    assert codes(findings) == ["fetch"]
    assert "example.invalid" not in str(findings[0])


def test_unreachable_keys_fail(signer):
    r = routes(signer)
    r[watchdog.KEYS_PATH] = Response(200, b'{"keys": []}')
    assert codes(watchdog.run_checks(BASE, FakeTransport(r), lambda: NOW)) == ["fetch"]


# -- main: códigos de salida y configuración ------------------------------------------------------


def test_main_exit_codes(signer, capsys):
    env = {watchdog.ENV_BASE_URL: BASE, watchdog.ENV_JWKS: json.dumps(jwks([signer]))}
    ok = FakeTransport(routes(signer, keys=False))
    assert watchdog.main([], env=env, transport=ok, clock=lambda: NOW) == 0

    stale = FakeTransport(routes(signer, doc(modified="2099-03-01T10:00:00Z"), keys=False))
    assert watchdog.main([], env=env, transport=stale, clock=lambda: NOW) == 1
    out = capsys.readouterr().out
    assert "[stale]" in out and "example.invalid" not in out


@pytest.mark.parametrize(
    "env",
    [
        {},
        {watchdog.ENV_BASE_URL: "  "},
        {watchdog.ENV_BASE_URL: "http://feed.example.invalid"},
        {watchdog.ENV_BASE_URL: BASE, watchdog.ENV_JWKS: "no es json"},
        {watchdog.ENV_BASE_URL: BASE, watchdog.ENV_JWKS: '{"keys": []}'},
    ],
)
def test_main_without_config_is_not_green(env):
    t = FakeTransport({})
    assert watchdog.main([], env=env, transport=t, clock=lambda: NOW) == 2
    assert t.calls == []


def test_main_now_is_real_time_by_default(signer):
    """Sin reloj inyectado usa la hora real: el fixture del 2099 está en el futuro → `clock`."""
    env = {watchdog.ENV_BASE_URL: BASE, watchdog.ENV_JWKS: json.dumps(jwks([signer]))}
    t = FakeTransport(routes(signer, keys=False))
    assert watchdog.main([], env=env, transport=t) == 1
    assert datetime.now(UTC) < NOW - timedelta(days=1)


# -- el workflow ----------------------------------------------------------------------------------


def test_workflow_shape():
    import yaml

    text = (ROOT / ".github" / "workflows" / "watchdog.yml").read_text(encoding="utf-8")
    wf = yaml.safe_load(text)
    triggers = wf[True]  # YAML 1.1 lee `on` como True
    assert triggers["schedule"] == [{"cron": "7,37 * * * *"}]  # cada 30 min, fuera del minuto 0
    assert "workflow_dispatch" in triggers
    assert wf["permissions"] == {"contents": "read"}
    (job,) = wf["jobs"].values()
    # Sin la URL, el job sale «saltado», no en verde.
    assert job["if"] == "vars.VS_FEED_BASE_URL != ''"
    steps = job["steps"]
    check = next(s for s in steps if "vs.watchdog" in s.get("run", ""))
    assert check["env"]["VS_FEED_BASE_URL"] == "${{ vars.VS_FEED_BASE_URL }}"
    notify = steps[-1]
    assert notify["if"] == "failure()"
    assert notify["env"]["NTFY_TOPIC"] == "${{ secrets.VS_NTFY_TOPIC }}"
    assert notify["env"]["NTFY_TOKEN"] == "${{ secrets.VS_NTFY_TOKEN }}"  # noqa: S105 - nombre
    # Ningún secreto interpolado en el script (solo por env) y acciones fijadas por SHA.
    assert not any("${{" in s.get("run", "") for s in steps)
    for s in steps:
        if "uses" in s:
            assert len(s["uses"].split("@", 1)[1]) == 40


# -- el publicador emite lo que el vigilante lee --------------------------------------------------


def test_publisher_head_carries_status_and_passes_watchdog(signer):
    from vs.feed.config import FeedConfig
    from vs.feed.publish import FeedPublisher, FeedStatus
    from vs.feed.rights import PUBLIC
    from vs.sources.health import source_health
    from vs.sources.run import RunStatus, SourceRunResult

    def run(source, minutes_ago, status):
        at = NOW - timedelta(minutes=minutes_ago)
        return SourceRunResult(source, at, at + timedelta(seconds=5), status)

    runs = [
        run("cvelistv5", 20, RunStatus.OK),
        run("epss", 200, RunStatus.OK),
        run("epss", 150, RunStatus.UNKNOWN),
        run("epss", 10, RunStatus.UNKNOWN),
    ]
    pub = FeedPublisher(PUBLIC, FeedConfig(api_base=BASE, key_id=signer.kid), signer)
    head = pub.changes_head("all", None, NOW)
    assert "modified" not in json.loads(head.body)

    pub.set_status(FeedStatus(NOW - timedelta(minutes=5), tuple(source_health(runs))))
    head = pub.changes_head("all", None, NOW)
    v = Draft202012Validator({"$ref": "#/$defs/changes_page", "$defs": SCHEMA["$defs"]})
    assert not list(v.iter_errors(json.loads(head.body)))
    jws = pub.signature(head).body.decode()
    findings = watchdog.check_head(head.body, jws, json.loads(pub.keys().body), NOW)
    assert codes(findings) == ["source_unknown"]  # epss en UNKNOWN desde hace 150 min
    assert "150 min" in str(findings[0])

    with pytest.raises(ValueError, match="retroceder"):
        pub.set_status(FeedStatus(NOW - timedelta(hours=1), ()))
