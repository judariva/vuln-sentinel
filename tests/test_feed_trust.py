"""Modelo de confianza del feed (T5b): clave fijada fuera del origen, frescura y retroceso.

- Un JWKS sustituido en el origen (otra clave válida con el mismo `kid`) hace que la firma
  «verifique»; con la huella RFC 7638 publicada en el repo, falla.
- Un documento viejo bien firmado se puede volver a servir: `--max-age` y `--state` lo detectan.
- El `kid` de la cabecera tiene que ser una cadena no vacía en las tres implementaciones.

Las claves se generan en el test y no se guardan; los ficheros van a `.cache/`, nunca a /tmp.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vs.feed.config import load_feed_config
from vs.feed.publish import FeedPublisher, FeedStatus
from vs.feed.rights import PUBLIC
from vs.feed.sign import (
    LocalDevSigner,
    SignatureError,
    b64url,
    jwk_thumbprint,
    jwks,
    sign_detached,
    verify_detached,
)

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "examples" / "verify"
KID = "test-2099-01"
DOC = b'{"id":"VS-CVE-2099-0001","modified":"2099-03-01T12:00:00Z"}'
HAS_OPENSSL = shutil.which("openssl") is not None


@pytest.fixture
def workdir():
    path = ROOT / ".cache" / "test-feed" / uuid.uuid4().hex
    path.mkdir(parents=True)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(scope="module")
def signer() -> LocalDevSigner:
    return LocalDevSigner.generate(KID)


@pytest.fixture(scope="module")
def attacker() -> LocalDevSigner:
    """Quien controla el origen: otra clave P-256 válida con el mismo `kid`."""
    return LocalDevSigner.generate(KID)


def _py(*args: str | Path) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - intérprete y script del propio repo
        [sys.executable, str(VERIFY / "verify.py"), *map(str, args)],
        capture_output=True,
        text=True,
        check=False,
    )


def _sh(workdir: Path, *args: str | Path) -> subprocess.CompletedProcess:
    bash = shutil.which("bash")
    assert bash
    return subprocess.run(  # noqa: S603 - script del propio repo
        [bash, str(VERIFY / "verify.sh"), *map(str, args)],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "TMPDIR": str(workdir)},
    )


def _files(workdir: Path, key: LocalDevSigner, payload: bytes = DOC, jws: str | None = None):
    """Documento, firma, JWKS y PEM tal como los serviría un origen con la clave `key`."""
    doc, sig = workdir / "doc.json", workdir / "doc.json.jws"
    keys, pem = workdir / "keys.json", workdir / "key.pem"
    doc.write_bytes(payload)
    sig.write_text(jws if jws is not None else sign_detached(payload, key), encoding="ascii")
    keys.write_text(json.dumps(jwks([key])), encoding="utf-8")
    pem.write_bytes(key.public_pem())
    return doc, sig, keys, pem


def _jws_with_header(header_json: bytes, payload: bytes, key: LocalDevSigner) -> str:
    """Firma válida sobre una cabecera arbitraria (para probar `kid` raros)."""
    protected = b64url(header_json)
    return f"{protected}..{b64url(key.sign(protected.encode('ascii') + b'.' + payload))}"


# -- huella RFC 7638 ------------------------------------------------------------------------------


def test_thumbprint_is_rfc7638(signer):
    jwk = signer.public_jwk()
    canon = json.dumps(
        {k: jwk[k] for k in ("crv", "kty", "x", "y")}, sort_keys=True, separators=(",", ":")
    ).encode()
    assert jwk_thumbprint(jwk) == b64url(hashlib.sha256(canon).digest())
    # Los miembros opcionales (kid, use, alg) no cuentan.
    assert jwk_thumbprint({**jwk, "kid": "otro", "use": "enc"}) == jwk_thumbprint(jwk)
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", jwk_thumbprint(jwk))


def test_thumbprint_rejects_short_coordinates(signer):
    jwk = dict(signer.public_jwk())
    jwk["x"] = b64url(b"\x01" * 31)
    with pytest.raises(SignatureError):
        jwk_thumbprint(jwk)


def test_three_implementations_agree_on_thumbprint(workdir, signer):
    *_, keys, _ = _files(workdir, signer)
    out = _py("--list-thumbprints", keys)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == f"{KID}\t{jwk_thumbprint(signer.public_jwk())}"


# -- clave fijada fuera del origen -----------------------------------------------------------------


def test_library_pinning(signer, attacker):
    good = jwk_thumbprint(signer.public_jwk())
    assert verify_detached(sign_detached(DOC, signer), DOC, jwks([signer]), [good]) == KID
    # El origen comprometido cambia documento, firma y JWKS a la vez.
    forged = sign_detached(DOC.replace(b"0001", b"6666"), attacker)
    forged_keys = jwks([attacker])
    assert verify_detached(forged, DOC.replace(b"0001", b"6666"), forged_keys) == KID  # sin fijar
    with pytest.raises(SignatureError, match="huella"):
        verify_detached(forged, DOC.replace(b"0001", b"6666"), forged_keys, [good])
    with pytest.raises(SignatureError):
        verify_detached(sign_detached(DOC, signer), DOC, jwks([signer]), ["", " "])


def test_library_pinning_allows_rotation(signer):
    new = LocalDevSigner.generate("test-2099-02")
    pins = [jwk_thumbprint(signer.public_jwk()), jwk_thumbprint(new.public_jwk())]
    keys = jwks([new, signer])
    assert verify_detached(sign_detached(DOC, new), DOC, keys, pins) == "test-2099-02"
    assert verify_detached(sign_detached(DOC, signer), DOC, keys, pins) == KID


def test_python_script_pinning(workdir, signer, attacker):
    good = jwk_thumbprint(signer.public_jwk())
    doc, sig, keys, _ = _files(workdir, signer)
    ok = _py("--expected-thumbprint", good, doc, sig, keys)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "huella fijada" in ok.stdout

    doc, sig, keys, _ = _files(workdir, attacker)  # JWKS sustituido, mismo kid
    assert _py(doc, sig, keys).returncode == 0  # sin fijar, «verifica»
    bad = _py("--expected-thumbprint", good, doc, sig, keys)
    assert bad.returncode == 1
    assert "huella" in bad.stdout
    # Con varias huellas (rotación) basta con una.
    other = jwk_thumbprint(LocalDevSigner.generate("x").public_jwk())
    two = _py("--expected-thumbprint", other, "--expected-thumbprint", good, doc, sig, keys)
    assert two.returncode == 1  # ninguna de las dos es la del atacante
    rot = _py(
        "--expected-thumbprint",
        other,
        "--expected-thumbprint",
        jwk_thumbprint(attacker.public_jwk()),
        doc,
        sig,
        keys,
    )
    assert rot.returncode == 0, rot.stdout
    assert _py("--expected-thumbprint", "", doc, sig, keys).returncode == 2


def test_thumbprint_starting_with_dash(workdir):
    """Una huella base64url puede empezar por «-»: los scripts no la toman por una opción."""
    for _ in range(2000):
        key = LocalDevSigner.generate(KID)
        tp = jwk_thumbprint(key.public_jwk())
        if tp.startswith("-"):
            break
    else:  # pragma: no cover - probabilidad (63/64)^2000
        pytest.skip("no salió ninguna huella con «-» delante")
    doc, sig, keys, pem = _files(workdir, key)
    res = _py("--expected-thumbprint", tp, doc, sig, keys)
    assert res.returncode == 0, res.stdout + res.stderr
    if HAS_OPENSSL:
        res = _sh(workdir, "--expected-thumbprint", tp, doc, sig, pem)
        assert res.returncode == 0, res.stdout + res.stderr


def test_python_script_pem_export_is_pinned(workdir, signer, attacker):
    good = jwk_thumbprint(signer.public_jwk())
    *_, keys, _ = _files(workdir, signer)
    assert _py("--pem", KID, "--expected-thumbprint", good, keys).returncode == 0
    *_, keys, _ = _files(workdir, attacker)
    bad = _py("--pem", KID, "--expected-thumbprint", good, keys)
    assert bad.returncode == 1
    assert "BEGIN PUBLIC KEY" not in bad.stdout


@pytest.mark.skipif(not HAS_OPENSSL, reason="openssl no está instalado")
def test_openssl_script_pinning(workdir, signer, attacker):
    good = jwk_thumbprint(signer.public_jwk())
    doc, sig, _, pem = _files(workdir, signer)
    ok = _sh(workdir, "--expected-thumbprint", good, doc, sig, pem)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "Verified OK" in ok.stdout
    eq = _sh(workdir, f"--expected-thumbprint={good}", doc, sig, pem)
    assert eq.returncode == 0, eq.stdout + eq.stderr

    doc, sig, _, pem = _files(workdir, attacker)
    assert _sh(workdir, doc, sig, pem).returncode == 0  # sin fijar, «verifica»
    bad = _sh(workdir, "--expected-thumbprint", good, doc, sig, pem)
    assert bad.returncode == 1
    assert "Verified OK" not in bad.stdout
    # La huella que calcula el script con openssl es la misma que la de la librería.
    assert jwk_thumbprint(attacker.public_jwk()) in bad.stdout
    rot = _sh(
        workdir,
        "--expected-thumbprint",
        good,
        "--expected-thumbprint",
        jwk_thumbprint(attacker.public_jwk()),
        doc,
        sig,
        pem,
    )
    assert rot.returncode == 0, rot.stdout + rot.stderr
    assert _sh(workdir, "--expected-thumbprint", "", doc, sig, pem).returncode == 2


@pytest.mark.skipif(not HAS_OPENSSL, reason="openssl no está instalado")
def test_openssl_thumbprint_many_keys(workdir):
    """Coordenadas con ceros a la izquierda: la huella desde la PEM tiene que coincidir siempre."""
    for _ in range(16):
        key = LocalDevSigner.generate(KID)
        doc, sig, _, pem = _files(workdir, key)
        res = _sh(workdir, "--expected-thumbprint", jwk_thumbprint(key.public_jwk()), doc, sig, pem)
        assert res.returncode == 0, res.stdout + res.stderr


# -- kid: cadena no vacía --------------------------------------------------------------------------

BAD_KIDS = [
    b'{"alg":"ES256","b64":false,"crit":["b64"]}',
    b'{"alg":"ES256","b64":false,"crit":["b64"],"kid":""}',
    b'{"alg":"ES256","b64":false,"crit":["b64"],"kid":123}',
    b'{"alg":"ES256","b64":false,"crit":["b64"],"kid":["test-2099-01"]}',
    b'{"alg":"ES256","b64":false,"crit":["b64"],"kid":null}',
]


@pytest.mark.parametrize("header", BAD_KIDS)
def test_kid_must_be_non_empty_string(workdir, signer, header):
    jws = _jws_with_header(header, DOC, signer)
    keys = jwks([signer])
    with pytest.raises(SignatureError, match="kid"):
        verify_detached(jws, DOC, keys)
    # Un JWKS con una entrada sin kid no hace que un kid ausente «encuentre» clave.
    loose = {"keys": [{k: v for k, v in keys["keys"][0].items() if k != "kid"}]}
    with pytest.raises(SignatureError, match="kid"):
        verify_detached(jws, DOC, loose)

    doc, sig, keys_path, pem = _files(workdir, signer, jws=jws)
    keys_path.write_text(json.dumps(loose), encoding="utf-8")
    res = _py(doc, sig, keys_path)
    assert res.returncode == 1 and "kid" in res.stdout
    if HAS_OPENSSL:
        res = _sh(workdir, doc, sig, pem)
        assert res.returncode == 1 and "kid" in res.stdout


def test_well_formed_kid_still_passes_with_custom_header(workdir, signer):
    header = b'{"alg":"ES256","b64":false,"crit":["b64"],"kid":"test-2099-01"}'
    jws = _jws_with_header(header, DOC, signer)
    assert verify_detached(jws, DOC, jwks([signer])) == KID
    doc, sig, keys, pem = _files(workdir, signer, jws=jws)
    assert _py(doc, sig, keys).returncode == 0
    if HAS_OPENSSL:
        assert _sh(workdir, doc, sig, pem).returncode == 0


# -- frescura (--max-age) --------------------------------------------------------------------------


def _ts(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _index(when: datetime, *, field: str = "modified") -> bytes:
    doc = {"schema_version": "1.0.0", "kind": "changes", "feed": "all", field: _ts(when)}
    return json.dumps(doc, separators=(",", ":")).encode()


def test_max_age_on_real_head_index(workdir):
    """El índice «head» que genera el publicador lleva `generated_at` y `modified` firmados."""
    config = load_feed_config(ROOT / "config" / "brand.example.yaml")
    key = LocalDevSigner.generate(config.key_id)
    pub = FeedPublisher(PUBLIC, config, key)
    now = datetime.now(UTC).replace(microsecond=0)
    pub.set_status(FeedStatus(modified=now - timedelta(minutes=10), sources=()))
    head = pub.changes_head("all", None, now)
    doc, sig = workdir / "head.json", workdir / "head.json.jws"
    keys = workdir / "keys.json"
    doc.write_bytes(head.body)
    sig.write_bytes(pub.signature(head).body)
    keys.write_bytes(pub.keys().body)
    pin = jwk_thumbprint(key.public_jwk())
    ok = _py("--expected-thumbprint", pin, "--max-age", "30m", doc, sig, keys)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    # `modified` (10 min) manda sobre `generated_at` (ahora): con 5 min es viejo.
    old = _py("--max-age", "5m", doc, sig, keys)
    assert old.returncode == 1 and "viejo" in old.stdout


@pytest.mark.parametrize("field", ["modified", "generated_at"])
def test_max_age_fresh_and_stale(workdir, signer, field):
    now = datetime.now(UTC)
    doc, sig, keys, _ = _files(workdir, signer, _index(now - timedelta(minutes=2), field=field))
    assert _py("--max-age", "30m", doc, sig, keys).returncode == 0
    doc, sig, keys, _ = _files(workdir, signer, _index(now - timedelta(hours=2), field=field))
    stale = _py("--max-age", "30m", doc, sig, keys)
    assert stale.returncode == 1 and "viejo" in stale.stdout
    assert _py("--max-age", "3h", doc, sig, keys).returncode == 0
    assert _py("--max-age", "1d", doc, sig, keys).returncode == 0
    assert _py(doc, sig, keys).returncode == 0  # sin --max-age no se mira


def test_max_age_fails_closed(workdir, signer):
    now = datetime.now(UTC)
    # Sin marca de tiempo (p. ej. una hora sellada): no se puede comprobar, falla.
    doc, sig, keys, _ = _files(workdir, signer, b'{"kind":"changes","sealed":true}')
    assert _py("--max-age", "30m", doc, sig, keys).returncode == 1
    # Fecha en el futuro (más allá del margen de reloj).
    doc, sig, keys, _ = _files(workdir, signer, _index(now + timedelta(hours=1)))
    fut = _py("--max-age", "30m", doc, sig, keys)
    assert fut.returncode == 1 and "futuro" in fut.stdout
    # Marca sin zona horaria o que no es una cadena.
    for body in (b'{"modified":"2099-01-01T00:00:00"}', b'{"modified":1700000000}'):
        doc, sig, keys, _ = _files(workdir, signer, body)
        assert _py("--max-age", "30m", doc, sig, keys).returncode == 1
    # Duraciones no válidas: error de uso.
    doc, sig, keys, _ = _files(workdir, signer, _index(now))
    for bad in ("0m", "30x", "-5m", ""):
        assert _py("--max-age", bad, doc, sig, keys).returncode == 2, bad


def test_freshness_only_after_signature(workdir, signer, attacker):
    """Una fecha nueva en un documento con la firma mala no cuenta ni toca el estado."""
    state = workdir / "state.json"
    good = jwk_thumbprint(signer.public_jwk())
    now = datetime.now(UTC)
    doc, sig, keys, _ = _files(workdir, attacker, _index(now))
    res = _py("--expected-thumbprint", good, "--state", state, "--max-age", "30m", doc, sig, keys)
    assert res.returncode == 1 and "FIRMA NO VÁLIDA" in res.stdout
    assert not state.exists()


# -- retroceso (--state) ---------------------------------------------------------------------------


def test_state_detects_rollback(workdir, signer):
    state = workdir / "state.json"
    now = datetime.now(UTC).replace(microsecond=0)
    t1, t2 = now - timedelta(minutes=20), now - timedelta(minutes=5)

    doc, sig, keys, _ = _files(workdir, signer, _index(t1))
    first = _py("--state", state, doc, sig, keys)
    assert first.returncode == 0, first.stdout + first.stderr
    assert json.loads(state.read_text())["modified"] == _ts(t1)

    newer = workdir / "newer"
    newer.mkdir()
    doc2, sig2, keys2, _ = _files(newer, signer, _index(t2))
    assert _py("--state", state, doc2, sig2, keys2).returncode == 0
    assert json.loads(state.read_text())["modified"] == _ts(t2)
    assert _py("--state", state, doc2, sig2, keys2).returncode == 0  # el mismo otra vez vale

    # El origen vuelve a servir el documento viejo, bien firmado.
    back = _py("--state", state, doc, sig, keys)
    assert back.returncode == 1 and "retroceso" in back.stdout
    assert json.loads(state.read_text())["modified"] == _ts(t2)  # el estado no retrocede


def test_state_unreadable_fails_closed(workdir, signer):
    state = workdir / "state.json"
    doc, sig, keys, _ = _files(workdir, signer, _index(datetime.now(UTC)))
    for junk in ("{", "[]", '{"modified":""}', '{"other":1}'):
        state.write_text(junk, encoding="utf-8")
        res = _py("--state", state, doc, sig, keys)
        assert res.returncode == 1, junk
        assert state.read_text(encoding="utf-8") == junk  # no se pisa


def test_state_and_max_age_together(workdir, signer):
    state = workdir / "state.json"
    now = datetime.now(UTC).replace(microsecond=0)
    doc, sig, keys, _ = _files(workdir, signer, _index(now - timedelta(hours=2)))
    stale = _py("--max-age", "30m", "--state", state, doc, sig, keys)
    assert stale.returncode == 1
    assert not state.exists()  # un documento rechazado no se apunta


# -- documentación ---------------------------------------------------------------------------------


def test_keys_md_matches_example_jwks():
    """`docs/feed/keys.md` publica huellas con el formato correcto, y la del ejemplo es la real."""
    text = (ROOT / "docs" / "feed" / "keys.md").read_text(encoding="utf-8")
    example = json.loads((VERIFY / "jwks.example.json").read_text(encoding="utf-8"))["keys"][0]
    assert f"`{jwk_thumbprint(example)}`" in text
    readme = (VERIFY / "README.md").read_text(encoding="utf-8")
    for flag in ("--expected-thumbprint", "--max-age", "--state"):
        assert flag in readme
