"""Firma del feed (ADR-0008): JWS detached ES256 sobre los bytes exactos, verificada con Python y
con openssl de punta a punta. Las claves se generan en el test y no se guardan."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from vs.feed.sign import (
    KeyVaultSigner,
    LocalDevSigner,
    SignatureError,
    Signer,
    b64url,
    jwks,
    parse_detached,
    sign_detached,
    verify_detached,
)

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "examples" / "verify"
KID = "test-2099-01"
DOC = b'{"id":"VS-CVE-2099-0001","modified":"2099-03-01T12:00:00Z","summary":"\xc3\xb1"}'


@pytest.fixture
def workdir():
    """Directorio de trabajo bajo `.cache/` (ignorado por git), nunca en /tmp."""
    path = ROOT / ".cache" / "test-feed" / uuid.uuid4().hex
    path.mkdir(parents=True)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(scope="module")
def signer() -> LocalDevSigner:
    return LocalDevSigner.generate(KID)


def _write(workdir: Path, signer: LocalDevSigner, payload: bytes = DOC) -> dict[str, Path]:
    paths = {
        "doc": workdir / "doc.json",
        "jws": workdir / "doc.json.jws",
        "jwks": workdir / "keys.json",
        "pem": workdir / "key.pem",
    }
    paths["doc"].write_bytes(payload)
    paths["jws"].write_text(sign_detached(payload, signer), encoding="ascii")
    paths["jwks"].write_text(json.dumps(jwks([signer])), encoding="utf-8")
    paths["pem"].write_bytes(signer.public_pem())
    return paths


# -- formato ----------------------------------------------------------------------------------


def test_detached_jws_header_and_shape(signer):
    jws = sign_detached(DOC, signer)
    protected, header, sig = parse_detached(jws)
    assert jws.count(".") == 2 and ".." in jws  # payload separado
    assert header == {"alg": "ES256", "b64": False, "crit": ["b64"], "kid": KID}
    assert len(sig) == 64
    assert protected == b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())


def test_python_verify_roundtrip_and_tamper(signer):
    keys = jwks([signer])
    assert verify_detached(sign_detached(DOC, signer), DOC, keys) == KID
    jws = sign_detached(DOC, signer)
    with pytest.raises(SignatureError):
        verify_detached(jws, DOC + b" ", keys)  # un byte más
    with pytest.raises(SignatureError):
        verify_detached(jws, DOC.replace(b"0001", b"0002"), keys)
    other = LocalDevSigner.generate(KID)
    with pytest.raises(SignatureError):
        verify_detached(jws, DOC, jwks([other]))  # misma kid, otra clave


def test_verify_rejects_attached_or_other_alg(signer):
    keys = jwks([signer])
    protected, _, sig = sign_detached(DOC, signer).split(".")
    with pytest.raises(SignatureError):
        verify_detached(f"{protected}.{b64url(DOC)}.{sig}", DOC, keys)
    hs = b64url(b'{"alg":"HS256","b64":false,"crit":["b64"],"kid":"test-2099-01"}')
    with pytest.raises(SignatureError):
        verify_detached(f"{hs}..{sig}", DOC, keys)
    plain = b64url(b'{"alg":"ES256","kid":"test-2099-01"}')
    with pytest.raises(SignatureError):
        verify_detached(f"{plain}..{sig}", DOC, keys)


def test_unknown_kid(signer):
    with pytest.raises(SignatureError):
        verify_detached(sign_detached(DOC, signer), DOC, {"keys": []})


def test_rotation_two_keys(signer):
    new = LocalDevSigner.generate("test-2099-02")
    keys = jwks([new, signer])
    assert verify_detached(sign_detached(DOC, signer), DOC, keys) == KID
    assert verify_detached(sign_detached(DOC, new), DOC, keys) == "test-2099-02"
    with pytest.raises(ValueError):
        jwks([signer, LocalDevSigner.generate(KID)])


def test_jwks_has_no_private_material(signer):
    for key in jwks([signer])["keys"]:
        assert set(key) == {"kty", "crv", "x", "y", "kid", "use", "alg"}


# -- interfaz Signer ------------------------------------------------------------------------------


def test_signers_implement_interface():
    assert issubclass(LocalDevSigner, Signer)
    assert issubclass(KeyVaultSigner, Signer)


def test_key_vault_signer_without_tokens_fails_closed():
    # La firma real con Key Vault se prueba en test_azure_runtime.py con un vault simulado.
    kv = KeyVaultSigner("https://vault.example.invalid", "feed-signing", "v1", KID)
    assert kv.kid == KID
    with pytest.raises(SignatureError):
        kv.sign(DOC)
    with pytest.raises(SignatureError):
        kv.public_jwk()
    with pytest.raises(ValueError):
        KeyVaultSigner("http://vault.example.invalid", "feed-signing", "v1", KID)
    assert not any(m == "azure" or m.startswith("azure.") for m in sys.modules)


def test_local_key_never_inside_repo_outside_cache(workdir):
    with pytest.raises(ValueError):
        LocalDevSigner.load_or_create(ROOT / "config" / "feed-key.pem", KID)
    with pytest.raises(ValueError):
        LocalDevSigner.load_or_create(ROOT / "src" / "vs" / "feed" / "k.pem", KID)
    path = workdir / "dev-key.pem"
    first = LocalDevSigner.load_or_create(path, KID)
    again = LocalDevSigner.load_or_create(path, KID)
    assert first.public_jwk() == again.public_jwk()
    assert path.stat().st_mode & 0o077 == 0


def test_example_jwks_is_valid_public_p256():
    data = json.loads((VERIFY / "jwks.example.json").read_text(encoding="utf-8"))
    assert len(data["keys"]) == 1
    key = data["keys"][0]
    assert set(key) == {"kty", "crv", "x", "y", "kid", "use", "alg"}  # sin «d»
    assert (key["kty"], key["crv"], key["alg"], key["use"]) == ("EC", "P-256", "ES256", "sig")

    def num(v: str) -> int:
        return int.from_bytes(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)), "big")

    ec.EllipticCurvePublicNumbers(num(key["x"]), num(key["y"]), ec.SECP256R1()).public_key()


# -- de punta a punta con los scripts de examples/verify ------------------------------------------


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


def test_end_to_end_python_script(workdir, signer):
    p = _write(workdir, signer)
    ok = _py(p["doc"], p["jws"], p["jwks"])
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert KID in ok.stdout
    p["doc"].write_bytes(DOC.replace(b"12:00", b"12:01"))
    bad = _py(p["doc"], p["jws"], p["jwks"])
    assert bad.returncode == 1


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl no está instalado")
def test_end_to_end_openssl(workdir, signer):
    p = _write(workdir, signer)
    # La PEM sale del JWKS con el script de Python, como haría un consumidor.
    pem = _py("--pem", KID, p["jwks"])
    assert pem.returncode == 0, pem.stderr
    assert pem.stdout.encode() == signer.public_pem()
    p["pem"].write_text(pem.stdout, encoding="ascii")

    ok = _sh(workdir, p["doc"], p["jws"], p["pem"])
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "Verified OK" in ok.stdout

    p["doc"].write_bytes(DOC + b"\n")  # un salto de línea basta para romperla
    bad = _sh(workdir, p["doc"], p["jws"], p["pem"])
    assert bad.returncode != 0
    assert "Verified OK" not in bad.stdout


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl no está instalado")
def test_openssl_many_signatures(workdir, signer):
    """r o s con ceros a la izquierda: la conversión r||s → DER tiene que valer siempre."""
    for i in range(24):
        payload = DOC + str(i).encode()
        p = _write(workdir, signer, payload)
        res = _sh(workdir, p["doc"], p["jws"], p["pem"])
        assert res.returncode == 0, (i, res.stdout, res.stderr)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl no está instalado")
def test_openssl_signs_python_verifies(workdir):
    """Interoperabilidad inversa: una firma ES256 hecha por openssl la acepta verify_detached."""
    openssl = shutil.which("openssl")
    key = workdir / "k.pem"
    subprocess.run(  # noqa: S603
        [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
        check=True,
        capture_output=True,
    )
    priv = serialization.load_pem_private_key(key.read_bytes(), password=None)
    dev = LocalDevSigner(priv, KID)
    protected = b64url(b'{"alg":"ES256","b64":false,"crit":["b64"],"kid":"test-2099-01"}')
    (workdir / "in").write_bytes(protected.encode() + b"." + DOC)
    der = subprocess.run(  # noqa: S603
        [openssl, "dgst", "-sha256", "-sign", str(key), str(workdir / "in")],
        check=True,
        capture_output=True,
    ).stdout
    r, s = utils.decode_dss_signature(der)
    jws = f"{protected}..{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    assert verify_detached(jws, DOC, jwks([dev])) == KID
