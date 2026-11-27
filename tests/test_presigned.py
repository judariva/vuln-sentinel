"""ADR-0026: la API sin clave sirve lo que firmó el job de publicación, y nada más.

Sin base de datos: el job (`signable_documents`, `presign`, `keys_row`) firma con la clave de
desarrollo, la API recibe esas filas (`StoredSignature`) y un `UnavailableSigner`.
"""

from datetime import timedelta

import pytest

from tests.test_api import NOW, make_app
from tests.test_feed import CONFIG, run_day
from vs.feed.publish import KEYS_PATH, LATEST_PATH, StoredSignature
from vs.feed.sign import UnavailableSigner, verify_detached
from vs.jobs.publish import closed_days, keys_row, presign, signable_documents


def presigned(now=NOW):
    """Publicador como el de la API en Azure: sin clave y con lo que dejó el job."""
    _, pub = run_day()
    signed = presign(pub, signable_documents(pub, pub.published_records(), now), {})
    keys = keys_row(pub, {})
    assert keys is not None
    pub.signer = UnavailableSigner(CONFIG.key_id)
    pub.load_signatures([row for _doc, _jws, row, _exp in signed] + [keys[1]])
    client, _ = make_app(publisher=pub, now=now)
    return client, pub, signed, keys[0]


def test_api_without_key_serves_what_publish_signed():
    client, _pub, signed, keys_doc = presigned()
    resp = client.get(KEYS_PATH)
    assert resp.status_code == 200 and resp.content == keys_doc.body
    jwks = resp.json()
    paths = [doc.path for doc, _jws, _row, _exp in signed]
    assert any(p.startswith("/v1/vulns/") for p in paths)
    assert any("/changes/" in p for p in paths)  # páginas selladas
    assert any(p.startswith("/v1/digest/") for p in paths)
    assert LATEST_PATH in paths
    for path in paths:
        body = client.get(path)
        jws = client.get(path + ".jws")
        assert body.status_code == 200 and jws.status_code == 200, path
        assert jws.headers["content-type"].startswith("application/jose")
        assert verify_detached(jws.text, body.content, jwks) == CONFIG.key_id, path


def test_latest_is_the_one_publish_signed():
    client, _pub, signed, _keys = presigned()
    stored = next(doc for doc, _jws, _row, _exp in signed if doc.path == LATEST_PATH)
    # La API no lo regenera con su reloj: sirve los bytes que se firmaron.
    assert client.get(LATEST_PATH).content == stored.body


def test_head_of_the_index_needs_a_key():
    client, *_ = presigned()
    assert client.get("/v1/feed/all/changes").status_code == 200
    resp = client.get("/v1/feed/all/changes.jws")
    assert resp.status_code == 503 and resp.json()["error"] == "signing_unavailable"


def test_a_signature_of_other_bytes_is_never_served():
    _, pub = run_day()
    doc = pub.vuln(sorted(pub.published_records())[0])
    jws = pub.signature(doc).body.decode("ascii")
    pub.signer = UnavailableSigner(CONFIG.key_id)
    pub.load_signatures([StoredSignature(doc.path, "0" * 64, jws, CONFIG.key_id)])
    client, _ = make_app(publisher=pub)
    assert client.get(doc.path).status_code == 200
    assert client.get(doc.path + ".jws").status_code == 503


def test_stored_body_must_match_its_hash():
    with pytest.raises(ValueError):
        StoredSignature("/v1/feed/alerts/latest.json", "0" * 64, None, CONFIG.key_id, b"{}")


def test_presign_skips_what_is_already_signed():
    _, pub = run_day()
    first = presign(pub, signable_documents(pub, pub.published_records(), NOW), {})
    already = {row.path: row.sha256 for _doc, _jws, row, _exp in first}
    again = presign(pub, signable_documents(pub, pub.published_records(), NOW), already)
    assert again == []
    assert keys_row(pub, {KEYS_PATH: pub.keys().sha256}) is None


def test_bodies_only_for_what_the_api_cannot_rebuild():
    _, pub = run_day()
    rows = [row for _d, _j, row, _e in presign(pub, signable_documents(pub, [], NOW), {})]
    with_body = {r.path for r in rows if r.body is not None}
    assert with_body == {LATEST_PATH}
    assert all(r.jws for r in rows)


def test_what_expires_with_retention():
    _, pub = run_day()
    retention = timedelta(days=CONFIG.retention_days)
    signed = presign(pub, signable_documents(pub, pub.published_records(), NOW), {})
    for doc, _jws, _row, expires in signed:
        if doc.path.startswith("/v1/vulns/") or doc.path == LATEST_PATH:
            assert expires is None, doc.path
        else:
            assert expires is not None and expires > NOW and expires <= NOW + retention, doc.path


def test_closed_days_are_inside_the_retention():
    days = closed_days(NOW, timedelta(days=3))
    assert days[-1] == NOW.date() - timedelta(days=1)
    assert days[0] == (NOW - timedelta(days=3)).date()


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/v1/feed/all/changes/2099-03-02T10.json", 404),  # hora en curso: no sellada
        ("/v1/feed/all/changes/2099-3-1T1.json", 400),
        ("/v1/feed/nada/changes/2099-03-01T13.json", 404),
        ("/v1/feed/all/changes/2098-01-01T00.json", 410),
    ],
)
def test_sealed_page_errors(path, status):
    client, *_ = presigned()
    assert client.get(path).status_code == status
