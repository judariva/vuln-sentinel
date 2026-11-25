"""Licencia de los datos e instancias (ADR-0022).

Todos los conectores y datos de este fichero son SINTÉTICOS: no salen de ninguna fuente real.
"""

from pathlib import Path

import pytest

from vs.feed.rights import PUBLIC, Level, audience_for, filter_signals, level_for_feed
from vs.instance import (
    GuardedStore,
    Instance,
    InstanceConfigError,
    InstanceKind,
    audit,
    load_instance,
    parse_instance,
)
from vs.sources.base import Connector, LicenseClass, LicenseError, Record, Registry

ROOT = Path(__file__).resolve().parents[1]
CVE = "CVE-2099-0001"  # ficticio
LICENSE = "example-commercial-license"  # la de config/instance.example-clients.yaml


class SyntheticOpen(Connector):
    name = "synthetic-open"
    license_class = LicenseClass.OPEN

    def fetch(self):
        return [{"cve": CVE, "epss": 0.42}]

    def normalize(self, raw):
        yield Record(
            source=self.name,
            cve_id=raw["cve"],
            kind="epss",
            license_class=self.license_class,
            value={"score": raw["epss"]},
        )


class SyntheticRestricted(Connector):
    """Imita una fuente de pago que da la única señal de explotación."""

    name = "synthetic-restricted"
    license_class = LicenseClass.RESTRICTED
    licensee = LICENSE
    required_config = ("api_key_env",)

    def fetch(self):
        return [{"cve": CVE}]

    def normalize(self, raw):
        yield Record(
            source=self.name,
            cve_id=raw["cve"],
            kind="kev_vulncheck",
            license_class=self.license_class,
            licensee=self.licensee,
        )


@pytest.fixture
def registry():
    reg = Registry()
    reg.register(SyntheticOpen)
    reg.register(SyntheticRestricted)
    return reg


@pytest.fixture
def public():
    return load_instance(ROOT / "config" / "instance.public.yaml")


@pytest.fixture
def clients():
    return load_instance(ROOT / "config" / "instance.example-clients.yaml")


def _with_connectors(inst: Instance, *names: str) -> Instance:
    data = {
        "instance": {
            "name": inst.name,
            "kind": inst.kind.value,
            "allowed_license_classes": [c.value for c in inst.allowed_license_classes],
            "licenses": sorted(inst.licenses),
            "connectors": [{"name": n, "config": {"api_key_env": "X"}} for n in names],
        }
    }
    return parse_instance(data)


# -- configuración ---------------------------------------------------------------------------


def test_public_config_only_open(public):
    assert public.kind is InstanceKind.PUBLIC
    assert public.allowed_license_classes == {LicenseClass.OPEN}
    assert not public.licenses


def test_public_config_cannot_allow_restricted():
    with pytest.raises(InstanceConfigError):
        parse_instance(
            {
                "instance": {
                    "name": "p",
                    "kind": "public",
                    "allowed_license_classes": ["open", "restricted"],
                    "connectors": [],
                }
            }
        )


def test_public_config_cannot_declare_licenses():
    with pytest.raises(InstanceConfigError):
        Instance("p", InstanceKind.PUBLIC, frozenset({LicenseClass.OPEN}), frozenset({LICENSE}))


def test_example_clients_config_is_valid(clients):
    assert clients.kind is InstanceKind.CLIENTS
    assert LICENSE in clients.licenses


# -- la instancia pública no guarda nada restringido -----------------------------------------


def test_public_instance_refuses_restricted_connector(public, registry):
    inst = _with_connectors(public, "synthetic-open", "synthetic-restricted")
    with pytest.raises(LicenseError, match="synthetic-restricted"):
        inst.build_connectors(registry)


def test_public_instance_stores_only_open(public, registry):
    inst = _with_connectors(public, "synthetic-open")
    store = GuardedStore(inst)
    for conn in inst.build_connectors(registry):
        store.extend(conn.records())
    assert store.rows()
    assert all(r.license_class is LicenseClass.OPEN for r in store.rows())
    audit(inst, store.rows())


def test_public_store_rejects_restricted_record(public):
    store = GuardedStore(public)
    rec = Record("synthetic-restricted", CVE, "kev_vulncheck", LicenseClass.RESTRICTED, LICENSE)
    with pytest.raises(LicenseError):
        store.add(rec)
    assert store.rows() == ()


def test_audit_fails_on_restricted_row_in_public(public):
    rows = [
        {"license_class": "open", "licensee": None},
        {"license_class": "restricted", "licensee": LICENSE},
    ]
    with pytest.raises(LicenseError):
        audit(public, rows)


def test_audit_fails_on_malformed_row(public):
    with pytest.raises(LicenseError):
        audit(public, [{"license_class": "restricted", "licensee": None}])


def test_clients_instance_loads_both(clients, registry):
    inst = _with_connectors(clients, "synthetic-open", "synthetic-restricted")
    store = GuardedStore(inst)
    for conn in inst.build_connectors(registry):
        store.extend(conn.records())
    assert {r.license_class for r in store.rows()} == {LicenseClass.OPEN, LicenseClass.RESTRICTED}


def test_clients_instance_refuses_unlicensed_restricted(clients, registry):
    class OtherLicense(SyntheticRestricted):
        name = "synthetic-other-license"
        licensee = "a-license-we-do-not-have"

    registry.register(OtherLicense)
    inst = _with_connectors(clients, "synthetic-other-license")
    with pytest.raises(LicenseError):
        inst.build_connectors(registry)


# -- conectores ------------------------------------------------------------------------------


def test_restricted_connector_needs_licensee():
    with pytest.raises(LicenseError):

        class _NoLicensee(Connector):
            name = "bad"
            license_class = LicenseClass.RESTRICTED

            def fetch(self):
                return []

            def normalize(self, raw):
                return []


def test_connector_cannot_emit_other_license():
    class Liar(SyntheticOpen):
        name = "synthetic-liar"

        def normalize(self, raw):
            yield Record(self.name, CVE, "kev_vulncheck", LicenseClass.RESTRICTED, LICENSE)

    with pytest.raises(LicenseError):
        list(Liar().records())


def test_connector_required_config():
    with pytest.raises(ValueError, match="api_key_env"):
        SyntheticRestricted({})


def test_registry_rejects_duplicate_name(registry):
    class Clash(SyntheticOpen):
        pass

    with pytest.raises(ValueError):
        registry.register(Clash)


def test_unknown_connector(public, registry):
    with pytest.raises(KeyError):
        _with_connectors(public, "does-not-exist").build_connectors(registry)


# -- feed según derechos ---------------------------------------------------------------------


def test_same_cve_different_level_per_feed(clients, registry):
    """La única señal de A es restricted: A en el feed de clientes, no en el público."""
    inst = _with_connectors(clients, "synthetic-open", "synthetic-restricted")
    signals = [r for c in inst.build_connectors(registry) for r in c.records()]

    client_feed = audience_for(inst, "client-1", [LICENSE])
    assert level_for_feed(signals, client_feed) is Level.A
    assert level_for_feed(signals, PUBLIC) is Level.NONE
    assert all(s.license_class is LicenseClass.OPEN for s in filter_signals(signals, PUBLIC))


def test_open_exploitation_signal_gives_a_in_public():
    signals = [
        Record("synthetic-open", CVE, "ssvc", LicenseClass.OPEN, value={"exploitation": "active"})
    ]
    assert level_for_feed(signals, PUBLIC) is Level.A


def test_audience_cannot_exceed_instance(public):
    with pytest.raises(ValueError):
        audience_for(public, "x", [LICENSE])
