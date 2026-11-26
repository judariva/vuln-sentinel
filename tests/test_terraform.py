"""Invariantes del módulo Terraform del producto (T16, ADR-0025).

Checkov 3.4.11 no tiene checks para Container Apps (solo CKV_AZURE_136 y CKV2_AZURE_57, de
PostgreSQL): los controles CORE del patrón de Container Apps de la plataforma se comprueban aquí,
sobre el texto HCL, sin red ni Terraform.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "infra" / "terraform" / "modules" / "vuln-sentinel"
EXAMPLE = ROOT / "infra" / "terraform" / "examples" / "golden-dev"

RESOURCE_RE = re.compile(r'^resource "([\w]+)" "([\w]+)" \{', re.MULTILINE)


def _tf(path: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(path.glob("*.tf")))


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _block(text: str, start: int) -> str:
    """El bloque que empieza en la primera llave a partir de `start`, con llaves equilibradas."""
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at : i + 1]
    raise AssertionError("bloque sin cerrar")


def _resources(text: str) -> dict[tuple[str, str], str]:
    return {(m[1], m[2]): _block(text, m.start()) for m in RESOURCE_RE.finditer(text)}


@pytest.fixture(scope="module")
def code() -> str:
    return _strip_comments(_tf(MODULE))


@pytest.fixture(scope="module")
def resources(code) -> dict[tuple[str, str], str]:
    return _resources(code)


def test_module_creates_no_platform_resources(resources):
    # Identidades, roles, RG, Key Vault, redes y zonas DNS son del vending y de la plataforma.
    forbidden = re.compile(
        r"^azurerm_(role_assignment|role_definition|user_assigned_identity|resource_group"
        r"|key_vault|key_vault_access_policy|private_dns_zone\w*|virtual_network|subnet\w*"
        r"|network_security_group\w*|log_analytics_workspace|management_lock)$"
    )
    types = {t for t, _ in resources}
    assert not {t for t in types if forbidden.match(t)}, types
    for (t, n), body in resources.items():
        if t == "azapi_resource":
            assert "Microsoft.Authorization" not in body, n
            assert "Microsoft.Network/privateDnsZones" not in body, n


def test_ingress_is_internal_and_tls_only(resources):
    env = resources[("azurerm_container_app_environment", "this")]
    assert re.search(r"internal_load_balancer_enabled\s*=\s*true", env)
    apps = {n: b for (t, n), b in resources.items() if t == "azurerm_container_app"}
    assert set(apps) == {"api", "cloudflared"}
    for name, body in apps.items():
        assert not re.search(r"external_enabled\s*=\s*true", body), name
        assert not re.search(r"allow_insecure_connections\s*=\s*true", body), name
    assert re.search(r"external_enabled\s*=\s*false", apps["api"])
    assert re.search(r"allow_insecure_connections\s*=\s*false", apps["api"])
    assert "ingress" not in apps["cloudflared"]


def test_apps_have_probes_single_revision_and_explicit_replicas(resources):
    for (t, n), body in resources.items():
        if t != "azurerm_container_app":
            continue
        assert "liveness_probe" in body and "readiness_probe" in body, n
        assert re.search(r'revision_mode\s*=\s*"Single"', body), n
        assert "min_replicas" in body and "max_replicas" in body, n


def test_secrets_only_as_key_vault_references(resources):
    for (t, n), body in resources.items():
        if t not in ("azurerm_container_app", "azurerm_container_app_job"):
            continue
        for m in re.finditer(r"\bsecret \{", body):
            secret = _block(body, m.start())
            assert "key_vault_secret_id" in secret, n
            assert "identity" in secret, n
            assert not re.search(r"^\s*value\s*=", secret, re.MULTILINE), n


def test_every_workload_uses_a_managed_identity(resources):
    for (t, n), body in resources.items():
        if t in ("azurerm_container_app", "azurerm_container_app_job"):
            assert re.search(r'type\s*=\s*"UserAssigned"', body), n
            # El registro, si lo hay, con la identidad: nunca usuario y contraseña.
            assert "password_secret_name" not in body and "username" not in body, n


def test_postgres_private_and_entra_only(resources):
    pg = resources[("azurerm_postgresql_flexible_server", "this")]
    assert re.search(r"public_network_access_enabled\s*=\s*false", pg)
    assert re.search(r"password_auth_enabled\s*=\s*false", pg)
    assert re.search(r"active_directory_auth_enabled\s*=\s*true", pg)
    assert "administrator_password" not in pg and "administrator_login" not in pg
    assert "prevent_destroy = true" in pg
    tls = resources[("azurerm_postgresql_flexible_server_configuration", "require_tls")]
    assert '"require_secure_transport"' in tls and '"on"' in tls


def test_diagnostics_all_logs_without_shared_key(resources):
    env = resources[("azurerm_container_app_environment", "this")]
    assert re.search(r'logs_destination\s*=\s*"azure-monitor"', env)
    assert "log_analytics_workspace_id" not in env
    diags = {n: b for (t, n), b in resources.items() if t == "azurerm_monitor_diagnostic_setting"}
    assert set(diags) == {"environment", "postgres"}
    for name, body in diags.items():
        assert re.search(r'category_group\s*=\s*"allLogs"', body), name


def test_signing_key_is_ec_p256_sign_only_not_exportable(resources):
    key = resources[("azapi_resource", "signing_key")]
    assert '"Microsoft.KeyVault/vaults/keys@' in key
    assert 'kty       = "EC"' in key and '"P-256"' in key
    assert re.search(r'keyOps\s*=\s*\["sign", "verify"\]', key)
    assert re.search(r"exportable\s*=\s*false", key)


def test_secret_and_image_inputs_are_validated():
    variables = _tf(MODULE)
    # Imagen por digest y secretos solo como ids de Key Vault (validaciones de entrada).
    assert r"^sha256:[0-9a-f]{64}$" in variables
    assert r"^https://[a-z0-9-]+\\.vault\\.azure\\.net/secrets/[A-Za-z0-9-]+$" in variables
    assert '"acr", "ghcr"' in variables


def test_names_follow_type_name_env():
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    for prefix in ("cae", "psql", "ca", "caj"):
        assert re.search(rf'"{prefix}-\$\{{var\.name\}}-', main), prefix
    # El nombre más largo de ACA (caj-<16>-xxx-prod) cabe en 32 caracteres.
    assert len("caj-" + "x" * 16 + "-inv-prod") <= 32


def test_providers_pinned_exactly():
    for path in (MODULE / "versions.tf", EXAMPLE / "main.tf"):
        text = path.read_text(encoding="utf-8")
        # Proveedores (no required_version, que es un rango a propósito).
        versions = re.findall(r'^\s+version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert versions, path
        for v in versions:
            assert re.fullmatch(r"\d+\.\d+\.\d+", v), (path, v)
    lock = (EXAMPLE / ".terraform.lock.hcl").read_text(encoding="utf-8")
    assert 'version     = "4.81.0"' in lock and 'version     = "2.14.0"' in lock


def test_checkov_suppressions_are_scoped_and_justified():
    skip = re.compile(r"checkov:skip=([^:\s]+)(?::(.*))?")
    found = []
    for path in MODULE.glob("*.tf"):
        for line in path.read_text(encoding="utf-8").splitlines():
            m = skip.search(line)
            if m:
                found.append(m[1])
                assert re.fullmatch(r"CKV2?_AZURE_\d+", m[1]), line  # nunca comodines (S-24)
                assert m[2] and len(m[2].strip()) > 20, line  # con motivo
    assert sorted(found) == ["CKV2_AZURE_57", "CKV_AZURE_136"]


def test_example_uses_only_fictitious_values():
    text = _tf(EXAMPLE)
    for guid in re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text):
        assert len(set(guid.replace("-", ""))) == 1, guid
    for mail in re.findall(r"[\w.+-]+@[\w.-]+", text):
        assert mail.endswith("@example.com"), mail
    assert "sha256:" + "0" * 64 in text
