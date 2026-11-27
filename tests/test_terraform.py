"""Invariantes del módulo Terraform del producto (T16, T16b, ADR-0025).

Checkov 3.4.11 no tiene checks para Container Apps (solo CKV_AZURE_136 y CKV2_AZURE_57, de
PostgreSQL): los controles CORE del patrón de Container Apps de la plataforma y las decisiones de
T16b (dos UAMI, endpoint privado, clave de la plataforma, rangos de versión) se comprueban aquí,
sobre el texto HCL, sin red ni Terraform.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "infra" / "terraform" / "modules" / "vuln-sentinel"
EXAMPLE = ROOT / "infra" / "terraform" / "examples" / "golden-lab"

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
        r"|key_vault\w*|private_dns_zone\w*|private_endpoint\w*|virtual_network|subnet\w*"
        r"|network_security_group\w*|log_analytics_workspace|management_lock)$"
    )
    types = {t for t, _ in resources}
    assert not {t for t in types if forbidden.match(t)}, types
    # La clave de firma la crea la plataforma (P-4): sin azapi ni azurerm_key_vault_key.
    assert not {t for t in types if t.startswith("azapi_")}, types


def test_ingress_is_internal_and_tls_only(resources):
    env = resources[("azurerm_container_app_environment", "this")]
    assert re.search(r"internal_load_balancer_enabled\s*=\s*true", env)
    apps = {n: b for (t, n), b in resources.items() if t == "azurerm_container_app"}
    assert set(apps) == {"api", "cloudflared"}
    for name, body in apps.items():
        assert not re.search(r"external_enabled\s*=\s*true", body), name
        assert not re.search(r"allow_insecure_connections\s*=\s*true", body), name
    # La API solo se abre a la VNet con api.vnet_ingress_from (CIDR privados validados; el entorno
    # es interno) y entonces cada CIDR es una regla Allow. El comportamiento lo prueba
    # tests/api_ingress.tftest.hcl con `terraform test`.
    api = apps["api"]
    assert re.search(r"external_enabled\s*=\s*length\(var\.api\.vnet_ingress_from\)\s*>\s*0", api)
    assert re.search(r'action\s*=\s*"Allow"', api) and '"Deny"' not in api
    assert re.search(r"allow_insecure_connections\s*=\s*false", api)
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


def test_postgres_private_endpoint_and_entra_only(resources):
    pg = resources[("azurerm_postgresql_flexible_server", "this")]
    assert re.search(r"public_network_access_enabled\s*=\s*false", pg)
    assert re.search(r"password_auth_enabled\s*=\s*false", pg)
    assert re.search(r"active_directory_auth_enabled\s*=\s*true", pg)
    assert "administrator_password" not in pg and "administrator_login" not in pg
    # D-7: sin subred delegada; el endpoint privado lo crea la plataforma (v0.1.2).
    assert "delegated_subnet_id" not in pg and "private_dns_zone_id" not in pg
    tls = resources[("azurerm_postgresql_flexible_server_configuration", "require_tls")]
    assert '"require_secure_transport"' in tls and '"on"' in tls


def test_postgres_outputs_for_platform_private_endpoint():
    # La puerta de la factoría es estática: un recurso declarado con count 0 también cuenta. El
    # módulo no declara endpoints ni variables de red de endpoints (v0.1.2).
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    assert "private_endpoint_subnet_id" not in variables
    assert "postgres_private_dns_zone_id" not in variables
    outputs = (MODULE / "outputs.tf").read_text(encoding="utf-8")
    pg_out = _block(outputs, outputs.index('output "postgres"'))
    assert re.search(r"name\s*=\s*azurerm_postgresql_flexible_server\.this\.name", pg_out)


def test_no_grant_without_consumer(code):
    # Mínimo privilegio: ningún componente consulta Cost Management todavía.
    assert "Cost Management Reader" not in code


def test_postgres_without_prevent_destroy(code):
    # Respuesta 7: prevent_destroy no admite variables y la retirada exige poder destruir. La
    # protección de prod va fuera del módulo (ADR-0025).
    assert "prevent_destroy" not in code


def test_geo_backup_on_in_prod_off_elsewhere():
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    assert re.search(
        r"coalesce\(var\.postgres\.geo_redundant_backup, var\.environment == \"prod\"\)", main
    )
    pg = (MODULE / "postgres.tf").read_text(encoding="utf-8")
    assert "geo_redundant_backup_enabled  = local.postgres_geo_backup" in pg


def test_diagnostics_all_logs_without_shared_key(resources):
    env = resources[("azurerm_container_app_environment", "this")]
    assert re.search(r'logs_destination\s*=\s*"azure-monitor"', env)
    assert "log_analytics_workspace_id" not in env
    diags = {n: b for (t, n), b in resources.items() if t == "azurerm_monitor_diagnostic_setting"}
    assert set(diags) == {"environment", "postgres"}
    for name, body in diags.items():
        assert re.search(r'category_group\s*=\s*"allLogs"', body), name
        assert re.search(r"name\s*=\s*local\.names\.diag_", body), name


def test_diagnostic_names_follow_platform_convention():
    # Convención de la plataforma: diag-<ns>-...; por defecto el espacio gt (respuesta 6).
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    m = re.search(
        r'variable "diagnostic_setting_prefix" \{.*?default\s*=\s*"([^"]+)"', variables, re.S
    )
    assert m and m[1] == "diag-gt-"
    name = m[1] + "psql-" + "x" * 16 + "-prod"
    assert re.fullmatch(r"diag-gt-[a-z0-9-]+", name)


def test_two_identities_and_only_publish_signs(code):
    # D-3: dos UAMI. Solo el job publish usa la identidad publish.
    m = re.search(r"identity_key = \{(.*?)\}", code, re.S)
    assert m
    pairs = dict(re.findall(r"(\w+)\s*=\s*\"(\w+)\"", m[1]))
    assert set(pairs.values()) == {"runtime", "publish"}
    assert [c for c, k in pairs.items() if k == "publish"] == ["publish"]
    assert set(pairs) == {
        "api",
        "cloudflared",
        "ingest",
        "investigate",
        "publish",
        "daily",
        "migrate",
    }
    # Las identidades salen del mapa, nunca de var.identities indexado por componente.
    assert not re.search(r"var\.identities\[", code)


def test_signing_key_comes_from_platform(code):
    # Respuesta 8: la clave la crea el vending; el módulo recibe su key_id sin versión.
    assert "VS_SIGNING_KEY_URI = var.signing_key_id" in code
    grants = (MODULE / "outputs.tf").read_text(encoding="utf-8")
    crypto = re.findall(
        r'component = "(\w+)"\s*\n\s*role\s*=\s*"Key Vault Crypto User"\s*\n'
        r"\s*scope\s*=\s*([\w.]+)",
        grants,
    )
    assert crypto == [("publish", "local.signing_key_scope")]
    assert 'signing_key_scope = "${var.key_vault_id}/keys/${local.signing_key_name}"' in code


def test_acr_is_default_and_cloudflared_pulls_from_it():
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    m = re.search(r'variable "image_registry" \{.*?default\s*=\s*"(\w+)"', variables, re.S)
    assert m and m[1] == "acr"
    assert "registry_uses_identity" not in _tf(MODULE)
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    assert 'startswith(var.cloudflared.image, "${var.registry_server}/")' in main


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


def _provider_versions(path: Path) -> list[str]:
    # Proveedores (no required_version, que es un rango a propósito).
    text = path.read_text(encoding="utf-8")
    return re.findall(r'^\s+version\s*=\s*"([^"]+)"', text, re.MULTILINE)


def test_module_uses_ranges_and_root_pins_exactly():
    # Respuesta 5: el módulo pone `>=` con techo de mayor; la raíz, la versión exacta y el lock.
    module = _provider_versions(MODULE / "versions.tf")
    assert module == [">= 4.81.0, < 5.0.0"]
    root = _provider_versions(EXAMPLE / "main.tf")
    assert root and all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in root), root
    lock = (EXAMPLE / ".terraform.lock.hcl").read_text(encoding="utf-8")
    assert 'version     = "4.81.0"' in lock
    assert "azapi" not in lock


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
    # CKV2_AZURE_57 vuelve en v0.1.2: el endpoint privado lo crea la plataforma, fuera del módulo.
    assert sorted(found) == ["CKV2_AZURE_57", "CKV_AZURE_136"]


def test_tflint_ignores_are_scoped():
    found = []
    for path in MODULE.glob("*.tf"):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if "tflint-ignore" in line:
                found.append(line.split(":", 1)[1].strip())
                assert lines[i - 1].lstrip().startswith("#") and "T16b" in lines[i - 1], line
                assert lines[i + 1].startswith("resource "), line
    assert found == ["azurerm_resources_missing_prevent_destroy"] * 2


def test_example_uses_only_fictitious_values():
    text = _tf(EXAMPLE)
    for guid in re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text):
        assert len(set(guid.replace("-", ""))) == 1, guid
    for mail in re.findall(r"[\w.+-]+@[\w.-]+", text):
        assert mail.endswith("@example.com"), mail
    assert "sha256:" + "0" * 64 in text
