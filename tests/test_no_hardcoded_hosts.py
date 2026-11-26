"""Ningún host real de la marca aparece en código, configuración o fixtures (ADR-0016).

Los hosts reales no pueden estar en el repo (regla 8), así que el test los lee de la variable de
entorno VS_FORBIDDEN_HOSTS (lista separada por comas), que en CI viene de un secret. Sin la
variable, el test se salta.
"""

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCANNED = ("src", "web", "config", "tests/fixtures", "examples", "schema", "infra")
TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".json", ".yaml", ".yml", ".toml", ".md", ".html"}
# Dependencias y artefactos generados del portal: no son código del repo (ni están en git).
SKIPPED_DIRS = {"node_modules", "dist", "test-results", "playwright-report"}


def _forbidden() -> list[str]:
    raw = os.environ.get("VS_FORBIDDEN_HOSTS", "")
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


@pytest.mark.skipif(not _forbidden(), reason="VS_FORBIDDEN_HOSTS no definida")
def test_no_real_hosts_in_repo():
    hosts = _forbidden()
    hits = []
    for top in SCANNED:
        base = ROOT / top
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if SKIPPED_DIRS & set(path.relative_to(base).parts):
                continue
            if path.is_file() and path.suffix in TEXT_SUFFIXES:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
                hits += [f"{path.relative_to(ROOT)}: {h}" for h in hosts if h in text]
    assert not hits, "Hosts reales escritos en el repo:\n" + "\n".join(hits)
