"""Las vistas y los ADR solo pueden nombrar IDs que existen en architecture.yaml (D12)."""

import re
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / "docs" / "architecture"
ID_RE = re.compile(r"\b(?:CMP|FLW|TB|CTL|THR|SRC)-\d{3}\b")
SECTIONS = ("components", "sources", "trust_boundaries", "flows", "threats", "controls")


def _declared_ids() -> list[str]:
    data = yaml.safe_load((ARCH / "architecture.yaml").read_text(encoding="utf-8"))
    return [item["id"] for section in SECTIONS for item in data.get(section, [])]


def test_ids_are_unique():
    dupes = [i for i, n in Counter(_declared_ids()).items() if n > 1]
    assert not dupes, f"IDs repetidos: {dupes}"


def test_ids_have_known_prefix():
    bad = [i for i in _declared_ids() if not ID_RE.fullmatch(i)]
    assert not bad, f"IDs con formato no válido: {bad}"


def test_internal_references_exist():
    data = yaml.safe_load((ARCH / "architecture.yaml").read_text(encoding="utf-8"))
    declared = set(_declared_ids())
    refs: list[str] = []
    for flow in data.get("flows", []):
        refs += [flow["from"], flow["to"], *flow.get("crosses", [])]
        if "via" in flow:
            refs.append(flow["via"])
    for ctl in data.get("controls", []):
        refs += ctl.get("mitigates", [])
    missing = sorted(set(refs) - declared)
    assert not missing, f"Referencias a IDs inexistentes en architecture.yaml: {missing}"


def test_views_and_adrs_only_reference_declared_ids():
    declared = set(_declared_ids())
    docs = [*(ARCH / "views").glob("*.md"), *(ARCH / "adr").glob("*.md")]
    assert docs, "No hay vistas ni ADR que comprobar"
    problems = []
    for doc in docs:
        for found in sorted(set(ID_RE.findall(doc.read_text(encoding="utf-8")))):
            if found not in declared:
                problems.append(f"{doc.relative_to(ROOT)}: {found}")
    assert not problems, "IDs que no existen en architecture.yaml:\n" + "\n".join(problems)
