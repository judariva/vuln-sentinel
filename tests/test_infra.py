"""Endurecimiento de la infraestructura y de los workflows (T9b).

Sin red ni Azure: comprueba el envoltorio que oculta los errores de az (THR-019) y la forma de
los ficheros que deciden qué llega a producción (THR-018).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
LEGACY = ROOT / "infra" / "bicep-legacy"
AZ_QUIET = LEGACY / "scripts" / "az-quiet.sh"
WORKFLOWS = ROOT / ".github" / "workflows"
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+(/[\w.-]+)*@[0-9a-f]{40}$")

# Error de ARM inventado con todo lo que no debe salir al log: IDs, nombres y rangos ficticios.
FAKE_SUB = "00000000-1111-2222-3333-444444444444"
FAKE_ARM_ERROR = f"""ERROR: (InvalidTemplateDeployment) The deployment 'vs-1-1' is not valid.
Code: InvalidTemplateDeployment
Message: The template deployment failed for /subscriptions/{FAKE_SUB}/resourceGroups/rgsecret
Exception Details:\t(PrivateIPAddressInReservedRange) Subnet 10.9.8.0/24 (vaultsecretname) overlaps.
\tCode: PrivateIPAddressInReservedRange
{{"error": {{"code": "SubnetOverlap", "message": "vnet secretvnet {FAKE_SUB}"}}}}
"""
LEAKS = [FAKE_SUB, "rgsecret", "10.9.8.0", "vaultsecretname", "secretvnet", "vs-1-1"]


def _fake_cmd(tmp_path: Path, stdout: str, stderr: str, rc: int) -> Path:
    (tmp_path / "out.txt").write_text(stdout, encoding="utf-8")
    (tmp_path / "err.txt").write_text(stderr, encoding="utf-8")
    script = tmp_path / "fakeaz.sh"
    script.write_text(
        f'#!/usr/bin/env bash\ncat "{tmp_path}/out.txt"\ncat "{tmp_path}/err.txt" >&2\nexit {rc}\n',
        encoding="utf-8",
    )
    return script


def _run_quiet(
    tmp_path: Path, script: Path, *args: str
) -> tuple[subprocess.CompletedProcess, Path]:
    out = tmp_path / "captured.json"
    bash = shutil.which("bash")
    assert bash
    proc = subprocess.run(  # noqa: S603 - script del propio repo y comando falso del test
        [bash, str(AZ_QUIET), str(out), bash, str(script), *args],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "TMPDIR": str(tmp_path)},
        timeout=30,
        check=False,
    )
    return proc, out


needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="sin bash")


@needs_bash
def test_az_quiet_failure_shows_only_codes(tmp_path):
    script = _fake_cmd(tmp_path, stdout=f'{{"id": "{FAKE_SUB}"}}', stderr=FAKE_ARM_ERROR, rc=3)
    proc, out = _run_quiet(tmp_path, script, "deployment", "group", "validate", "--rg", "rgsecret")

    assert proc.returncode == 3
    shown = proc.stdout + proc.stderr
    for leak in LEAKS:
        assert leak not in shown, leak
    assert "InvalidTemplateDeployment" in shown
    assert "PrivateIPAddressInReservedRange" in shown
    assert "SubnetOverlap" in shown
    # Un paréntesis en mitad del mensaje no es un código (podría ser un nombre de recurso).
    assert "vaultsecretname" not in shown
    # La salida estándar del comando fallido no se queda en disco.
    assert out.read_text(encoding="utf-8") == ""
    # No quedan ficheros temporales con el error.
    assert not list(tmp_path.glob("az-quiet.*"))


@needs_bash
def test_az_quiet_unknown_error_says_unknown(tmp_path):
    script = _fake_cmd(tmp_path, stdout="", stderr=f"boom {FAKE_SUB}\n", rc=1)
    proc, _ = _run_quiet(tmp_path, script)
    assert proc.returncode == 1
    assert "desconocido" in proc.stdout
    assert FAKE_SUB not in proc.stdout + proc.stderr


@needs_bash
def test_az_quiet_success_keeps_stdout_and_prints_nothing(tmp_path):
    script = _fake_cmd(tmp_path, stdout='{"changes": []}', stderr="WARNING: algo\n", rc=0)
    proc, out = _run_quiet(tmp_path, script)
    assert proc.returncode == 0
    assert proc.stdout == "" and proc.stderr == ""
    assert out.read_text(encoding="utf-8") == '{"changes": []}'


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _uses(job: dict) -> list[str]:
    return [s["uses"] for s in job.get("steps", []) if "uses" in s]


def test_all_actions_pinned_by_sha():
    for path in WORKFLOWS.glob("*.yml"):
        wf = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in wf["jobs"].items():
            for uses in _uses(job):
                assert SHA_PIN.match(uses), f"{path.name}:{job_name}: {uses}"


def test_images_attest_permissions_only_in_attest_job():
    wf = _workflow("images.yml")
    assert set(wf["permissions"]) == {"contents"}
    build, attest = wf["jobs"]["build"], wf["jobs"]["attest"]
    assert "id-token" not in build["permissions"]
    assert "attestations" not in build["permissions"]
    assert attest["permissions"]["id-token"] == "write"
    assert attest["permissions"]["attestations"] == "write"
    uses = _uses(attest)
    assert any(u.startswith("actions/attest-build-provenance@") for u in uses)
    assert any(u.startswith("actions/attest@") for u in uses)
    for step in attest["steps"]:
        if "uses" in step:
            assert step["with"]["push-to-registry"] is True
            assert step["with"]["subject-digest"] == "${{ env.DIGEST }}"
    # BuildKit y el generador del SBOM, por digest.
    for key in ("BUILDKIT_IMAGE", "SBOM_GENERATOR"):
        assert re.search(r"@sha256:[0-9a-f]{64}$", wf["env"][key]), key


def test_no_workflow_of_this_repo_deploys_to_azure():
    # ADR-0025: despliega la factoría de la plataforma con sus identidades. Este repo solo
    # construye y atesta la imagen y valida el módulo; ningún workflow entra en Azure.
    for path in WORKFLOWS.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "azure/login@" not in text, path.name
        assert "az deployment" not in text, path.name
        assert "terraform apply" not in text and "terraform plan" not in text, path.name
        wf = yaml.safe_load(text)
        for job_name, job in wf["jobs"].items():
            assert "id-token" not in job.get("permissions", {}) or path.name == "images.yml", (
                f"{path.name}:{job_name}"
            )
    assert not (WORKFLOWS / "deploy.yml").exists()
    assert (LEGACY / "workflows" / "deploy.yml").exists()


def test_dockerfile_base_pinned_by_digest():
    froms = [
        line
        for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
        if line.startswith("FROM ")
    ]
    assert len(froms) == 2  # portal (node) + imagen final (python)
    for line in froms:
        # Digest obligatorio; solo se admite detrás el alias de la etapa (`AS web`).
        assert re.search(r"@sha256:[0-9a-f]{64}( AS [a-z][a-z0-9_-]*)?$", line), line
    assert "COPY --from=web /web/dist ./web/dist" in (ROOT / "Dockerfile").read_text("utf-8")


def test_dockerignore_keeps_local_web_files_out():
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for entry in ("web/node_modules", "web/dist", "web/.env*"):
        assert entry in ignore, entry


def test_dependabot_covers_every_ecosystem_weekly():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    seen = {(u["package-ecosystem"], u["directory"]) for u in cfg["updates"]}
    assert {("docker", "/"), ("github-actions", "/"), ("npm", "/web"), ("uv", "/")} <= seen
    assert all(u["schedule"]["interval"] == "weekly" for u in cfg["updates"])


def test_pipeline_condition_restricts_principal_ids():
    # Referencia (ADR-0025): el Bicep ya no se despliega; el diseño de la condición se conserva.
    text = (LEGACY / "platform" / "modules" / "pipeline-identity.bicep").read_text(encoding="utf-8")
    condition = next(line for line in text.splitlines() if line.startswith("var condition ="))
    for source in ("@Request", "@Resource"):
        for attr in ("RoleDefinitionId", "PrincipalId", "PrincipalType"):
            assert f"{source}[Microsoft.Authorization/roleAssignments:{attr}]" in condition
    assert "{${principalList}}" in condition
    # El pipeline ya no crea identidades: las crea la plataforma y main.bicep las referencia.
    main = (LEGACY / "main.bicep").read_text(encoding="utf-8")
    assert "modules/identities-existing.bicep" in main
    assert "'modules/identities.bicep'" not in main
    platform = (LEGACY / "platform" / "platform.bicep").read_text(encoding="utf-8")
    assert "'../modules/identities.bicep'" in platform
