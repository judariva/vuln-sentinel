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
AZ_QUIET = ROOT / "infra" / "scripts" / "az-quiet.sh"
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


def test_deploy_verifies_provenance_before_azure_and_hides_az_errors():
    wf = _workflow("deploy.yml")
    steps = wf["jobs"]["deploy"]["steps"]
    names = [s.get("name", "") for s in steps]
    verify = names.index("Verificar la procedencia de la imagen")
    login = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("azure/login@"))
    validate = names.index("Validar la plantilla")
    assert verify < login < validate
    verify_run = steps[verify]["run"]
    assert "gh attestation verify" in verify_run
    assert "--repo" in verify_run and "--signer-workflow" in verify_run
    assert "exit 1" in verify_run
    for name in ("Validar la plantilla", "What-if (recuento de cambios)", "Desplegar"):
        run = steps[names.index(name)]["run"]
        assert "infra/scripts/az-quiet.sh" in run, name
        # Ninguna llamada a az deployment fuera del envoltorio.
        for line in run.splitlines():
            if "az deployment" in line:
                prev = run.splitlines()[run.splitlines().index(line) - 1]
                assert "az-quiet.sh" in prev, name


def test_dockerfile_base_pinned_by_digest():
    froms = [
        line
        for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
        if line.startswith("FROM ")
    ]
    assert froms
    for line in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", line), line


def test_dependabot_covers_every_ecosystem_weekly():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    seen = {(u["package-ecosystem"], u["directory"]) for u in cfg["updates"]}
    assert {("docker", "/"), ("github-actions", "/"), ("npm", "/web"), ("uv", "/")} <= seen
    assert all(u["schedule"]["interval"] == "weekly" for u in cfg["updates"])


def test_pipeline_condition_restricts_principal_ids():
    text = (ROOT / "infra" / "platform" / "modules" / "pipeline-identity.bicep").read_text(
        encoding="utf-8"
    )
    condition = next(line for line in text.splitlines() if line.startswith("var condition ="))
    for source in ("@Request", "@Resource"):
        for attr in ("RoleDefinitionId", "PrincipalId", "PrincipalType"):
            assert f"{source}[Microsoft.Authorization/roleAssignments:{attr}]" in condition
    assert "{${principalList}}" in condition
    # El pipeline ya no crea identidades: las crea la plataforma y main.bicep las referencia.
    main = (ROOT / "infra" / "main.bicep").read_text(encoding="utf-8")
    assert "modules/identities-existing.bicep" in main
    assert "'modules/identities.bicep'" not in main
    platform = (ROOT / "infra" / "platform" / "platform.bicep").read_text(encoding="utf-8")
    assert "'../modules/identities.bicep'" in platform
