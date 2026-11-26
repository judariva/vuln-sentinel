# Fixtures de los conectores (T3)

Recortes pequeños de fuentes públicas, descargados el 2026-11-26 y recortados a mano. Los tests no
hacen llamadas de red: un transporte simulado (`tests/fakes.py`) sirve estos ficheros.

| Fichero | Origen | Licencia | Recorte |
|---|---|---|---|
| `cvelistv5/deltaLog.json` | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json` | CVE Program Terms of Use (licencia de MITRE; reproducir su aviso de copyright) | 2 entradas reales con 1 CVE cada una |
| `cvelistv5/CVE-2026-131916.json`, `cvelistv5/CVE-2026-103406.json` | `…/cvelistV5/main/cves/2026/…` | Ídem | Registros reales; se quitan `supportingMedia`, `orgId` y algunos textos |
| `cisa-kev/kev.json` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (catálogo 2026.11.25) | CC0 1.0 | 3 entradas reales; `count` ajustado a 3; sin `shortDescription`, `requiredAction` ni `notes` |
| `epss/epss_scores.csv` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (enlazado desde `https://www.first.org/epss/data`) | Uso libre, atribución pedida (FIRST, FAQ de EPSS) | Cabecera real y 4 filas reales; sin comprimir (el test lo comprime) |
| `ghsa/page1.json`, `ghsa/page2.json` | `https://api.github.com/advisories?type=reviewed&per_page=5` | CC-BY 4.0; atribución con el enlace `https://github.com/advisories/<GHSA>` | 2 avisos reales, uno por página; sin `description`, `references`, `credits` ni `cvss` |
| `osv/crates.io/RUSTSEC-2021-0003.json` | `https://osv-vulnerabilities.storage.googleapis.com/crates.io/RUSTSEC-2021-0003.json` | CC0 1.0 (Rust Advisory Database; el registro lo declara en `database_specific.license`) | Real, sin `details` |
| `osv/modified_id.csv` | **Sintético**, con el formato de `modified_id.csv` | — | Líneas inventadas para probar la política por fuente |
| `osv/Alpine/ALPINE-CVE-2099-0001.json` | **Sintético** | — | No se guarda ningún registro real de Alpine ni de Ubuntu (CC-BY-SA) |
| `osv/npm/GHSA-0000-0000-0001.json` | **Sintético** | — | Aviso inventado con un `affected` de Wolfi, que el conector descarta |
| `metasploit/modules_metadata_base.json` (T7) | `https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json` | BSD-3-Clause, Copyright 2006-2026, Rapid7, Inc. | 3 módulos reales (un `exploit/`, un `auxiliary/dos/` y un `post/` sin CVE); sin `author`, `description` ni campos de red |
| `exploitdb/files_exploits.csv` (T7) | **Sintético**, con la cabecera real de `files_exploits.csv` | — | 4 filas inventadas (`remote`, `dos`, `webapps`, `local`); no se guarda ninguna fila real (GPL-2.0, solo metadatos) |
| `nomisec/commits.json`, `nomisec/commit-a.json`, `nomisec/commit-b.json` (T7) | **Sintéticos**, con la forma de la API de commits de GitHub | — | SHA inventados; solo los campos que lee el conector |
| `nomisec/CVE-2099-0301.json` (T7) | **Sintético**, con la forma de un fichero de PoC-in-GitHub | — | Repositorios y cuentas ficticios; la descripción lleva un intento de inyección que no se debe guardar |
| `nomisec/CVE-2018-3260.json` (T7) | `https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2018/CVE-2018-3260.json` | CC0 1.0 | 1 entrada real, sin `description` ni campos de avatar |
| `nginx2root/` (T12) | cvelistV5, NVD (registro e historial), API de GitHub (metadatos), nomi-sec y CISA KEV | Ver `nginx2root/README.md` | Snapshots reconstruidos de la prueba de aceptación R6; origen, hashes y recortes en su README |

Las heurísticas `poc_suspicious` se prueban con repositorios, ficheros, binarios y blobs
**sintéticos** que se fabrican en `tests/test_exploit_sources.py`: no hay código de PoC ni malware
real en el repositorio.

No hay ningún fichero de Chainguard/Wolfi (CC-BY-NC-ND), de VulnCheck ni de la EUVD. Las CVE
`CVE-2099-*` son ficticias.

Atribución: datos de CVE © The MITRE Corporation, bajo los CVE Program Terms of Use; EPSS de FIRST
(https://www.first.org/epss/); avisos de la GitHub Advisory Database
(https://github.com/advisories), CC-BY 4.0.
