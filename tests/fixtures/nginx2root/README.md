# Snapshots reconstruidos de nginx2root (T12, prueba de aceptación R6)

Son **snapshots reconstruidos**: datos publicados, descargados el 2026-11-26 y recortados, no
grabaciones de lo que devolvían las API el 18/11. Los usa `tests/test_nginx2root_reconstruction.py`.
Nada de VulnCheck. Nada de código de PoC: del repositorio solo hay metadatos. Sin correos (regla
8): en los ficheros de NVD, los `source`/`sourceIdentifier` que eran un correo valen
`[correo retirado]`; la prueba no los usa.

| Fichero | Origen | Recorte |
|---|---|---|
| `cvelistv5/deltaLog.json` | `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json` (sha256 de la descarga `8c7a1407…a2823`) | Solo las entradas con `fetchTime` del 18/11 entre 14:00Z y 18:05Z. Se conservan todas esas horas (para que el conector vea un dato fresco) pero en `new`/`updated` solo quedan las dos CVE; `numberOfChanges` se recalcula |
| `cvelistv5/CVE-2026-123007.590851bd.json` | El fichero en el commit `590851bd0bba15c0fba1c1ed471758ff2341f3dd` (18/11 15:25:28Z), primera versión | Entero (sha256 `b2bd6f48…60507`) |
| `cvelistv5/CVE-2026-123007.07059e5c.json` | Commit `07059e5cb353a3860ad31fbea95956c728885075` (16:15:24Z): añade el SSVC de CISA | Entero (sha256 `06d10dc6…3245a`) |
| `cvelistv5/CVE-2026-123633.590851bd.json` | Commit `590851bd…` (15:25:28Z), primera versión | Entero (sha256 `f5e97c22…f1c31`) |
| `cvelistv5/CVE-2026-123633.35e04952.json` | Commit `35e04952aea5448a0d3d26601adbeaa6ffed21ec` (16:57:10Z): añade el SSVC de CISA | Entero (sha256 `a1103ad7…1f59`) |
| `cvelistv5/versions.json` | Lista de commits de cada fichero (`GET /repos/CVEProject/cvelistV5/commits?path=…`) | Solo los commits del 18/11 hasta las 18:00Z |
| `nvd/CVE-2026-123007.json` | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-123007` (sha256 `21219691…0bcab`) | Sin `descriptions`, `metrics` ni `configurations` |
| `nvd/CVE-2026-123007.history.json` | `https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2026-123007` (sha256 `dfaedc53…c7fe7`) | Sin los detalles de tipo `CPE Configuration` |
| `github/sfewer-r7.CVE-2026-123007.json` | `https://api.github.com/repos/sfewer-r7/CVE-2026-123007` (sha256 `a7500068…c6a7`) | Solo `id`, `full_name`, `owner`, `html_url`, `fork`, `private`, `visibility`, `created_at`, `pushed_at`, `updated_at` |
| `nomisec/first-listing.json` | Primer commit de nomi-sec que toca `2026/CVE-2026-123007.json` (`f186857237e25fb1ad5d9242acdcdcafdfba41fd`, 18/11 20:08:35Z) | Solo el commit, su hora, el número de repositorios del fichero y la entrada de `sfewer-r7` |
| `cvelistv5/CVE-2026-123007.{89edb96c,8f5b7cfd,6eca39f0}.json` (T14) | Versiones del registro en los commits `89edb96c18693b38ae4d8dcd87c464c425faf3fd` (19:40:59Z), `8f5b7cfd9a7c07f659ae44ee759ba2a669d11115` (19:52:50Z) y `6eca39f00ea29b77961243c99895c4d21c4b4cac` (20:17:41Z) | Enteros (sha256 `6c102d78…1669`, `fe1863a0…922e`, `9cf1450e…ae1c`) |
| `cvelistv5/CVE-2026-123633.{bc1b5d8c,8f5b7cfd,6eca39f0,253db544}.json` (T14) | Commits `bc1b5d8ce8f8170af5eb197bdb4595fa692a84d4` (19:28:22Z), `8f5b7cfd…` (19:52:50Z), `6eca39f0…` (20:17:41Z) y `253db544f18b9e04ecddb414410476c4128ddffd` (22:19:17Z) | Enteros (sha256 `34a1b865…75d7`, `bbb77fa4…89aa`, `4f34de35…af65`, `6f07cc13…c32`) |
| `cvelistv5/deltaLog.json` y `versions.json` (ampliados en T14) | Los mismos orígenes | El `deltaLog` va ahora del 18/11 14:00Z al 19/11 00:05Z (mismo recorte); `versions.json`, todos los commits del 18/11 |
| `cisa-kev/kev-2026.11.18.json` (T14) | `cisagov/kev-data` en el commit `a705bb0fa3ba6fc554cf8694c9c321364a4a094e` (18/11 23:57:33Z), catálogo 2026.11.18 con 1.786 entradas (sha256 `ad618e40…eef3`) | Cabecera y las 3 últimas entradas por `dateAdded`; comprobado antes del recorte que ninguna de las dos CVE está |
| `nomisec/commits.json` (T14) | `GET /repos/nomi-sec/PoC-in-GitHub/commits?since=2026-11-17T12:00:00Z&until=2026-11-19T01:00:00Z` (12 commits, sha256 `4f43fcc1…baa`) | sha, hora y mensaje de cada commit; `files` solo con los ficheros de las dos CVE, que añade por primera vez `f1868572` (el historial por ruta, `commits?path=2026/CVE-…json`, empieza en ese commit para las dos) |
| `nomisec/CVE-2026-123007.f1868572.json`, `nomisec/CVE-2026-123633.f1868572.json` (T14) | Los ficheros en el commit `f186857237e25fb1ad5d9242acdcdcafdfba41fd` (sha256 `4497c3c1…b7d` y `fea6e2b4…b20d`) | Por repositorio solo `id`, `full_name`, `owner.login`, `html_url`, `fork`, `created_at`, `pushed_at` (sin descripciones, THR-001) |
| `cisa-kev/kev-2026.11.17.json` | `cisagov/kev-data` en el commit `2b7b13557a4f585212ef3c4725cd2d8f7281d61a` (18/11 00:38Z; el siguiente es de las 23:57Z), catálogo 2026.11.17 con 1.782 entradas (sha256 `11ee3c54…7dee`) | Cabecera y las 3 últimas entradas por `dateAdded`; `count` = 3. Comprobado antes de recortar: ninguna de las dos CVE está en ese catálogo ni en el 2026.11.25 (`51e0a777…`, sha256 `a7636000…631a`) |

## Licencias

Leídas el 2026-11-26.

- **cvelistV5**: CVE Program Terms of Use (https://www.cve.org/Legal/TermsOfUse; texto leído en su
  fuente, https://github.com/CVEProject/cve-website, `src/views/Legal/TermsOfUse.vue`): «MITRE
  hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
  copyright license to reproduce, prepare derivative works of, publicly display, publicly perform,
  sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for
  such purposes is authorized provided that you reproduce MITRE's copyright designation and this
  license in any such copy.» CVE® es una marca de The MITRE Corporation.
- **CISA KEV**: https://github.com/cisagov/kev-data/blob/main/LICENSE: «The KEV database is
  distributed under the Creative Commons 0 1.0 License. You may use this data in any legal manner
  […] Use of the information does not authorize you to use the CISA Logo or DHS Seal».
- **PoC-in-GitHub (nomi-sec)**: https://github.com/nomi-sec/PoC-in-GitHub/blob/master/LICENSE:
  «Creative Commons Legal Code / CC0 1.0 Universal».
- **NVD**: https://nvd.nist.gov/developers/terms-of-use devolvió 403 el 2026-11-26: **SIN
  VERIFICAR** hoy. El plan (§4) la da como dominio público, con aviso fijo y sin sugerir aval; el
  texto literal del aviso no se ha podido leer.
- **API de GitHub (metadatos del repositorio)**: solo metadatos, sin código. Términos de la API
  (GitHub Terms of Service, §H, https://docs.github.com/en/site-policy/github-terms/github-terms-of-service):
  **SIN VERIFICAR** hoy; el plan (§4) los recoge para la búsqueda de GitHub.
