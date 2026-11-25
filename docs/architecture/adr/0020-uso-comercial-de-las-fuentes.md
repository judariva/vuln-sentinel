---
adr: "0020"
titulo: Uso comercial de las fuentes y fuentes aisladas
estado: aceptado
fecha: 2026-11-25
afecta: [CMP-003, SRC-003, SRC-006, SRC-009, SRC-013]
sustituye: null
---

## Contexto

El producto se monetizará si funciona (P-3). P-5 pide comprobar si los términos de VulnCheck
admiten un producto de pago. Cada fuente lleva en el plan una columna de «uso comercial» comprobada
con la URL de sus términos. Las fuentes que no lo admitan se marcan y se aíslan. Antes de
monetizar, Juan hace una revisión legal, que queda fuera de este repo.

## Decisión

1. **VulnCheck KEV queda fuera de la v1**: no entra en el feed ni en las reglas. Sus términos de
   servicio (revisión del 06-07-2026), que se aplican también al uso gratuito y community, dicen:

   > «Customer may not make the Services Data available for free or under an open source or
   > similar license.» ([service-terms](https://vulncheck.com/service-terms))

   Eso choca ya con el feed público y gratuito, no solo con la oferta de pago. Además exigen
   atribución destacada, prohíben entrenar IA y prohíben productos que compitan con VulnCheck.
   **Para que vuelva a entrar** hace falta una de dos cosas: una confirmación por escrito de
   VulnCheck que cubra un feed público gratuito y una oferta de pago, o una licencia de pago. En
   ese caso, este ADR se sustituye.
2. **INCIBE-CERT: solo enlace.** Su aviso legal exige «que no se pretenda un uso comercial» y prohíbe
   la transformación sin autorización previa ([aviso legal](https://www.incibe.es/aviso-legal)). Se
   usan los hechos (el identificador CVE) y se enlaza; no se reproduce texto.
3. **nginx.org y avisos de fabricante sin licencia: hechos y enlace.** Versiones, CVE y fix sí; no
   se copia texto (© F5, «All rights reserved»).
4. **OSV.dev: filtro por fuente.**
   - Se **excluye** Chainguard/Wolfi (CC-BY-NC-ND 4.0).
   - Ubuntu y Alpine (CC-BY-SA 4.0) se marcan `share_alike` para la revisión legal.
   - El resto (CC-BY y CC0) se atribuye.
5. **Exploit-DB (GPL-2.0): solo metadatos.** Se usa como señal (identificador, tipo y enlace); no se
   redistribuye el CSV ni el código.
6. **GitHub API: dentro de los límites.** Uso comercial permitido; no se comparten tokens para
   superar los límites. El código de los PoC conserva la licencia de su autor: se enlaza, no se
   aloja.
7. Cada fuente lleva en `config/sources.yaml` (F1a) los campos `commercial_use` (yes, no o
   conditional), `terms_url`, `checked_at` e `isolation` (none, link_only, facts_only o excluded).
   El código no permite que una fuente `excluded` entre en el feed. Un test lo comprueba.

## Alternativas descartadas

- Usar VulnCheck solo internamente para decidir el nivel: el nivel publicado derivaría de sus datos
  y el feed es gratuito. Se descarta hasta tener el permiso por escrito.

## Consecuencias

- **A** se apoya en CISA KEV, en SSVC `exploitation = active` y en avisos oficiales verificados.
  Se pierde la ventaja temporal de VulnCheck. La métrica «ventaja sobre KEV» medirá si eso se nota.
- `NOTICE` deja de citar VulnCheck.

## Evidencia (2026-11-25)

Verificado por la sesión principal:
- https://vulncheck.com/service-terms
- https://www.incibe.es/aviso-legal

Del informe de investigación, con cita en `PLAN.md` §4:
- https://docs.vulncheck.com/community/vulncheck-kev/attribution
- https://google.github.io/osv.dev/data/
- https://gitlab.com/exploit-database/exploitdb
- https://cert.europa.eu/legal-notice
- https://docs.github.com/en/site-policy/github-terms/github-terms-of-service

Los términos de OffSec (exploit-db.com/terms) quedan SIN VERIFICAR: la página devuelve 403.
