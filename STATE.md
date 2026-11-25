# Estado · vuln-sentinel

Actualizado: 2026-11-25.

## Fase actual: plan cerrado salvo J-2; siguiente, F1a-0

| Elemento | Estado |
|---|---|
| Licencia | Todo Apache-2.0 (ADR-0011). ADR-0018 (open core) rechazado. Contribuciones con DCO (`CONTRIBUTING.md`) |
| Sostenibilidad | Donaciones, no venta. **ADR-0021 aceptado**: lista on-chain pregenerada offline (en secret) + Phoenix con totales manuales, detrás de `donations.enabled`, en la F4b |
| Transparencia | Pantalla pública «Coste del proyecto» (§9, §10). Tablas `cost_daily` y `donation_received`, sin datos del donante; test que lo comprueba |
| Redes | ADR-0017 propuesto: **Zernio** recomendada; Buffer descartado por su cláusula 4.2(n). Pendiente de Juan (J-2) |
| VulnCheck KEV | Fuera (ADR-0020; J-3 cerrada) |
| ADR | 0001–0021. Propuesto: 0017. Rechazado: 0018 |
| Repo | **Privado** en GitHub. Pasa a público al cerrar la F1a, tras una búsqueda de fugas sobre todo el historial (J-7) |
| `main` | Sin protección de GitHub mientras sea privado (sin GitHub Pro, J-8). **Regla 9 de `CLAUDE.md`**: ninguna sesión hace push a `main`; solo ramas y PR; fusiona Juan. Hook `pre-push` local: `bash .githooks/install.sh`. Al hacerlo público se aplica la protección de rama |
| PR abiertos | #1 (estado de la protección de `main`) y el de esta rama, apilado sobre #1. Los fusiona Juan |

## Pendiente de Juan

- Fusionar los PR abiertos (primero #1).
- J-2: aceptar o no Zernio (ADR-0017).

## Siguiente: F1a-0 (sesión nueva)

1. Instalar el hook (`bash .githooks/install.sh`) y crear una rama desde `main`.
2. Scripts que generan `config/exposed-products.yaml` y `config/trusted-exploit-authors.yaml` con
   el criterio escrito en cada fichero, a partir de datos públicos (KEV, metadatos de Metasploit,
   `credits` de registros CVE), de forma reproducible (fecha de corte y hash de las entradas).
3. **PR con las dos listas para que Juan las revise ANTES de cualquier fixture de nginx2root**
   (R7). No se añade a mano ningún autor ni producto pensando en el caso de prueba.
4. Cuando Juan fusione ese PR, empieza la F1a: modelo de datos, `config/sources.yaml` con uso
   comercial y aislamiento, reglas, colectores (cvelistV5, CISA KEV, nomi-sec, búsqueda de GitHub,
   nginx.org), feed completo y de alertas, firma, API y reconstrucción de nginx2root.

La búsqueda de fugas de cada push se registra en `local/` (informe de la sesión), no aquí.
