# Vista de seguridad (borrador F0)

Versiones fijadas de los marcos: MITRE ATLAS **5.6.0**, ATT&CK **v20.1** (13-10-2026),
OWASP Top 10 for LLM Applications **2025**. NIST se fija en F5.

| Amenaza | Controles | Prueba |
|---|---|---|
| THR-001 | CTL-003 | eval `injection-advisory` |
| THR-002 | CTL-001 | test de monotonía |
| THR-003 | CTL-002 | eval de citas falsas |
| THR-004 | CTL-004 | test de herramienta |
| THR-005 | CTL-005 | revisión del contenedor |
| THR-006 | CTL-006 | bucle simulado |
| THR-007 | CTL-007 | carga inicial → 0 alertas |
| THR-008 | CTL-008 | curl directo al origen |
| THR-009 | CTL-009 | prueba de caos F3 |
| THR-010 | CTL-010 | autoasignación denegada |
