-- Consultas de las métricas principales contra schema-draft.sql (R5).
-- Parámetro :day = día a calcular (date, UTC). job-daily las ejecuta y guarda en metric_daily.

-- name: funnel_daily
-- Embudo del día: ingeridas → elegibles → candidatas → A/B/C.
WITH ev AS (
    SELECT DISTINCT ON (cve_id) cve_id, eligible, exposed, impact_class, result_level
    FROM rule_evaluation
    WHERE evaluated_at >= CAST(:day AS date) AND evaluated_at < CAST(:day AS date) + 1
    ORDER BY cve_id, evaluated_at DESC
)
SELECT
    (SELECT count(*) FROM vulnerability
      WHERE NOT baseline
        AND observed_at >= CAST(:day AS date) AND observed_at < CAST(:day AS date) + 1) AS ingested,
    count(*) FILTER (WHERE eligible)                                                    AS eligible,
    count(*) FILTER (WHERE eligible AND exposed AND impact_class <> 'other')            AS candidates,
    count(*) FILTER (WHERE result_level = 'A')                                          AS level_a,
    count(*) FILTER (WHERE result_level = 'B')                                          AS level_b,
    count(*) FILTER (WHERE result_level = 'C')                                          AS level_c
FROM ev;

-- name: detection_time_by_level
-- Tiempo de detección: desde que la fuente publicó el hecho que provocó el nivel hasta que
-- vuln-sentinel lo alcanzó. Si la señal no tiene hora (KEV), se usa la publicación de la CVE.
SELECT
    h.level_to AS level,
    percentile_cont(0.5)  WITHIN GROUP (ORDER BY extract(epoch FROM h.at - coalesce(s.source_published_at, v.source_published_at))) AS p50_seconds,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM h.at - coalesce(s.source_published_at, v.source_published_at))) AS p95_seconds,
    count(*) AS n
FROM alert_level_history h
JOIN alert a          ON a.alert_id = h.alert_id
JOIN vulnerability v  ON v.cve_id = a.cve_id
LEFT JOIN signal s    ON s.id = h.trigger_signal_id
WHERE h.decided_by IN ('rules', 'ai')
  AND h.at >= CAST(:day AS date) AND h.at < CAST(:day AS date) + 1
GROUP BY h.level_to;

-- name: lead_over_kev
-- Ventaja sobre KEV (R4): observed_at de la señal kev_cisa menos la primera alerta B o C.
-- KEV solo publica fecha (dateAdded): la precisión es la del sondeo (±15 min).
-- Positivo = vuln-sentinel alertó antes que la entrada en KEV.
WITH first_bc AS (
    SELECT a.cve_id, min(h.at) AS first_bc_at
    FROM alert_level_history h
    JOIN alert a ON a.alert_id = h.alert_id
    WHERE h.level_to IN ('B', 'C')
    GROUP BY a.cve_id
), kev AS (
    SELECT cve_id, min(observed_at) AS kev_observed_at
    FROM signal
    WHERE kind = 'kev_cisa' AND NOT baseline
    GROUP BY cve_id
)
SELECT
    kev.cve_id,
    extract(epoch FROM kev.kev_observed_at - first_bc.first_bc_at) / 3600.0 AS lead_hours,
    '±15 min' AS precision
FROM kev
JOIN first_bc USING (cve_id)
WHERE kev.kev_observed_at >= CAST(:day AS date) AND kev.kev_observed_at < CAST(:day AS date) + 1;

-- name: misses
-- Fallos: altas de KEV (tras la carga inicial) en productos expuestos sin alerta B o A previa.
SELECT s.cve_id, s.observed_at AS kev_observed_at
FROM signal s
WHERE s.kind = 'kev_cisa'
  AND NOT s.baseline
  AND s.observed_at >= CAST(:day AS date) AND s.observed_at < CAST(:day AS date) + 1
  AND EXISTS (
      SELECT 1 FROM affected_product p
      WHERE p.cve_id = s.cve_id AND p.category IS NOT NULL
  )
  AND NOT EXISTS (
      SELECT 1
      FROM alert_level_history h
      JOIN alert a ON a.alert_id = h.alert_id
      WHERE a.cve_id = s.cve_id
        AND h.level_to IN ('B', 'A')
        AND h.at < s.observed_at
  );

-- name: ai_blocked_downgrades
-- IA: intentos de bajar el nivel bloqueados por max(determinista, IA).
SELECT count(*) AS blocked
FROM ai_call
WHERE blocked_downgrade
  AND at >= CAST(:day AS date) AND at < CAST(:day AS date) + 1;
