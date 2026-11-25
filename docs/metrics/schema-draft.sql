-- Borrador del esquema (F0). Fuente de verdad para escribir las consultas de métricas (R5).
-- En F1a se convierte en migraciones de Alembic; este fichero se mantiene alineado o se retira.
-- Todo hecho lleva source_published_at (cuándo dice la fuente) y observed_at (cuándo lo vimos).

CREATE TYPE alert_level AS ENUM ('none', 'C', 'B', 'A');
CREATE TYPE impact_class AS ENUM ('rce', 'auth_bypass', 'arbitrary_rw', 'other');
CREATE TYPE run_status AS ENUM ('ok', 'partial', 'unknown');
-- ADR-0022: open = redistribuible; restricted = solo para quien tenga la licencia `licensee`.
-- Toda tabla con datos de fuentes lleva license_class y licensee con el mismo CHECK. La instancia
-- pública nunca guarda filas 'restricted' (guarda en código y auditoría, tests/test_license_rights).
CREATE TYPE license_class AS ENUM ('open', 'restricted');

CREATE TABLE source (
    name                   text PRIMARY KEY,
    baseline_completed_at  timestamptz,          -- NULL = la carga inicial aún no ha terminado
    freshness_threshold    interval NOT NULL,
    license_class          license_class NOT NULL,   -- la que declara su conector
    licensee               text,
    CONSTRAINT source_license_ck CHECK (
        (license_class = 'open' AND licensee IS NULL)
        OR (license_class = 'restricted' AND licensee IS NOT NULL))
);

CREATE TABLE source_run (
    id                      bigserial PRIMARY KEY,
    source                  text NOT NULL REFERENCES source (name),
    started_at              timestamptz NOT NULL,
    finished_at             timestamptz,
    status                  run_status NOT NULL,
    items_seen              integer NOT NULL DEFAULT 0,
    items_new               integer NOT NULL DEFAULT 0,
    error                   text,
    last_item_published_at  timestamptz
);

CREATE TABLE vulnerability (
    cve_id               text PRIMARY KEY,
    cna                  text,
    cvss_vector          text,
    cvss_source          text,
    cwe                  text[] NOT NULL DEFAULT '{}',
    impact_class         impact_class NOT NULL DEFAULT 'other',
    vendor               text,
    product              text,
    source_published_at  timestamptz NOT NULL,
    observed_at          timestamptz NOT NULL,
    withdrawn_at         timestamptz,
    baseline             boolean NOT NULL DEFAULT false,
    source               text NOT NULL REFERENCES source (name),
    license_class        license_class NOT NULL,
    licensee             text,
    CONSTRAINT vulnerability_license_ck CHECK (
        (license_class = 'open' AND licensee IS NULL)
        OR (license_class = 'restricted' AND licensee IS NOT NULL))
);

CREATE TABLE affected_product (
    id                   bigserial PRIMARY KEY,
    cve_id               text NOT NULL REFERENCES vulnerability (cve_id),
    vendor               text,
    product              text,
    cpe                  text,
    purl                 text,
    ecosystem            text,
    ranges               jsonb NOT NULL DEFAULT '[]',
    range_source         text NOT NULL,
    category             text,                   -- de config/exposed-products.yaml; NULL = no expuesto
    source_published_at  timestamptz NOT NULL,
    observed_at          timestamptz NOT NULL,
    source               text NOT NULL REFERENCES source (name),  -- conector; range_source = quién da el rango
    license_class        license_class NOT NULL,
    licensee             text,
    CONSTRAINT affected_product_license_ck CHECK (
        (license_class = 'open' AND licensee IS NULL)
        OR (license_class = 'restricted' AND licensee IS NOT NULL))
);

-- Solo inserción: el historial de una señal es la propia tabla.
CREATE TABLE signal (
    id                   bigserial PRIMARY KEY,
    cve_id               text NOT NULL REFERENCES vulnerability (cve_id),
    kind                 text NOT NULL,          -- kev_cisa, kev_vulncheck, ssvc, epss, exploit, fix, mitigation, vendor_exploited
    value                jsonb NOT NULL,
    source               text NOT NULL REFERENCES source (name),
    url                  text,
    baseline             boolean NOT NULL DEFAULT false,
    source_published_at  timestamptz,            -- NULL si la fuente no da hora (KEV: solo fecha)
    observed_at          timestamptz NOT NULL,
    license_class        license_class NOT NULL,
    licensee             text,
    CONSTRAINT signal_license_ck CHECK (
        (license_class = 'open' AND licensee IS NULL)
        OR (license_class = 'restricted' AND licensee IS NOT NULL))
);

-- Una fila por evaluación de reglas (R5): permite el embudo.
CREATE TABLE rule_evaluation (
    id                 bigserial PRIMARY KEY,
    cve_id             text NOT NULL REFERENCES vulnerability (cve_id),
    evaluated_at       timestamptz NOT NULL,
    trigger_signal_id  bigint REFERENCES signal (id),
    eligible           boolean NOT NULL,         -- §5.1: reciente o señal nueva tras la carga inicial
    exposed            boolean NOT NULL,
    impact_class       impact_class NOT NULL,
    exploit_rule       text,                     -- E1..E5 o NULL
    result_level       alert_level NOT NULL,
    rules_version      text NOT NULL
);

CREATE TABLE alert (
    alert_id            text PRIMARY KEY,        -- VS-CVE-…
    cve_id              text NOT NULL UNIQUE REFERENCES vulnerability (cve_id),
    level               alert_level NOT NULL,
    reason              text[] NOT NULL,
    status              text NOT NULL,
    first_published_at  timestamptz NOT NULL,
    modified_at         timestamptz NOT NULL
);

CREATE TABLE alert_level_history (
    id                 bigserial PRIMARY KEY,
    alert_id           text NOT NULL REFERENCES alert (alert_id),
    level_from         alert_level NOT NULL,
    level_to           alert_level NOT NULL,
    reason             text[] NOT NULL,
    trigger_signal_id  bigint REFERENCES signal (id),
    decided_by         text NOT NULL,            -- rules | ai | juan
    at                 timestamptz NOT NULL
);

CREATE TABLE ai_call (
    id                 bigserial PRIMARY KEY,
    alert_id           text REFERENCES alert (alert_id),
    kind               text NOT NULL,            -- agent | draft
    model              text NOT NULL,
    proposed_level     alert_level,
    final_level        alert_level,
    tokens_in          integer NOT NULL,
    tokens_out         integer NOT NULL,
    cost_usd           numeric(10, 6) NOT NULL,
    trace_id           text,
    dossier            jsonb,
    blocked_downgrade  boolean NOT NULL DEFAULT false,
    at                 timestamptz NOT NULL,
    -- El dosier cita fuentes: hereda la clase más restrictiva de lo que leyó el agente.
    license_class      license_class NOT NULL,
    licensee           text,
    CONSTRAINT ai_call_license_ck CHECK (
        (license_class = 'open' AND licensee IS NULL)
        OR (license_class = 'restricted' AND licensee IS NOT NULL))
);

CREATE TABLE publication (
    id            bigserial PRIMARY KEY,
    alert_id      text REFERENCES alert (alert_id),
    channel       text NOT NULL,
    status        text NOT NULL,
    approved_by   text,
    approved_at   timestamptz,
    sent_at       timestamptz,
    external_ref  text
);

CREATE TABLE verdict (
    alert_id  text NOT NULL REFERENCES alert (alert_id),
    verdict   text NOT NULL CHECK (verdict IN ('util', 'ruido')),
    note      text,
    at        timestamptz NOT NULL
);

-- Transparencia de costes (§9). Coste real leído por API de Azure Cost Management (RG) y de la
-- facturación de Cloudflare.
CREATE TABLE cost_daily (
    day        date NOT NULL,
    provider   text NOT NULL CHECK (provider IN ('azure', 'cloudflare', 'other')),
    service    text NOT NULL DEFAULT '',
    amount_eur numeric(12, 4) NOT NULL,
    source_published_at  timestamptz,
    observed_at          timestamptz NOT NULL,
    PRIMARY KEY (day, provider, service)
);

-- Donaciones recibidas (ADR-0021). SIN datos del donante: ni nombre, ni IP, ni dirección de origen,
-- ni mensaje. Solo importe, fecha y canal. La referencia externa es opaca (id de factura o txid).
CREATE TABLE donation_received (
    id           bigserial PRIMARY KEY,
    channel      text NOT NULL CHECK (channel IN ('lightning', 'onchain')),
    amount_sats  bigint NOT NULL CHECK (amount_sats > 0),
    received_at  timestamptz NOT NULL,
    observed_at  timestamptz NOT NULL,
    external_ref text NOT NULL UNIQUE
);

CREATE TABLE metric_daily (
    day        date NOT NULL,
    metric     text NOT NULL,
    dimension  text NOT NULL DEFAULT '',
    value      double precision NOT NULL,
    PRIMARY KEY (day, metric, dimension)
);
