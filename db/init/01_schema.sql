-- CENTINELA — esquema inicial (db/init/01_schema.sql)
-- Se ejecuta automáticamente al crear el volumen de centinela-db
-- (docker-entrypoint-initdb.d). NO reescribir a mano en producción: todo
-- cambio de esquema futuro va en un archivo nuevo numerado.

CREATE TABLE IF NOT EXISTS attack_technique (
    technique_id    VARCHAR(16) PRIMARY KEY,
    name            VARCHAR(128) NOT NULL,
    tactic          VARCHAR(64)  NOT NULL,
    description     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule (
    id              VARCHAR(32) PRIMARY KEY,
    category        VARCHAR(32) NOT NULL,
    severity        VARCHAR(16) NOT NULL,
    technique_id    VARCHAR(16) NOT NULL REFERENCES attack_technique(technique_id),
    description     TEXT NOT NULL,
    pattern         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip          VARCHAR(64) NOT NULL,
    method          VARCHAR(16) NOT NULL,
    path            TEXT NOT NULL,
    target          VARCHAR(64) NOT NULL,
    verdict         VARCHAR(16) NOT NULL CHECK (verdict IN ('block', 'allow')),
    rule_id         VARCHAR(32) REFERENCES rule(id),
    category        VARCHAR(32),
    severity        VARCHAR(16) CHECK (severity IN ('baja', 'media', 'alta', 'critica') OR severity IS NULL),
    technique_id    VARCHAR(16),
    ml_score        REAL,
    engine_us       INTEGER NOT NULL,
    payload_sample  TEXT,
    ai_summary      TEXT,
    ai_status       VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (ai_status IN ('pending', 'done', 'failed'))
);

-- Índices compuestos para los filtros del panel SOC (severidad, IP, fecha)
-- y para los agregados del Observatorio (verdict + ts, category, target).
CREATE INDEX IF NOT EXISTS idx_event_ts ON event (ts DESC);
CREATE INDEX IF NOT EXISTS idx_event_severity_ts ON event (severity, ts DESC);
CREATE INDEX IF NOT EXISTS idx_event_src_ip_ts ON event (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_event_verdict_ts ON event (verdict, ts DESC);
CREATE INDEX IF NOT EXISTS idx_event_category ON event (category) WHERE verdict = 'block';
CREATE INDEX IF NOT EXISTS idx_event_target ON event (target) WHERE verdict = 'block';
CREATE INDEX IF NOT EXISTS idx_event_ai_status ON event (ai_status) WHERE verdict = 'block';

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_id        BIGINT REFERENCES event(id),
    action          VARCHAR(32) NOT NULL,
    payload         TEXT NOT NULL,
    prev_hash       CHAR(64) NOT NULL,
    hash            CHAR(64) NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_id ON audit_log (event_id);

-- Ancla externa de la cadena de auditoría: registra el último eslabón (id y
-- hash) para detectar borrados del final de la cadena (truncamiento).
CREATE TABLE IF NOT EXISTS audit_anchor (
    id          SMALLINT PRIMARY KEY CHECK (id = 1),
    last_id     BIGINT NOT NULL,
    head_hash   CHAR(64) NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
