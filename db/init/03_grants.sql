-- CENTINELA — Inmutabilidad de la bitácora de auditoría y principio de mínimos privilegios (db/init/03_grants.sql)
--
-- Complemento SQL estándar de db/init/03_grants.sh para inicialización y migraciones.
--
-- La inmutabilidad de la evidencia forense no depende únicamente de la cadena de
-- hashes en la capa de aplicación: a nivel del motor PostgreSQL, el rol de la aplicación
-- ('centinela_app') TIENE PROHIBIDO modificar o eliminar registros ya asentados.
--
-- Aunque un atacante logre Ejecución Remota de Código (RCE) en el backend o exista un bug
-- en la lógica de negocio, cualquier intento de UPDATE o DELETE sobre 'audit_log' o 'event'
-- es abortado inmediatamente por el motor relacional.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'centinela_app') THEN
        CREATE ROLE centinela_app LOGIN;
    END IF;
END
$$;

-- Permisos de conexión y esquema
GRANT USAGE ON SCHEMA public TO centinela_app;

-- 1. Tabla event: Permite registrar y consultar eventos de seguridad
GRANT SELECT, INSERT ON event TO centinela_app;

-- 2. Enriquecimiento del Copiloto IA:
-- Permite al worker asíncrono (app/ai/worker.py) anexar exclusivamente el triage
-- redactado ('ai_summary') y marcar el estado ('ai_status'), sin poder alterar
-- bajo ninguna circunstancia los campos críticos (ts, src_ip, path, verdict, rule_id, etc.).
GRANT UPDATE (ai_summary, ai_status) ON event TO centinela_app;

-- 3. Tabla audit_log: Evidencia forense WORM (Write Once, Read Many)
-- Solo inserción y lectura para verificación de la cadena de hashes
GRANT SELECT, INSERT ON audit_log TO centinela_app;

-- 4. Catálogos estáticos: Solo lectura para joins y verificación de reglas
GRANT SELECT ON rule, attack_technique TO centinela_app;

-- 5. Secuencias de autoincremento para IDs de eventos y auditoría
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO centinela_app;

-- ============================================================================
-- REVOCACIONES EXPLÍCITAS DE SEGURIDAD (INMUTABILIDAD FORENSE)
-- ============================================================================

-- audit_log es estrictamente inmutable: ni siquiera los superusuarios de la app pueden alterarlo
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM centinela_app;

-- event no puede ser truncado ni purgado
REVOKE DELETE, TRUNCATE ON event FROM centinela_app;

-- Las tablas de catálogo no pueden ser alteradas por la aplicación
REVOKE UPDATE, DELETE, TRUNCATE ON rule, attack_technique FROM centinela_app;
