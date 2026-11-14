-- CENTINELA — inmutabilidad de la bitácora de auditoría.
--
-- "Registros auditables inmutables" no significa solo una cadena de
-- hashes en la aplicación: significa que el ROL de base de datos que usa
-- el backend no tiene, a nivel de motor, el permiso de modificar lo ya
-- escrito. Aunque un bug (o un atacante con RCE en centinela-core) intente
-- un UPDATE o DELETE sobre event/audit_log, PostgreSQL lo rechaza antes de
-- que llegue a ejecutarse.
--
-- El rol de la aplicación sigue pudiendo INSERT/SELECT con normalidad; lo
-- único que pierde es la capacidad de alterar o borrar filas existentes
-- en las dos tablas que son evidencia forense.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'centinela_app') THEN
        CREATE ROLE centinela_app LOGIN PASSWORD 'change-me-in-dev';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE centinela TO centinela_app;
GRANT USAGE ON SCHEMA public TO centinela_app;

GRANT SELECT, INSERT ON event TO centinela_app;
GRANT SELECT, INSERT ON audit_log TO centinela_app;
GRANT SELECT ON rule, attack_technique TO centinela_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO centinela_app;

-- Revocación explícita: aunque GRANT ya es restrictivo por defecto, se deja
-- constancia explícita de la intención para que quede auditable en el
-- propio script, no solo implícito por omisión.
REVOKE UPDATE, DELETE, TRUNCATE ON event FROM centinela_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM centinela_app;
REVOKE UPDATE, DELETE, TRUNCATE ON rule, attack_technique FROM centinela_app;
