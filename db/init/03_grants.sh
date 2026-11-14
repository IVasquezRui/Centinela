#!/bin/sh
# CENTINELA — inmutabilidad de la bitácora de auditoría.
#
# "Registros auditables inmutables" no significa solo una cadena de hashes en
# la aplicación: significa que el ROL de base de datos que usa el backend no
# tiene, a nivel de motor, el permiso de modificar lo ya escrito. Aunque un bug
# (o un atacante con RCE en centinela-core) intente un UPDATE o DELETE sobre
# event/audit_log, PostgreSQL lo rechaza antes de que llegue a ejecutarse.
#
# El rol de la aplicación sigue pudiendo INSERT/SELECT con normalidad; lo único
# que pierde es la capacidad de alterar o borrar filas existentes en las dos
# tablas que son evidencia forense.
#
# Este script es .sh y no .sql por dos razones de seguridad:
#   1. El password del rol no está escrito en el repositorio ni en .env: se
#      deriva con SHA-256 y separación de dominio a partir de POSTGRES_PASSWORD,
#      que el entrypoint de PostgreSQL ya cargó del secreto de Docker y mantiene
#      solo en memoria. Así no hace falta un archivo extra y el rol NO comparte
#      credencial con el superusuario (mismo secreto de origen, distinto valor).
#   2. El nombre de la base no se codifica a mano: se toma de POSTGRES_DB, así
#      que renombrar la BD en .env no rompe los GRANT.
set -eu

APP_PASSWORD="$(printf '%s' "centinela_app:${POSTGRES_PASSWORD}" | sha256sum | cut -d' ' -f1)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'centinela_app') THEN
        EXECUTE format('CREATE ROLE centinela_app LOGIN PASSWORD %L', '${APP_PASSWORD}');
    ELSE
        EXECUTE format('ALTER ROLE centinela_app WITH LOGIN PASSWORD %L', '${APP_PASSWORD}');
    END IF;
END
\$\$;

GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO centinela_app;
GRANT USAGE ON SCHEMA public TO centinela_app;

GRANT SELECT, INSERT ON event TO centinela_app;
-- Permite al worker de IA (app/ai/worker.py) enriquecer el evento con el
-- triage sin poder alterar ningún otro campo (motor, regla, severidad, etc.).
GRANT UPDATE (ai_summary, ai_status) ON event TO centinela_app;
GRANT SELECT, INSERT ON audit_log TO centinela_app;
GRANT SELECT ON rule, attack_technique TO centinela_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO centinela_app;

-- Revocación explícita: aunque GRANT ya es restrictivo por defecto, se deja
-- constancia explícita de la intención para que quede auditable en el propio
-- script, no solo implícito por omisión.
-- audit_log es estrictamente inmutable (WORM forense): ni siquiera las dos
-- columnas de triage son mutables ahí.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM centinela_app;
-- event no puede truncarse ni borrarse; su UPDATE ya quedó acotado arriba a
-- las dos columnas del triage por el GRANT granular, así que deliberadamente
-- NO se incluye UPDATE en este REVOKE de tabla completa, para no generar
-- ninguna ambigüedad sobre si el privilegio por columna sobrevive.
REVOKE DELETE, TRUNCATE ON event FROM centinela_app;
REVOKE UPDATE, DELETE, TRUNCATE ON rule, attack_technique FROM centinela_app;
EOSQL