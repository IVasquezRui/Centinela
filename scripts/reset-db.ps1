# Borra y resiembra los eventos/auditoría entre ensayos del pitch (fase F5).
# La cadena de hashes empieza de nuevo limpia (GENESIS_HASH) tras el reset.
# Uso: ./scripts/reset-db.ps1
$ErrorActionPreference = "Stop"

# Comillas simples a propósito: $POSTGRES_USER/$POSTGRES_DB se expanden DENTRO
# del contenedor, donde sí existen. En el host no hay credenciales (viven en
# secrets/), y antes el script caía a valores por defecto aunque la BD tuviera
# otro nombre de usuario o de base.
docker compose exec -T centinela-db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "TRUNCATE audit_log, event RESTART IDENTITY CASCADE;"'
if ($LASTEXITCODE -ne 0) { throw "El TRUNCATE falló (exit $LASTEXITCODE)" }

# Reinicia el core para vaciar la cuarentena en memoria del IPS y la cola.
docker compose restart centinela-core
if ($LASTEXITCODE -ne 0) { throw "No se pudo reiniciar centinela-core (exit $LASTEXITCODE)" }

Write-Host "event y audit_log reiniciados. La cadena de hashes vuelve a GENESIS_HASH."
Write-Host "centinela-core reiniciado: cuarentena IPS y cola en memoria vaciadas."
