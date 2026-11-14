# Borra y resiembra los eventos/auditoría entre ensayos del pitch (fase F5).
# La cadena de hashes empieza de nuevo limpia (GENESIS_HASH) tras el reset.
# Uso: ./scripts/reset-db.ps1
$ErrorActionPreference = "Stop"

$postgresUser = if ($env:POSTGRES_USER) { $env:POSTGRES_USER } else { "centinela" }
$postgresDb = if ($env:POSTGRES_DB) { $env:POSTGRES_DB } else { "centinela" }

docker compose exec -T centinela-db psql -U $postgresUser -d $postgresDb `
    -c "TRUNCATE audit_log, event RESTART IDENTITY CASCADE;"

Write-Host "event y audit_log reiniciados. La cadena de hashes vuelve a GENESIS_HASH."
