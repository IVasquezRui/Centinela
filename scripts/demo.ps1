# Lanza el entorno completo y dispara el corpus de tráfico mixto de la demo.
# Uso: ./scripts/demo.ps1 [-Total 1000] [-MaliciousRatio 0.3]
param(
    [int]$Total = 1000,
    [double]$MaliciousRatio = 0.3
)

docker compose up --build -d
docker compose ps

Write-Host "Esperando a que centinela-core esté healthy..."
docker compose exec centinela-core python -c "import urllib.request; urllib.request.urlopen('http://localhost:3000/api/health')"

docker compose --profile demo run --rm attacker-sim --total $Total --malicious-ratio $MaliciousRatio
