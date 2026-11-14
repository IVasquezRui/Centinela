# Genera los secretos locales del laboratorio (equivalente a gen-secrets.sh).
# Uso: ./scripts/gen-secrets.ps1
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$secretsDir = Join-Path $root "secrets"
New-Item -ItemType Directory -Force -Path $secretsDir | Out-Null

function New-RandomSecret([string]$Name) {
    $path = Join-Path $secretsDir $Name
    if ((Test-Path $path) -and ((Get-Item $path).Length -gt 0)) {
        Write-Host "existe:    $Name (no se toca)"
        return
    }
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    Set-Content -Path $path -Value $hex -NoNewline -Encoding ascii

    # Solo el usuario actual puede leer/escribir el secreto.
    icacls $path /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
    Write-Host "generado:  $Name"
}

New-RandomSecret "postgres_password.txt"
New-RandomSecret "gov_mysql_root_password.txt"

$apiKey = Join-Path $secretsDir "deepseek_api_key.txt"
if (-not (Test-Path $apiKey)) {
    Set-Content -Path $apiKey -Value "" -NoNewline -Encoding ascii
    icacls $apiKey /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
    Write-Host "creado:    deepseek_api_key.txt (vacío = sin copiloto IA)"
}

Write-Host "Listo. Los secretos están en .gitignore (ver secrets/README.md)."
