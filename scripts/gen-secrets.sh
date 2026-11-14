#!/bin/sh
# Genera los secretos locales del laboratorio (nunca se commitean).
#
#   ./scripts/gen-secrets.sh
#
# Idempotente: si el archivo existe y no está vacío, no lo sobreescribe.
# Ver secrets/README.md para rotarlos correctamente.
set -eu

cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets

random_hex() {
    # tr -d '\r\n' importa de verdad: en Git Bash para Windows, el openssl.exe
    # del sistema suele escribir \r\n al final. Un secreto con un \r colgando
    # provoca que la contraseña que arma el bootstrap de MySQL (leída por
    # shell, que solo recorta \n) deje de coincidir con la que usa PHP
    # (trim() sí recorta \r) — se autentica contra una cuenta y se verifica
    # contra otra, silenciosamente. Sin esto, cualquier cuenta de MySQL
    # creada a partir de estos secretos queda inservible en remoto.
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24 | tr -d '\r\n'
    else
        python3 -c 'import secrets; print(secrets.token_hex(24))' | tr -d '\r\n'
    fi
}

generate() {
    target="secrets/$1"
    if [ -s "$target" ]; then
        echo "existe:    $target (no se toca)"
        return
    fi
    random_hex >"$target"
    chmod 600 "$target"
    echo "generado:  $target"
}

generate postgres_password.txt
generate gov_mysql_root_password.txt
generate gov_app_password.txt

# La API key del copiloto la pega el equipo: se crea vacía para que el
# montaje del secreto exista y la plataforma use la plantilla de respaldo.
if [ ! -f secrets/deepseek_api_key.txt ]; then
    : >secrets/deepseek_api_key.txt
    chmod 600 secrets/deepseek_api_key.txt
    echo "creado:    secrets/deepseek_api_key.txt (vacío = sin copiloto IA)"
fi

echo "Listo. Los secretos tienen permisos 600 y están en .gitignore."
