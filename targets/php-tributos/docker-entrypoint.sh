#!/bin/sh
# Arranque del objetivo gov-pago.
#
# Carga la credencial de MySQL desde el Docker secret (/run/secrets) al entorno
# del proceso antes de lanzar Apache: el archivo lo monta docker compose como
# bind mount con uid del host y modo 600, y el servidor web corre como www-data,
# así que un file_get_contents() desde PHP no podría leerlo. Exportarlo aquí
# (como root, antes de que Apache baje privilegios) mantiene el archivo cerrado
# y la credencial fuera de la imagen y del repositorio.
set -eu

if [ -n "${MYSQL_ROOT_PASSWORD_FILE:-}" ] && [ -r "${MYSQL_ROOT_PASSWORD_FILE}" ]; then
    MYSQL_ROOT_PASSWORD="$(cat "${MYSQL_ROOT_PASSWORD_FILE}")"
    export MYSQL_ROOT_PASSWORD
fi

exec docker-php-entrypoint "$@"
