#!/bin/sh
# Simula una verificación de código de ticket contra un validador externo.
# Script de laboratorio: no realiza ninguna validación real, solo imprime
# el código recibido para que el endpoint vulnerable tenga algo que
# ejecutar vía shell (ver server.js, /validar).
echo "Verificando código de ticket: $1"
echo "Resultado: valido"
