# Imagen de laboratorio DELIBERADAMENTE vulnerable (SQLi + LFI).
# Uso exclusivo: objetivo de prueba aislado para que CENTINELA detecte y
# bloquee ataques en la demo. Sin salida a internet, sin datos reales,
# sin puertos publicados al host (ver docker-compose.yml). No desplegar
# fuera de la red interna "dmz-net" del laboratorio.
FROM php:8.1-apache

RUN docker-php-ext-install mysqli

COPY . /var/www/html/

EXPOSE 80
