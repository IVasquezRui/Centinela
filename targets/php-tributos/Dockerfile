# Imagen de laboratorio DELIBERADAMENTE vulnerable (SQLi + LFI).
# Uso exclusivo: objetivo de prueba aislado para que CENTINELA detecte y
# bloquee ataques en la demo. Sin salida a internet, sin datos reales,
# sin puertos publicados al host (ver docker-compose.yml). No desplegar
# fuera de la red interna "dmz-net" del laboratorio.
FROM php:8.1-apache

RUN docker-php-ext-install mysqli

COPY . /var/www/html/

# El secreto de MySQL llega como archivo 600 del usuario del host y Apache corre
# como www-data (los file secrets de Compose son bind mounts: no hay remapeo de
# uid fuera de Swarm). Se carga desde root al arrancar y se exporta al entorno,
# así que PHP lo lee con getenv() y el archivo nunca queda legible por el
# servidor web. Se mueve fuera del docroot para no publicarlo.
RUN mv /var/www/html/docker-entrypoint.sh /usr/local/bin/docker-entrypoint-centinela \
    && chmod 755 /usr/local/bin/docker-entrypoint-centinela

EXPOSE 80

ENTRYPOINT ["docker-entrypoint-centinela"]
CMD ["apache2-foreground"]
