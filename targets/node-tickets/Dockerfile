# Imagen de laboratorio DELIBERADAMENTE vulnerable (path traversal + command
# injection). Uso exclusivo: objetivo de prueba aislado para que CENTINELA
# detecte y bloquee ataques en la demo. Sin salida a internet, sin datos
# reales, sin puertos publicados al host (ver docker-compose.yml).
FROM node:18-alpine

WORKDIR /app

COPY package.json .
RUN npm install --omit=dev

COPY . .

EXPOSE 4000

CMD ["node", "server.js"]
