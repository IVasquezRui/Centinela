# Etapa de build: compila la SPA (Vite + React + TypeScript).
FROM node:18-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Variables de build de Vite: se hornean en el bundle estático.
ARG VITE_API_BASE_URL=http://localhost:3000
ARG VITE_API_KEY=
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL} VITE_API_KEY=${VITE_API_KEY}

RUN npm run build

# Etapa de producción: sirve los estáticos con nginx (sin servidor de dev).
FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
