# Secretos del laboratorio CENTINELA

Esta carpeta contiene los secretos **locales** que `docker-compose.yml` monta
como *Docker secrets* en `/run/secrets/<nombre>` dentro de cada contenedor.

| Archivo | Consumidor | Cómo se lee |
|---|---|---|
| `postgres_password.txt` | `centinela-db` / `centinela-core` | `POSTGRES_PASSWORD_FILE` y `DATABASE_PASSWORD_FILE` |
| `gov_mysql_root_password.txt` | `gov-mysql` / `gov-pago` | `MYSQL_ROOT_PASSWORD_FILE` |
| `deepseek_api_key.txt` | `centinela-core` | `DEEPSEEK_API_KEY_FILE` (vacío = plantilla de respaldo) |

El rol de mínimos privilegios `centinela_app` **no tiene archivo propio**: su
password se deriva dentro de `db/init/03_grants.sh` con
`sha256("centinela_app:" + POSTGRES_PASSWORD)`. Así se evita distribuir una
credencial más y el rol nunca comparte valor con el superusuario.

## Por qué no viven en `.env`

`.env` se commitea por error con muchísima facilidad, se imprime en capturas de
pantalla y `docker inspect` muestra las variables de entorno en claro. Los
secretos aquí:

- están en `.gitignore` (nunca llegan al repositorio);
- se crean con permisos `600` y aleatorios de 192 bits;
- no aparecen en `docker inspect` ni en `docker compose config`;
- no se registran en logs (solo se lee el archivo en el arranque).

## Generarlos

```bash
make secrets             # Linux/macOS/WSL -> scripts/gen-secrets.sh
./scripts/gen-secrets.ps1  # Windows PowerShell
```

El script es idempotente: si el archivo ya existe y no está vacío, no lo toca.

## Rotarlos

1. Borrar el archivo del secreto (p. ej. `secrets/postgres_password.txt`).
2. `make secrets` para regenerarlo.
3. Recrear la base desde cero para que el nuevo password sea el del clúster:
   `docker compose down -v && docker compose up -d --build`.

PostgreSQL guarda el password en el volumen: cambiar el archivo sin recrear el
volumen deja el contenedor esperando la credencial vieja.

## En producción

Estos archivos son el equivalente local a un gestor de secretos. En un entorno
real se sustituyen por Vault / AWS Secrets Manager / Docker Swarm secrets sin
tocar el código: solo cambia de dónde se monta el archivo en `/run/secrets/`.
