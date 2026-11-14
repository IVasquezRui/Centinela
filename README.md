# CENTINELA

Plataforma de laboratorio de seguridad defensiva (Blue Team): un motor de
detección y bloqueo en línea (IDS/IPS) que protege dos aplicaciones web
propias, intencionalmente vulnerables y aisladas, generando evidencia
auditable y alimentando un observatorio público de amenazas.

> Hackathon UNETI IA 2026 · Eje Ciberseguridad · Metodología Specification-Driven Development.
> Unificación de los proyectos de biblioteca **#23 — IDS/IPS para redes gubernamentales** y
> **#40 — Observatorio nacional de ciberseguridad**. Ver `docs/SPEC.md` y `docs/SDD.md`.

> *"CENTINELA detecta, bloquea y audita en el ente; agrega, anonimiza y publica en el país."*

## Qué hace

- **Gateway inline (:8080):** normaliza cada petición HTTP, la evalúa contra un motor de reglas regex deterministas y decide `BLOCK`/`ALLOW` en menos de 10 ms de CPU. Lo bloqueado nunca llega al objetivo.
- **Modo IPS:** 3 detecciones de la misma IP en 60 segundos → cuarentena automática de 5 minutos.
- **ML fuera del camino crítico:** un RandomForest entrenado sobre NSL-KDD añade un `ml_score` a cada evento, sin intervenir en el veredicto.
- **Auditoría inmutable:** cadena de hashes `sha256` encadenada + permisos de base de datos que revocan `UPDATE`/`DELETE` al rol de la aplicación.
- **Copiloto de IA (DeepSeek):** redacta el análisis de alertas ya bloqueadas. **Nunca decide un bloqueo**; si falla, hay plantilla de respaldo determinista.
- **Panel SOC (:5173):** eventos en vivo (SSE), KPIs, IPs en cuarentena, verificación de auditoría con un clic.
- **Observatorio público (:5173/publico):** 5 indicadores agregados y alertas en lenguaje claro, sin autenticación ni datos personales.

## Por qué las apps de laboratorio son "vulnerables"

`targets/php-tributos` y `targets/node-tickets` son aplicaciones que el propio equipo escribe desde cero, con **4–6 fallos clásicos de libro de texto** (SQLi, LFI, path traversal, command injection) y **datos 100% sintéticos**. No publican puertos al host: solo son alcanzables a través del gateway, en una red Docker sin salida a internet. Es el mismo patrón que usan laboratorios educativos públicos como DVWA, OWASP Juice Shop o WebGoat — generan tráfico de ataque reproducible para que un motor defensivo tenga algo real que detectar y bloquear.

## Arquitectura

```
   attacker-sim  ──►  GATEWAY INLINE (:8080)  ──► gov-pago (PHP+MySQL)
                       reglas + IPS                tickets (Node.js)
                              │
                       cola → PostgreSQL (eventos + audit_log + ATT&CK)
                       worker ML · worker IA (DeepSeek)
                              │
                       API (:3000) ──► Panel SOC (:5173) + Observatorio (:5173/publico)
```

Diagrama completo y decisiones de diseño en `docs/architecture.md`.

## Instalación y ejecución

Requisitos: Docker y Docker Compose.

```bash
cp .env.example .env
# Editar .env: como mínimo, DEEPSEEK_API_KEY si se quiere triage real de IA
# (sin la clave, el sistema usa la plantilla de respaldo automáticamente).

docker compose up --build
```

Al terminar de levantar (`docker compose ps` debe mostrar todos los
servicios `healthy`):

- Panel SOC: http://localhost:5173
- Observatorio público: http://localhost:5173/publico
- API: http://localhost:3000/api/health
- Gateway (objetivos de laboratorio, vía proxy): http://localhost:8080/gov-pago/ , http://localhost:8080/tickets/

### Lanzar el simulador de tráfico (demo)

```bash
docker compose --profile demo run --rm attacker-sim --total 1000 --malicious-ratio 0.3
```

### Entrenar el modelo de ML (opcional, ver `ml/README.md`)

```bash
cd ml
python train.py --train data/KDDTrain+.txt --test data/KDDTest+.txt --out model/nsl_kdd_rf.joblib
```

## Uso / API

Contrato completo de endpoints y del JSON de evento en `docs/SPRINT-1.md` sección 4. Resumen:

| Endpoint | Para |
|---|---|
| `GET /api/health` | Estado de servicios |
| `GET /api/stats` | KPIs del panel SOC |
| `GET /api/events` | Listado filtrable por severidad, IP y fechas |
| `GET /api/stream` | Eventos en vivo (SSE) |
| `GET /api/blocklist` | IPs en cuarentena |
| `GET /api/audit/verify` | Verificación de la cadena de hashes |
| `GET /api/public/indicadores` | 5 indicadores agregados del Observatorio |
| `GET /api/public/alertas` | Alertas públicas en lenguaje ciudadano |

## Datos

- **NSL-KDD** (entrenamiento ML): ver `ml/README.md` para la descarga; no se commitea (`.gitignore`).
- **Datos de las apps de laboratorio:** 100% sintéticos, generados a mano en `targets/*/init.sql` y `targets/*/data.js`. Nunca datos reales de personas.

## Pruebas

```bash
cd centinela-core
pip install -r requirements.txt
pytest
```

`tests/test_rules.py` cubre casos positivos y negativos del motor de reglas por categoría (`sqli`, `xss`, `traversal`, `cmdi`), incluida evasión por doble codificación de URL.

## Estructura del repositorio

```
centinela/
├─ docker-compose.yml   .env.example   .gitignore   README.md
├─ docs/                SPRINT-1.md  SPEC.md  SDD.md  architecture.md  decisiones.md  declaracion-ia.md
├─ centinela-core/      FastAPI: gateway (:8080) + API SOC/Observatorio (:3000)
├─ ml/                  Entrenamiento del modelo (NSL-KDD)
├─ db/init/             Esquema SQL, seed MITRE ATT&CK, grants de inmutabilidad
├─ frontend/             Vite + React + TS + Tailwind (panel SOC + Observatorio)
├─ targets/              Apps de laboratorio vulnerables (php-tributos, node-tickets)
└─ attacker-sim/         Generador de tráfico mixto para la demo
```

## Contribución

Proyecto de hackathon de 12 horas con 5 roles fijos (ver `docs/SPRINT-1.md` sección 6). Durante el sprint, los contratos de API y del evento JSON se congelan a la hora 2 y no se modifican sin avisar al equipo completo.

## Licencia

Proyecto académico — Hackathon UNETI IA 2026. Sin licencia de uso comercial definida.
