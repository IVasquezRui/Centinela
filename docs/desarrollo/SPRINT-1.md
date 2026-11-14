# SPRINT 1 — Proyecto CENTINELA

> Hackathon UNETI IA 2026 · Eje Ciberseguridad
> Unificación de los proyectos **#23 (IDS/IPS para redes gubernamentales)** y **#40 (Observatorio nacional de ciberseguridad)**
> Duración del sprint: **12 horas** · Equipo: 5 personas

---

## 1. Qué estamos construyendo

**CENTINELA** es una sola plataforma con dos caras conectadas:

| Cara | Origen | Qué hace | Quién la usa |
|---|---|---|---|
| **Operativa (SOC)** | SDD #23 | Detecta, bloquea en línea y audita ataques contra sistemas del ente público | Analista de seguridad del ministerio |
| **Pública (Observatorio)** | SDD #40 | Publica el panorama nacional de amenazas, agregado y anonimizado | Decisores y ciudadanía |

**La tesis de la unificación:** el Observatorio no se llena a mano. Cada ataque que el motor detecta y bloquea en un ente sube, agregado y despersonalizado, al panel nacional. Un solo flujo de datos alimenta las dos caras.

> *"CENTINELA detecta, bloquea y audita en el ente; agrega, anonimiza y publica en el país."*

---

## 2. Decisiones ya cerradas (no se rediscuten durante el sprint)

| Decisión | Valor |
|---|---|
| Despliegue | Docker Compose local, 100% offline (salvo la API del LLM) |
| Backend | Python 3.11 + FastAPI |
| Frontend | React + TypeScript + Vite + Tailwind |
| Base de datos | PostgreSQL 16 |
| Motor de detección | **Híbrido**: reglas regex deterministas (bloquean) + modelo ML ligero (puntúa) |
| Capa de inspección | **HTTP capa 7** mediante gateway inline (reverse proxy) |
| Dataset ML | NSL-KDD (~25 MB) |
| Copiloto IA | **DeepSeek API** (compatible OpenAI), detrás de una interfaz intercambiable |
| Observatorio en Sprint 1 | Vista pública de solo lectura, alimentada por el motor |

**Descartado explícitamente:** Cloudflare Workers/D1/KV, Kubernetes, Kafka, Redis, captura PCAP, autenticación de usuarios, exportación PDF/CSV. Todo eso es Sprint 2+.

---

## 3. Arquitectura del Sprint 1

```
   attacker-sim  ──►  ┌──────────────────────────────────────────────┐
   (tráfico mixto)    │  GATEWAY INLINE  ·  puerto 8080              │
                      │  1. normaliza la petición                    │
                      │  2. reglas regex  → veredicto (<10 ms)       │
                      │  3. BLOCK → 403 y NO llega al objetivo       │
                      │     ALLOW → proxy al objetivo                │
                      └───────┬──────────────────────┬───────────────┘
                              │ (solo si ALLOW)      │
                              ▼                      ▼
                    gov-pago (PHP+MySQL)     tickets (Node.js)
                              │                      │
                      ┌───────┴──────────────────────┴───────────────┐
                      │  cola en memoria → lote → PostgreSQL          │
                      │  worker ML (score)  ·  worker IA (triage)     │
                      │  audit_log con cadena de hashes               │
                      └───────┬───────────────────────┬──────────────┘
                              ▼                       ▼
                   Panel SOC (SSE, :3000)    Observatorio público (:3000/publico)
```

**Regla de oro:** el LLM **nunca** decide un bloqueo. Decide la regla determinista. El LLM solo redacta. Si la IA se cae, la plataforma sigue funcionando.

---

## 4. Contratos congelados a la hora 2 (permiten trabajar en paralelo)

Una vez publicados, nadie los cambia sin avisar al equipo completo.

### Evento (JSON interno y respuesta de la API)
```json
{
  "id": 1042,
  "ts": "2026-11-14T02:11:07Z",
  "src_ip": "172.20.0.9",
  "method": "GET",
  "path": "/consulta.php",
  "target": "gov-pago",
  "verdict": "block",
  "rule_id": "CNT-SQLI-001",
  "category": "sqli",
  "severity": "critical",
  "technique_id": "T1190",
  "ml_score": 0.93,
  "engine_us": 1420,
  "payload_sample": "id=1' OR '1'='1",
  "ai_summary": null,
  "ai_status": "pending"
}
```

### Endpoints
| Método | Ruta | Puerto | Para |
|---|---|---|---|
| ANY | `/*` | 8080 | Gateway inline hacia los objetivos |
| GET | `/api/health` | 3000 | Estado de servicios |
| GET | `/api/stats` | 3000 | KPIs del panel SOC |
| GET | `/api/events` | 3000 | Listado filtrable (severidad, IP, fechas) |
| GET | `/api/stream` | 3000 | SSE en tiempo real |
| GET | `/api/blocklist` | 3000 | IPs en cuarentena |
| GET | `/api/audit/verify` | 3000 | Verificación de la cadena de hashes |
| GET | `/api/public/indicadores` | 3000 | 5 indicadores agregados (Observatorio) |
| GET | `/api/public/alertas` | 3000 | Alertas en lenguaje ciudadano |

### Severidades y categorías
`severity`: `baja` · `media` · `alta` · `critica`
`category`: `sqli` · `xss` · `traversal` · `cmdi` · `scanner` · `bruteforce`

---

## 5. Fases del sprint

| Fase | Horas | Objetivo | Compuerta de salida |
|---|---|---|---|
| **F0 · Arranque** | 0:00 – 0:45 | Repo, esqueleto, todos levantan el entorno | `docker compose up` deja todos los contenedores *healthy* |
| **F1 · Contratos** | 0:45 – 2:00 | Esquema SQL, contrato de evento, endpoints mock | El frontend consume datos falsos de la API real |
| **F2 · Núcleo** | 2:00 – 5:00 | Gateway inline + reglas + persistencia | Un SQLi recibe 403 y **no** llega al objetivo |
| **F3 · Integración** | 5:00 – 7:30 | ML, simulador, panel SOC en vivo | Corpus de 1.000 peticiones medido: detección ≥95%, FP ≤5%, p95 <10 ms |
| **F4 · IA + Observatorio** | 7:30 – 9:30 | Triage DeepSeek + vista pública | Alertas con análisis redactado y panel ciudadano visible |
| **F5 · Endurecimiento** | 9:30 – 11:00 | Auditoría, arranque de un comando, plan B | Demo completa corre dos veces seguidas sin fallar |
| **F6 · Pitch** | 11:00 – 12:00 | Guion de 3 minutos y ensayos | Tres ensayos cronometrados bajo 3:00 |

---

## 6. Trabajo por rol

### 🔧 Karla — DevOps
| Fase | Tarea |
|---|---|
| F0 | Clonar repo, subir el esqueleto, crear `.env` desde `.env.example`, verificar que todos levanten el entorno |
| F0 | `docker-compose.yml`: 6 servicios, red `dmz-net` aislada, healthchecks, `depends_on` condicional |
| F1 | Dockerfiles de `centinela-core`, `frontend` y los dos objetivos vulnerables |
| F2 | Red: los objetivos **sin puertos publicados**; solo el gateway es puerta de entrada. Verificar que no se pueda saltar el proxy |
| F3 | Volumen y carga del dataset NSL-KDD; script `make demo` / `demo.ps1` de un solo comando |
| F4 | Variables de entorno de DeepSeek, `.env` fuera de git, verificar que ningún secreto esté en el repo |
| F5 | Script de *reset* que borra y resiembra la base en 10 segundos entre ensayos |
| F6 | Operar la demo en vivo: terminal de comandos visible y proyector |

**Entrega:** entorno reproducible en cualquier laptop del equipo con un solo comando.

---

### ⚙️ Iván — Backend (motor y gateway)
| Fase | Tarea |
|---|---|
| F1 | `engine/normalizer.py`: decodifica URL, unifica mayúsculas, resuelve dobles codificaciones |
| F1 | `engine/rules.yaml`: catálogo inicial de ~20 reglas con `id`, `categoría`, `severidad`, `técnica ATT&CK`, `patrón` |
| F2 | `engine/rules.py`: compila las reglas una vez al arrancar, evalúa con tope de tiempo por regla, devuelve veredicto |
| F2 | `gateway.py`: reverse proxy con `httpx`. BLOCK → 403 inmediato sin tocar el objetivo. ALLOW → reenvía |
| F2 | Medición de `engine_us` (microsegundos de CPU del motor) en cada petición |
| F3 | `ips/blocklist.py`: 3 detecciones de la misma IP en 60 s → cuarentena de 5 minutos |
| F3 | Afinar reglas contra el corpus hasta cumplir la compuerta de F3 |
| F5 | Pruebas de las reglas (`pytest`): casos positivos y negativos por categoría |

**Entrega:** una petición maliciosa muere en el gateway en menos de 10 ms y queda registrada.

---

### ⚙️ José Oropeza — Backend (datos, ML e IA)
| Fase | Tarea |
|---|---|
| F1 | `db/init/01_schema.sql`: tablas `event`, `rule`, `attack_technique`, `audit_log` con índices compuestos |
| F1 | `db/init/02_seed_attack.sql`: ~15 técnicas MITRE ATT&CK y el mapeo regla → técnica |
| F2 | `queue.py` + escritura por lotes a PostgreSQL (evita que el simulador tumbe la base) |
| F2 | `storage/audit.py`: cadena de hashes `sha256(hash_anterior + contenido)` y `03_grants.sql` que revoca UPDATE/DELETE al rol de la app |
| F3 | `ml/train.py`: entrena RandomForest sobre NSL-KDD, reporta **F1 y tasa de falsos positivos**, guarda el modelo |
| F3 | `engine/ml.py`: carga el modelo y añade `ml_score` al evento, **fuera** del camino crítico |
| F4 | `ai/sanitizer.py`: enmascara PII y codifica el payload antes de enviarlo al LLM |
| F4 | `ai/provider.py` + `worker.py`: DeepSeek con salida JSON validada, tiempo máximo 3 s, *fallback* a plantilla determinista |
| F4 | `api/public.py`: los 5 indicadores agregados del Observatorio, calculados desde `event` |

**Entrega:** datos persistidos, auditables y verificables; métricas del modelo que cumplen el SDD #23; triage redactado por IA que nunca bloquea la demo.

---

### 🎨 Luis — Frontend
| Fase | Tarea |
|---|---|
| F0 | Proyecto Vite + React + TS + Tailwind levantando |
| F1 | `lib/api.ts` contra los endpoints mock; tipos TypeScript del contrato de evento |
| F2 | **Panel SOC**: 4 tarjetas KPI (peticiones, bloqueos, IPs en cuarentena, latencia p95) |
| F2 | Tabla de eventos con filtros por severidad, IP y rango de fechas |
| F3 | Conexión SSE a `/api/stream`: los eventos entran solos, sin recargar |
| F3 | Panel de IPs en cuarentena y mapa de calor categoría × severidad |
| F4 | **Vista pública del Observatorio** en `/publico`: 5 indicadores, alertas en lenguaje claro, sin tecnicismos |
| F4 | Accesibilidad mínima: contraste AA, navegación por teclado, todo en español |
| F5 | Pulido visual para proyector: tipografía grande, modo oscuro, nada que requiera zoom |

**Entrega:** la pantalla que ve el jurado. Es el 40% de la nota del pitch.

---

### 📄 José Estanga — Documentación
| Fase | Tarea |
|---|---|
| F0 | `README.md` raíz: qué es, cómo se levanta, diagrama de arquitectura |
| F1 | **`docs/SDD.md` unificado**: fusiona el #23 y el #40 en un solo documento (problema, objetivos, RF, RNF, historias de usuario, criterios de aceptación, stack, Definition of Done) |
| F2 | `docs/SPEC.md` con los 8 bloques que exige el hackathón: problema con cifra, usuarios, propuesta de valor, alcance del MVP, criterios de aceptación, arquitectura, ética y privacidad, riesgos y supuestos |
| F3 | `docs/decisiones.md`: registro corto de las decisiones de arquitectura y por qué se descartó cada alternativa |
| F4 | **Declaración de uso de IA** (obligatoria): tabla Herramienta / Uso / Verificación humana |
| F4 | Bloque de ética: datos 100% sintéticos, sin datos de ciudadanos reales, PII enmascarada antes del LLM, el LLM no tiene autoridad de bloqueo |
| F5 | Capturas de pantalla de la demo y reporte de métricas del modelo |
| F6 | Guion del pitch de 3 minutos escrito y cronometrado |

**Entrega:** el jurado evalúa documentación. Sin SPEC.md y sin declaración de IA se pierden puntos directos.

---

## 7. Compuertas de control y planes B

| Hora | Compuerta | Si no se cumple |
|---|---|---|
| 0:45 | Todos levantan el entorno | Karla bloquea todo lo demás hasta resolverlo |
| 2:00 | Contratos publicados | Se congela lo que haya y se sigue; no se espera a nadie |
| 5:00 | SQLi bloqueado de punta a punta | Se elimina el objetivo Node.js y se queda solo el PHP |
| 7:30 | Métricas medidas | Si el ML no converge, se presenta solo el motor de reglas con sus métricas reales |
| 9:30 | IA funcionando | Se activa el modo plantilla determinista y se presenta como "IA con respaldo determinista" |
| 11:00 | Demo corre dos veces seguidas | Se graba un video de respaldo de la demo |

**Nunca se improvisa en el escenario.** Si algo no está listo a las 11:00, no entra en la demo.

---

## 8. Guion de la demo (3 minutos)

1. **0:00–0:30** — El problema, con la cifra. Pantalla: panel vacío, sistemas en verde.
2. **0:30–1:15** — Karla lanza el simulador. 1.000 peticiones mezcladas. El panel se llena solo: tráfico legítimo pasa, los ataques se bloquean, aparecen IPs en cuarentena.
3. **1:15–1:50** — Se abre un ataque bloqueado: regla disparada, técnica MITRE, `ml_score` y el análisis redactado por la IA. Se recalca que la IA explica, no decide.
4. **1:50–2:20** — **Momento de impacto:** se edita a mano un registro en la base con `psql` y se pulsa *Verificar auditoría*. El sistema detecta la cadena de hashes rota e indica el registro exacto.
5. **2:20–2:50** — Se cambia a la vista pública del Observatorio: los mismos ataques, ya agregados y anonimizados, en lenguaje ciudadano. **Aquí se muestra la unificación.**
6. **2:50–3:00** — Cierre: latencia p95 real en pantalla, y la frase de escalabilidad.

---

## 9. Estructura del repositorio

```
centinela/
├─ docker-compose.yml          · Karla
├─ .env.example / .gitignore   · Karla
├─ README.md                   · José Estanga
├─ docs/
│  ├─ SPRINT-1.md  SPEC.md  SDD.md  architecture.md  decisiones.md
├─ centinela-core/             · Iván + José Oropeza
│  ├─ Dockerfile  requirements.txt
│  ├─ app/
│  │  ├─ main.py  config.py  gateway.py  queue.py
│  │  ├─ engine/    normalizer.py  rules.py  rules.yaml  ml.py
│  │  ├─ ips/       blocklist.py
│  │  ├─ storage/   db.py  models.py  audit.py
│  │  ├─ ai/        provider.py  prompts.py  sanitizer.py  worker.py
│  │  └─ api/       soc.py  public.py  stream.py
│  └─ tests/
├─ ml/                         · José Oropeza
│  ├─ train.py  data/  model/
├─ db/init/                    · José Oropeza
│  ├─ 01_schema.sql  02_seed_attack.sql  03_grants.sql
├─ frontend/                   · Luis
│  ├─ Dockerfile  package.json  vite.config.ts
│  └─ src/  (pages/Soc.tsx · pages/Observatorio.tsx · components/ · lib/api.ts)
├─ targets/                    · Karla
│  ├─ php-tributos/   node-tickets/
└─ attacker-sim/               · Iván
   ├─ Dockerfile  corpus.yaml  sim.py
```

---

## 10. Pendientes por confirmar

- [ ] **Rol de Rafael** en el equipo: no aparece en la lista de 5 integrantes. ¿Líder técnico, pitch, o ambos?
- [ ] **URL del repositorio** remoto, para que Karla haga el primer push.
- [ ] **Quién descarga NSL-KDD** y cuándo (bloquea la fase F3 de José Oropeza).
- [ ] **Hora exacta de inicio** del sprint, para convertir las horas relativas en hora de reloj.
