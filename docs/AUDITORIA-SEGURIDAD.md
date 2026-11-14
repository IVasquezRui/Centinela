# Auditoría de Seguridad — CENTINELA (backend + infraestructura)

> Rama auditada: **develop** · Commit: **35bfcbd** · Fecha: **2026-11-14** · Modo: revisión estática + pruebas dinámicas contra el motor real.
>
> **Conclusión general:** no se encontraron **puertas traseras** ni código malicioso. Sí se encontraron **3 vulnerabilidades críticas**, **3 altas**, **8 medias** y una serie de **bugs**, entre ellos uno que impide levantar el entorno en este árbol (falta un secreto). Los riesgos son de robustez del control de seguridad y de operación, no de sabotaje.

---

## 1. Resumen ejecutivo

| ID | Hallazgo | Severidad | Ubicación principal |
|---|---|---|---|
| **C1** | ReDoS en `CNT-BRUTEFORCE-001`: 27 KiB -> ~977 ms de CPU (crecimiento cuadrático; ~1 MiB ≈ ~23 min). El presupuesto por regla se comprueba **después** del `search` y falla **abierto**. | 🔴 Crítico | `rules.yaml:158`, `rules.py:96-98`, `gateway.py:133` |
| **C2** | API del SOC completa sin autenticación + CORS `*` + `/docs` público, publicada en `0.0.0.0:3000`. | 🔴 Crítico | `api/soc.py:24-31`, `docker-compose.yml` |
| **C3** | **11 evasiones confirmadas** del motor: tautologías no-`1=1`, `union all select`, `;sleep 5`, `;echo`, `;python3 -c`, tab-encoding y SQLi/XSS/traversal **en cabeceras**. | 🔴 Alto | `rules.yaml`, `normalizer.py`, `rules.py:82` |
| **C4** | Cuerpo HTTP sin límite de tamaño + amplificación ~2x en `inspectable_text` -> OOM con una sola petición. | 🔴 Alto | `gateway.py:133`, `normalizer.py:31-35` |
| **C5** | `joblib.load()` sobre artefacto no verificado, en contenedor **root** -> RCE de cadena de suministro. | 🔴 Alto | `engine/ml.py:92`, `Dockerfile` |
| **C6** | La cadena de hashes solo protege `payload`; `ts/action/event_id` y los campos de evidencia de `event` (src_ip, path, payload_sample) quedan fuera y son alterables sin detección. | 🔴 Alto | `storage/audit.py:35-56`, `queue.py:188` |
| **M1** | `X-Forwarded-For` toma el valor izquierdo (falsificable) + `src_ip VARCHAR(64)` -> pérdida silenciosa de evidencia. | 🟡 Medio | `gateway.py:96`, `models.py:24` |
| **M2** | SSE sin límite de conexiones; `/api/audit/verify` O(n) recalcula toda la cadena; `/api/public/alertas?limit=` sin tope. | 🟡 Medio | `stream.py`, `audit.py:64`, `public.py:121` |
| **M3** | Cola sin backpressure en `publish()`: el tope solo aplica al reencolado, no a la entrada -> OOM con BD caída. | 🟡 Medio | `queue.py:53,80,113` |
| **M4** | Worker IA **livelock**: `TypeError` no capturado si el LLM devuelve JSON no-objeto; el `CHECK` impide un estado terminal `failed`. | 🟡 Medio | `provider.py:115`, `worker.py:36`, `01_schema.sql:38` |
| **M5** | Prompt injection: `path` va fuera del bloque delimitado, no se neutraliza `</payload_capturado>`, `looks_like_prompt_injection` es código muerto. | 🟡 Medio | `prompts.py:41`, `sanitizer.py:41-54` |
| **M6** | Cuarentena por IP de contenedor (bloquea a todos detrás del puerto publicado) + mapas de hits nunca purgados. | 🟡 Medio | `blocklist.py`, `docker-compose.yml` |
| **M7** | Red plana única (`dmz-net`) con objetivos RCE-by-design, la BD de evidencia y la API. | 🟡 Medio | `docker-compose.yml:1-3` |
| **M8** | Contenedores root, sin `read_only`/`cap_drop`/límites; Vite **dev** en producción; `mysql:5.7` EOL; sin TLS. | 🟡 Medio | Dockerfiles, `docker-compose.yml` |
| **B1** | **Falta `secrets/gov_app_password.txt`** -> `docker compose up` falla en este árbol. | 🔵 Bajo (bloqueante) | `docker-compose.yml`, `secrets/` |
| **B2-B10** | Ruta absoluta en `/api/health`; `rule_id` en el 403; cabeceras hop-by-hop reenviadas; logs con path crudo; credenciales de ejemplo en `docs/PRD`; severidad sin `CHECK`; `Blocklist(Settings())` duplicado; `--rotate-ips` no-op; pérdida de cola al apagar; carrera en `append_entry`. | 🔵 Bajo | varias |

---

## 2. Alcance y método

**Archivos revisados:** `centinela-core/` (gateway, motor de reglas, normalizador, IPS, cola, auditoría, modelos, configuración, ML, IA, API SOC/Observatorio/SSE), `run.py`, `db/init/*`, `docker-compose.yml`, Dockerfiles y `.dockerignore`, `targets/*`, `attacker-sim/*`, `ml/*`, `scripts/*`, `frontend/src` (superficie que toca el backend), `README.md`, `.env.example` y `secrets/`.

**Verificaciones ejecutadas:**
- `grep` de primitivas peligrosas (`eval`, `exec`, `subprocess`, `pickle`, `os.system`, `b64decode`, `compile`, `marshal`, `__import__`) en todo el repo: **solo** aparecen en el objetivo de laboratorio `targets/node-tickets` (RCE deliberado) y en regex de PII del sanitizador. Nada en `centinela-core/`.
- Carga real del `RuleEngine` + `normalize()` y evaluación de payloads de ataque contra el código de `develop`.
- Medición de tiempos de regex con entradas adversariales (ReDoS).
- Medición de amplificación de memoria del normalizador.
- Verificación de `secrets/` (permisos, `git status --ignored`, `git log --all -- secrets`), `.gitignore` y `docker compose config`.

---

## 3. Hallazgos críticos y altos (detalle)

### C1 — ReDoS en `CNT-BRUTEFORCE-001` + presupuesto que falla abierto

- **Patrón** (`rules.yaml:158`): `(?i)(username|usuario)=admin.*(password|clave)=(admin|123456|root)`. El `.*` entre dos literales provoca backtracking catastrófico cuando **no** hay coincidencia.
- **Presupuesto** (`rules.py:25,96-98`): `PER_RULE_TIMEOUT_SECONDS = 0.005` se comprueba **después** de `pattern.search()` y, al superarse, hace `continue` (descarta la regla para esa petición: **fail-open**).
- **Medición real en `develop`** (payload `usuario=admin ` repetido, que no matchea ninguna regla):

| Tamaño | Tiempo de CPU |
|---|---|
| 6 KiB | 56,7 ms |
| 13 KiB | 244,9 ms |
| 27 KiB | 977 ms |

  Crecimiento cuadrático (×2 tamaño ≈ ×4 tiempo): **1 MiB ≈ ~23 minutos**. El gateway hace `await request.body()` sin tope (`gateway.py:133`) y comparte event loop con la API (`run.py:42`), así que una sola petición cuelga gateway + panel SOC + `/api/health`, y el healthcheck de Docker reinicia el contenedor en bucle.
- **Falsa sensación de seguridad:** `tests/test_f5_hardening_redos.py` solo prueba payloads que **matchean temprano** (`"' OR ''='"*2000 + "' OR '1'='1"` dispara `CNT-SQLI-001` al instante; el de traversal termina en `etc/passwd`; el de cmdi termina en `| bash`). Ninguno cubre el caso patológico de **no-match** con `.*`.
- **Remediación:** patrón lineal `(?i)(username|usuario)=admin[^&\s]{0,64}(password|clave)=(admin|123456|root)`; `fail-closed` (bloquear con regla de presupuesto en vez de `continue`); `MAX_BODY_BYTES` (~64 KiB) con `413`; test de regresión con `usuario=admin ` × 4000 (< 10 ms).

### C2 — Toda la API del SOC es pública y sin autenticación

- `api/soc.py:24` crea `FastAPI(...)` **sin** `docs_url=None` (a diferencia del gateway, `gateway.py:39`).
- `api/soc.py:26-31` añade `CORSMiddleware(allow_origins=["*"])` (aunque `allow_methods=["GET"]` limita el verbo).
- `docker-compose.yml` publica `3000` en `0.0.0.0`.
- **Expuesto sin credenciales:** `/api/events` (con `src_ip` y `payload_sample`), `/api/stream` (SSE en vivo), `/api/blocklist`, `/api/stats`, `/api/audit/verify`, `/api/health`, y además **`/docs` y `/openapi.json`**.
- **Vector adicional:** con CORS `*`, cualquier web abierta por el analista puede **leer** la telemetría vía el navegador del operador (no hace falta acceso a la red).
- **Remediación:** `docs_url=None/redoc_url=None/openapi_url=None`; CORS restringido a `localhost:5173`; `X-API-Key` por `Depends` en las rutas SOC (dejar `/api/public/*` abierta por diseño); bind de puertos a `127.0.0.1` por defecto.

### C3 — 11 evasiones confirmadas del motor

Ejecutado con `RuleEngine`/`normalize` reales de `develop`:

```text
tautologia 'a'='a      -> allow    union all select       -> allow
OR 2=2-- -             -> allow    subconsulta bool       -> allow
OR true-- -            -> allow    ;sleep 5               -> allow
;echo pwned            -> allow    ;python3 -c ...        -> allow
union%09all%09select   -> allow    (tab como separador)
SQLi en cabecera       -> allow    XSS en cabecera        -> allow
traversal en cabecera  -> allow
```

Causas en `rules.yaml` / `normalizer.py` / `rules.py:82`:
- `CNT-SQLI-001` sigue anclada a `1=1` -> `'a'='a`, `2=2`, `(SELECT 1)=(SELECT 1)`, `true` no se detectan.
- `CNT-SQLI-002` es `union(\s|%20)+select` -> **`union all select`** y `union%09all%09select` no se detectan (solo reconoce espacio y `%20`, no tab `%09`).
- `CNT-SQLI-003` es `(--|#)\s*$` -> comentario **en medio** (`-- -`) no se detecta.
- `CNT-SQLI-004` exige paréntesis -> `;sleep 5` no se detecta.
- `CNT-CMDI-001` usa lista cerrada de binarios -> `;sleep`, `;echo`, `;python3 -c` pasan (y se ejecutan en el objetivo Node, que es RCE por diseño).
- **Cabeceras:** el normalizador arma `headers_text` pero `rules.py:82` solo lo evalúa para reglas con `applies_to: "headers"` (solo `CNT-SCANNER-001`). SQLi/XSS/traversal en `X-*`, `Referer`, `User-Agent`, `Cookie` **nunca** se inspeccionan.
- **Remediación:** reglas genéricas de tautología, `union( all)? select`, comentarios no anclados y time-based sin paréntesis; inspección de cabeceras para todas las categorías (excluyendo `authorization`/`cookie` del muestreo, no de la evaluación); normalización de tab/JSON/`\uXXXX`; añadir `tests/test_evasion_corpus.py` con estos 11 casos.

### C4 — Cuerpo sin límite y amplificación de memoria

- `gateway.py:133` -> `body = await request.body()` sin `MAX_BODY` (uvicorn no impone límite por defecto).
- `normalizer.py:31-35` concatena `path + query + body + (query y body con "+"->" ")` -> `inspectable_text` ≈ **2×** el cuerpo (verificado: 8 MiB -> 16 MiB), más el `bytes` original y la copia decodificada.
- Sin `deploy.resources.limits` en compose -> OOM-kill con una sola petición grande, y con concurrencia mucho menos.
- **Remediación:** `MAX_BODY_BYTES` (64 KiB) con `413` + evento; inspeccionar solo los primeros N KiB; `Content-Length` máximo en respuestas.

### C5 — `joblib.load()` = RCE de cadena de suministro

- `engine/ml.py:92` -> `joblib.load(path)` sobre `ML_MODEL_PATH` (bind-mount `./ml/model:ro`).
- El artefacto `.joblib` está en `.gitignore`, no se genera en CI y no tiene hash ni firma. `joblib` usa `pickle`: un archivo manipulado ejecuta código arbitrario.
- El contenedor corre como **root** (el `Dockerfile` no define `USER`), con acceso a la contraseña de Postgres, la API key y la red `dmz-net`.
- **Remediación:** contenedor non-root + `read_only` + `cap_drop: ALL`; registrar el SHA-256 del modelo y verificarlo antes de `joblib.load`; preferible formato sin pickle (`skops`/`onnx`).

### C6 — La inmutabilidad no cubre la evidencia real

Lo que **sí** mejoró en `develop`: la app conecta como `centinela_app` (`db.py:9`, `config.py:17,54`) y `03_grants.sh` otorga `UPDATE` solo de `(ai_summary, ai_status)` y revoca `DELETE/TRUNCATE` sobre `event` y todo sobre `audit_log`.

Lo que **sigue roto**:
- `audit.py:35-56` hashea **solo `payload`**, que es `{"event_id","verdict","rule_id"}` (`queue.py:188`). Quedan fuera de la cadena: `ts`, `action`, `event_id` de `audit_log`, y los campos de evidencia de `event` (`src_ip`, `path`, `payload_sample`, `method`, `target`, `severity`).
- Un atacante con superusuario (o con RCE previo a los GRANT, o un `psql -U centinela` como en la propia demo) puede reescribir `event.src_ip` o `event.path` **sin que `/api/audit/verify` detecte nada**.
- `verify_chain` no detecta **borrado del final** de la cadena ni huecos; `append_entry` lee `last` sin bloqueo -> en réplicas/concurrencia la cadena se bifurca silenciosamente.
- El docstring de `audit.py:12` cita `03_grants.sql` (nombre antiguo; ahora es `.sh`).
- **Remediación:** incluir `ts|action|event_id` y los campos de `event` en el hash; `FOR UPDATE`/`pg_advisory_lock` en `append_entry`; detectar truncamiento en `verify_chain`; job de anclaje (export del hash a un fichero/WORM).

---

## 4. Hallazgos medios

- **M1 — Falsificación de IP / pérdida de evidencia.** `gateway.py:96` toma `forwarded.split(",")[0]` (el valor **más a la izquierda**, el que escribe el cliente). Con un proxy estándar (`$proxy_add_x_forwarded_for`), el atacante rota IP y evita la cuarentena, o la envenena contra una víctima. Además `Event.src_ip` es `VARCHAR(64)` (`models.py:24`): un `X-Forwarded-For` de más de 64 caracteres provoca `DataError` y **el evento no se persiste** (el reintento `drop_rule_id` no trunca `src_ip`). *Corregir:* usar el valor más a la derecha no confiable, validar con `ipaddress.ip_address` y truncar/rechazar antes de encolar.
- **M2 — Amplificación por endpoints pesados.** `stream.py` no limita el número de suscriptores SSE (cada conexión = cola + corrutina); `audit.py:64` carga **toda** `audit_log` en memoria y recalcula cada SHA-256 en cada llamada; `public.py:121` acepta `limit` sin tope; `soc.py:56` ejecuta `percentile_cont` sobre la tabla completa. Sin auth ni rate-limit -> DoS trivial y OOM.
- **M3 — Backpressure insuficiente.** `queue.py:53` `asyncio.Queue()` **sin `maxsize`**; `publish()` hace `put` sin bloquear (`queue.py:80`) y el gateway lo `await` en la ruta de la petición. `MAX_REQUEUE=10_000` solo limita el **reencolado** tras fallo de BD (`queue.py:113`), no la entrada inicial. Con la BD caída, la cola crece sin techo. El test `test_queue_max_requeue_cap_protects_memory` solo cubre el camino del reencolado.
- **M4 — Livelock del worker IA.** `provider.py:115` captura `(HTTPError, KeyError, ValueError, JSONDecodeError)`. Si el LLM devuelve `[...]`, `"texto"` o `null`, `json.loads` tiene éxito y `data["resumen"]` lanza **`TypeError`** (no capturado) -> sube a `worker.py:36`, se revierte la transacción, el evento queda `pending` y se reintenta **para siempre** (1 llamada al LLM por segundo: coste + CPU). El `CHECK (ai_status IN ('pending','done'))` de `01_schema.sql:38` **impide** añadir un estado terminal `failed`.
- **M5 — Prompt injection en el copiloto.** `prompts.py:41` interpola `path` (controlado por el atacante) **fuera** del bloque `<payload_capturado>`, sin límite de longitud ni mask-PII; `sanitize_payload_for_llm` no neutraliza el cierre `</payload_capturado>` -> fence-escape. `looks_like_prompt_injection` (`sanitizer.py:41`) no se usa en ninguna parte (código muerto). Impacto contenido (la IA nunca decide bloqueos), pero puede corromper la evidencia narrativa y la severidad sugerida.
- **M6 — Cuarentena por IP de contenedor + fuga de memoria.** Publicado `8080` en el host, todo el tráfico externo llega con la IP del bridge: 3 detecciones de un cliente -> **cuarentena para todos** los clientes. `_hits`/`_last_block`/`_quarantined_until` no se purgan por IP expirada (solo `_quarantined_until` al consultar) -> crecimiento indefinido si `TRUSTED_PROXIES` se configura mal (claves controladas por el atacante).
- **M7 — Red plana.** `docker-compose.yml:1-3` define una sola `dmz-net` con `tickets`/`gov-pago` (RCE deliberado), `gov-mysql`, el frontend y `centinela-db` (toda la evidencia). Comprometer el objetivo Node da acceso directo a la API sin auth (C2), a `gov-mysql:3306` y a `centinela-db:5432`. *Corregir:* `edge-net` (gateway + targets) y `data-net` (solo core + BD), con la BD sin ruta desde los targets.
- **M8 — Hardening de contenedores.** `centinela-core/Dockerfile` sin `USER` (root); compose sin `read_only`, `cap_drop` ni `deploy.resources.limits`; `frontend/Dockerfile` ejecuta **`vite dev`** en "producción" (`host: true`, sin build estático, superficie de dev server); `mysql:5.7` EOL desde oct-2023 (CVEs sin parche, en la misma red que la BD de evidencia); sin TLS en ningún tramo.

---

## 5. Bugs y hallazgos bajos

1. **B1 (bloqueante) — Falta `secrets/gov_app_password.txt`.** `docker-compose.yml` declara el secreto `gov_app_password` (para `gov-mysql` y `gov-pago`) y `gen-secrets.sh` ya lo genera, pero **el archivo no existe** en este árbol (los secretos existentes son de antes de añadir ese secreto). `docker compose config` resuelve la ruta sin error, pero **`docker compose up` fallará** al montar el secreto. *Fix inmediato: `./scripts/gen-secrets.sh`.*
2. `/api/health` devuelve la **ruta absoluta** del modelo y su estado (`ml.py:68`) a cualquiera.
3. El 403 filtra `rule_id` (y la cuarentena, `CNT-IPS-QUARANTINE`) -> fingerprinting para afinar la evasión.
4. `gateway.py:202` reenvía **todas** las cabeceras salvo `Host`, incluidas hop-by-hop (`transfer-encoding`, `te`, `upgrade`, `proxy-*`, `x-forwarded-*`) -> riesgo de desincronización CL/TE en el upstream; y `gateway.py:213-221` deja `content-encoding` aunque `upstream_response.content` ya esté descomprimido por httpx -> respuestas corruptas. *Verificar en runtime.*
5. Uvicorn loguea el `path` **decodificado** crudo -> inyección de escapes ANSI / forging de líneas de log del operador.
6. `docs/PRD centinela.txt` (~líneas 99 y 121) mantiene credenciales de ejemplo (`POSTGRES_PASSWORD=secretcentinela`, `MYSQL_ROOT_PASSWORD=toor`) -> riesgo de copy-paste a un despliegue.
7. `Event.severity` sin `CHECK`; `public.py:82` usa `_SEVERITY_WEIGHT.get(s, 0)` -> severidad desconocida cuenta como 0 y sesga el KPI; `sector_mas_afectado` expone el nombre interno del objetivo.
8. `blocklist.py:86` instancia `Settings()` en import (segunda lectura de `.env`, ignora `get_settings()`); `config.py:48` degrada la lectura de secretos a `""` en silencio (arranca sin credencial y falla de forma confusa).
9. `attacker-sim` `--rotate-ips` es **no-op**: envía `x-forwarded-for`, pero el gateway lo ignora con `TRUSTED_PROXIES` vacío (`gateway.py:95-96`) -> la bandera engaña al usuario (todo sale por la misma IP del bridge).
10. `run.py:42-48`: al apagar, `event_queue.stop()` cancela el worker; solo se drena el lote en curso (`queue.py:108-111`), el resto de la cola **se pierde** (evidencia). Un DoS del gateway (C1) tumba también la API por compartir event loop.

---

## 6. ¿Hay puertas traseras? — No

Verificado explícitamente en `develop`:

- **Cero** `eval` / `exec` / `subprocess` / `os.system` / `pickle.loads` / `__import__` / `b64decode` / `compile` / `marshal` en `centinela-core/`. La única primitiva de ejecución de código es `joblib.load` (C5), que es una **superficie de riesgo**, no un backdoor.
- Sin rutas ocultas ni lógica condicionada a cabeceras, `User-Agent` o parámetros "mágicos": los endpoints son exactamente los del README.
- Sin URLs salientes salvo `https://api.deepseek.com` (configurable) y las dos URLs internas de los targets. Sin webhooks / telegram / pastebin / exfiltración.
- Sin credenciales hardcodeadas ni en git: `secrets/*` en `.gitignore`, `git status --ignored` los marca `!!`, `deepseek_api_key.txt` vacío, y `git log --all -- secrets` solo contiene `.gitkeep`/`README.md`.
- Los objetivos vulnerables (`targets/*`) están correctamente acotados: sin `ports:`, datos 100% sintéticos y comentarios que prohíben replicar los patrones.

**Conclusión:** no hay intención maliciosa en el código. Los riesgos reales son de **diseño y robustez del control de seguridad** (C1-C6) y de **operación** (B1), no de sabotaje.

---

## 7. Lo que está bien hecho en `develop` (no romper al corregir)

- Rol de BD de mínimos privilegios `centinela_app` (`config.py`, `db.py`, `03_grants.sh`): la app **ya no** se conecta como superusuario; `UPDATE` acotado a `(ai_summary, ai_status)` y `REVOKE DELETE/TRUNCATE` sobre `event`, inmutabilidad total sobre `audit_log`.
- `gov-pago` ya no usa `root` en MySQL: cuenta de aplicación `gov_app` con contraseña por secreto de Docker (y arreglado el bug de CRLF en `gen-secrets.sh`).
- Secretos por archivo (`*_FILE`) y no en `docker inspect`; `docs_url=None` en el gateway; compuerta `TRUSTED_PROXIES` (aunque con el bug M1).
- La IA **nunca** decide bloqueos, tiene timeout y plantilla de respaldo determinista; `mask_pii` antes de llamar al LLM; el ML va fuera del camino crítico.
- 20 reglas ordenadas por especificidad (cmdi antes que traversal), con nuevas coberturas: `CNT-TRAVERSAL-003` (wrappers php/file/data), `CNT-SQLI-005` (DDL/DML), `CNT-CMDI-003` (pipes a intérprete / `/dev/tcp`), `CNT-SCANNER-003`, `CNT-BRUTEFORCE-002`.
- Normalizador: variante `+` -> espacio, doble URL-decode (máx. 3 pasadas), neutralización de `\x00` y backslash.
- Cola: savepoint por evento, reintento `drop_rule_id` para no perder evidencia por FK, drenado por lote con flush al cancelar, tope `MAX_REQUEUE`.
- ML: resolución correcta de la ruta dentro del contenedor; acepta estimador "pelado"; degradación a `ml_score=None` sin romper el pipeline.
- Suites de tests ampliadas: auditoría, blocklist, cola, IA, sanitizador, API pública, redos, backpressure.

---

## 8. Plan de remediación priorizado

### Fase 1 — Contención (críticos)
1. `rules.yaml:158` -> patrón lineal `(?i)(username|usuario)=admin[^&\s]{0,64}(password|clave)=(admin|123456|root)`; `rules.py:96-98` -> **fail-closed** (bloquear con regla de presupuesto en vez de `continue`); `gateway.py` -> `MAX_BODY_BYTES` (~64 KiB) con `413` + evento y truncado del texto inspeccionado.
2. `soc.py:24,26-31` -> `docs_url=None/redoc_url=None/openapi_url=None`, CORS restringido a `localhost:5173`, `X-API-Key` por `Depends`; bind de puertos a `127.0.0.1` por defecto.
3. **B1** -> ejecutar `./scripts/gen-secrets.sh` para crear `secrets/gov_app_password.txt`.
4. Tests de regresión: `test_redos_budget` (`usuario=admin ` × 4000 < 10 ms), `test_evasion_corpus` (los 11 casos de C3), `test_header_inspection`, `test_body_limit`.

### Fase 2 — Motor de detección
5. Reglas genéricas: tautología (`(or|and)\s+('?[a-z0-9]+'?\s*=\s*'?[a-z0-9]+)`), `union\s+(all\s+)?select`, comentarios no anclados (`--|#|/\*`), time-based sin exigir paréntesis (`sleep|benchmark|pg_sleep|waitfor\s+delay`).
6. Inspección de cabeceras para todas las categorías (excluyendo `authorization`/`cookie` solo del muestreo de `payload_sample`, no de la evaluación).
7. Normalizador: tab `%09` y otros whitespace, JSON/`\uXXXX`, multipart; límite de texto inspeccionado.
8. Re-ejecutar `attacker-sim` con un `corpus_evasion.yaml` nuevo y medir recall/FP reales.

### Fase 3 — Integridad y aislamiento
9. `audit.py` + `queue.py:188`: incluir `ts|action|event_id` y los campos de `event` en el hash; `FOR UPDATE`/`pg_advisory_lock` en `append_entry`; detectar truncamiento en `verify_chain`.
10. `docker-compose.yml`: redes `edge-net`/`data-net`; `user: "10001"`, `read_only`, `cap_drop: ALL`, `deploy.resources.limits`; `mysql:8.4` (o MariaDB); frontend con build estático + nginx.
11. `run.py`: drenar la cola completa en `stop()`; separar los procesos del gateway y la API para que un DoS del gateway no tumbe el SOC.

### Fase 4 — Robustez de IA y operación
12. `provider._parse_llm_json`: validar `isinstance(data, dict)` + esquema cerrado; `worker`: estado terminal `failed` (requiere migrar el `CHECK` de `01_schema.sql:38`).
13. `sanitizer`: neutralizar `</payload_capturado>`, acotar `path` a 512 chars y usar (o eliminar) `looks_like_prompt_injection`; `prompts.py`: envolver `path` en `<ruta>`.
14. Hardening menor: validar/truncar `src_ip` a 45; purga de la blocklist; cabeceras hop-by-hop; logs con `repr`; `/api/health` sin ruta absoluta; `severity` con `CHECK`.

### Criterios de aceptación de la auditoría
- `pytest` verde **más** el corpus de evasión y el test de ReDoS real.
- `docker compose up` limpio (B1 resuelto).
- Demo con >=95% de detección y <=5% de FP **incluyendo** el corpus de evasión.
- p95 del motor < 10 ms con cuerpos de 64 KiB adversariales.
- `docker stop` en < 5 s sin pérdida de eventos.

---

## 9. Evidencia reproducible (apéndice)

**Evasiones (motor de `develop`):**
```text
tautologia 'a'='a      -> allow    union all select      -> allow
OR 2=2-- -             -> allow    subconsulta bool      -> allow
OR true-- -            -> allow    ;sleep 5              -> allow
;echo pwned            -> allow    ;python3 -c ...       -> allow
union%09all%09select   -> allow    SQLi/XSS/traversal en cabecera -> allow
```

**ReDoS (`CNT-BRUTEFORCE-001`, payload `usuario=admin ` repetido, sin match):**
```text
 6 KiB ->   56,7 ms
13 KiB ->  244,9 ms
27 KiB ->  977,0 ms   (cuadrático; ~1 MiB ≈ ~23 min)
```

**Amplificación del normalizador:** 8 MiB de cuerpo -> `inspectable_text` de 16 MiB (~2x), más el `bytes` original.

**Secreto faltante (B1):** `ls secrets/gov_app_password.txt` -> `No such file or directory`, mientras `docker compose config` lo resuelve a `secrets/gov_app_password.txt`.

---

*Informe generado por auditoría automática + manual sobre la rama `develop`. No se modificó código en esta pasada; los hallazgos quedan listos para priorizar en el backlog del equipo.*
