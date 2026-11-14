# Remediación de Seguridad — CENTINELA (Fases 1–4)

> Documento de justificación de los cambios aplicados tras la auditoría de ciberseguridad.
>
> **Rama:** `auditsecurity` · **Commit:** `8d0dc41` · **Base:** `develop` (`35bfcbd`)
> **Hallazgos de referencia:** `docs/AUDITORIA-SEGURIDAD.md`
> **Verificación:** `pytest` → **123 passed** · `docker compose config` → válido (EXIT 0)

---

## 1. Resumen ejecutivo

| Fase | Objetivo | Cambios | Hallazgos cerrados |
|---|---|---|---|
| 1 | Contención | 7 | **C1** ReDoS · **C2** API sin auth · **C4** cuerpo sin límite · **B1** secreto faltante |
| 2 | Motor de detección | 7 | **C3** 11 evasiones confirmadas |
| 3 | Integridad y aislamiento | 8 | **C6** hash incompleto · **M7** red plana · **M8** hardening · **B9** pérdida de cola |
| 4 | Robustez IA + hardening menor | 9 | **M4** livelock IA · **M5** prompt injection · **M1/M6/B2/B4/B5/B7** |

Cada cambio se documenta con cuatro preguntas: **Qué** se cambió, **Cómo** se implementó, **Por qué** era necesario (hallazgo de la auditoría) y **Para qué** sirve (objetivo/resultado).

---

## 2. Fase 1 — Contención

### 2.1 ReDoS en `CNT-BRUTEFORCE-001` (C1)
- **Qué:** Se sustituyó el patrón `(?i)(username|usuario)=admin.*(password|clave)=...` por una versión **lineal** acotada: `admin[^=]{0,64}(password|clave)=...`.
- **Cómo:** El `.*` (cuantificador no acotado entre dos literales) provocaba *backtracking catastrófico*; se reemplazó por una clase negada `[^=]{0,64}` de longitud máxima 64, que conserva la detección (`username=admin&password=admin`) pero hace el coste lineal.
- **Por qué:** En la auditoría se midió que 27 KiB de `usuario=admin ` repetido tardaban **~977 ms** (cuadrático: ~1 MiB ≈ 23 min) con veredicto `allow`, un DoS de una sola petición contra el gateway (y contra la API, que comparte event loop).
- **Para qué:** Que ningún payload adversario pueda colgar el proceso; la regla evalúa ahora en **~2 ms** para 56 KiB.

### 2.2 Presupuesto por regla fail-closed (C1)
- **Qué:** `rules.py` ya no descarta en silencio una regla lenta (`continue`); ahora **bloquea** con `CNT-ENGINE-BUDGET`.
- **Cómo:** Si una regla excede `PER_RULE_TIMEOUT_SECONDS` (0.05 s) sin hacer match, `evaluate()` devuelve `verdict="block"` con `rule_id="CNT-ENGINE-BUDGET"` en lugar de seguir evaluando.
- **Por qué:** El `continue` era **fail-open**: una regla que se volviera lenta quedaba desactivada y el atacante la evadía. La regla de presupuesto se sembró en `02_seed_attack.sql` para no romper la FK `event.rule_id`.
- **Para qué:** Convertir la latencia anómala de una regla en un bloqueo preventivo (defensa en profundidad), en vez de una puerta abierta.

### 2.3 Tope del texto inspeccionable (C1/C4)
- **Qué:** `normalizer.py` trunca `inspectable_text` a `MAX_INSPECTABLE_CHARS = 64 * 1024`.
- **Cómo:** `self.inspectable_text = "\n".join(parts)[:MAX_INSPECTABLE_CHARS]`.
- **Por qué:** Ninguna regla opera ya sobre una entrada arbitrariamente grande (query/body gigantes hacían lentas todas las reglas y disparaban el presupuesto fail-closed sobre tráfico legítimo).
- **Para qué:** Acotar el peor caso de CPU/memoria del motor por petición.

### 2.4 Límite del cuerpo HTTP (C4)
- **Qué:** `gateway.py` rechaza cuerpos > `MAX_BODY_BYTES = 64 * 1024` con **413** y registra un evento `CNT-BODY-TOO-LARGE`.
- **Cómo:** Se comprueba `Content-Length` antes de leer y `len(body)` después de leer; ambos devuelven `_reject_body_too_large(...)` (413 + evento de evidencia).
- **Por qué:** `await request.body()` sin tope permitía agotar la memoria del core con una sola petición (y amplificaba el ReDoS).
- **Para qué:** Un contrato de tamaño máximo explícito, con evidencia auditable cuando se viola.

### 2.5 API del SOC: docs off, CORS restringido, X-API-Key (C2)
- **Qué:** `api_app` cierra `/docs`, `/redoc` y `/openapi.json`; el CORS deja de ser `*` (ahora `localhost:5173`); las rutas del SOC exigen `X-API-Key` cuando `API_KEY` está definida.
- **Cómo:** `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`; `allow_origins=settings.cors_origin_list`; dependencia `require_api_key` sobre `/api/stats`, `/api/events`, `/api/blocklist` y `/api/audit/verify` (quedan abiertas `/api/health` para el healthcheck y `/api/public/*` por diseño).
- **Por qué:** La telemetría completa del SOC (con `src_ip` y `payload_sample`) era pública y legible por cualquier origen vía CORS `*`; la app exponía su esquema en `/docs`.
- **Para qué:** Evitar la exfiltración de la telemetría desde el navegador del analista y el fingerprinting de la API.

### 2.6 Puertos en `127.0.0.1` (C2/M8)
- **Qué:** `docker-compose.yml` publica `8080`, `3000` y `5173` solo en loopback (`127.0.0.1:puerto:puerto`).
- **Cómo:** Se antepuso `127.0.0.1:` a cada mapeo de puertos del host.
- **Por qué:** Estaban expuestos en `0.0.0.0` (toda la red) sin necesidad para una demo local.
- **Para qué:** Reducir la superficie de ataque a la máquina que ejecuta la demo.

### 2.7 Secreto `gov_app_password.txt` (B1)
- **Qué:** Se generó el secreto faltante `secrets/gov_app_password.txt` (modo 600).
- **Cómo:** `./scripts/gen-secrets.sh` (que ya lo contemplaba, pero el árbol tenía secretos viejos).
- **Por qué:** `docker-compose.yml` declara el secreto `gov_app_password` para `gov-mysql` y `gov-pago`; sin el archivo, `docker compose up` falla al montarlo.
- **Para qué:** Que el entorno levante y que la cuenta de aplicación MySQL use credencial propia (no root).

---

## 3. Fase 2 — Motor de detección

### 3.1 Reglas generalizadas (C3)
- **Qué:** Cinco reglas de `rules.yaml` se reescribieron para cubrir variantes reales de ataque que antes pasaban:
  - `CNT-SQLI-001` → tautología genérica `X=X`, `'a'='a`, `2=2`, subconsultas `(SELECT …)`, `OR true/false`.
  - `CNT-SQLI-002` → `union [all|distinct] select` (antes solo `union select`).
  - `CNT-SQLI-003` → comentarios `--`/`#` no anclados + `/* */` perezoso (antes anclado a fin de línea).
  - `CNT-SQLI-004` → `sleep/benchmark/pg_sleep/waitfor delay` sin exigir paréntesis.
  - `CNT-CMDI-001` → lista de binarios ampliada (`echo`, `printf`, `python3`, `perl`, `ruby`, `node`, `php`, etc.).
- **Cómo:** Se editó `rules.yaml` y se sincronizó `02_seed_attack.sql` (la copia para FK/join), manteniendo **20 reglas y 6 categorías** (el contrato de `test_rule_catalog_completeness`).
- **Por qué:** La auditoría confirmó **11 evasiones** (`'a'='a`, `union all`, `OR 2=2`, subconsultas, `;sleep 5`, `;echo`, `;python3 -c`, `union%09all%09select`, SQLi/XSS/traversal en cabeceras…); el corpus de tests solo usaba las cadenas exactas de las reglas, dando falsa seguridad.
- **Para qué:** Elevar el recall real del motor sin añadir reglas (ni romper el contrato), y cerrar la vía de bypass más obvia.

### 3.2 Inspección de cabeceras (C3)
- **Qué:** Las reglas de "body" ahora también evalúan el contenido de las cabeceras HTTP.
- **Cómo:** En `rules.py` se construye `headers_text` (excluyendo `authorization`, `cookie`, `proxy-authorization`, `set-cookie` por portar secretos) y se concatena a `inspectable_text` en el `body_haystack`.
- **Por qué:** Antes solo `CNT-SCANNER-001` miraba cabeceras; un SQLi/XSS/traversal en `X-*`, `Referer`, `User-Agent` o `Cookie` pasaba siempre.
- **Para qué:** Cerrar el vector de evasión por cabecera sin filtrar secretos a los eventos.

### 3.3 Decodificación de escapes JSON `\uXXXX` (C3)
- **Qué:** `normalizer.py` añade `_decode_unicode_escapes`, que convierte `\u0027` → `'` (y similares).
- **Cómo:** `re.compile(r"\\u([0-9a-fA-F]{4})")` aplicado tras el doble URL-decode, ignorando puntos de código sustitutos para no generar `chr()` inválidos.
- **Por qué:** Un payload codificado como JSON (`\u0061` para `a`) evadía las reglas porque los literales quedaban como texto con backslash.
- **Para qué:** Que la codificación JSON no sea un mecanismo de evasión.

---

## 4. Fase 3 — Integridad y aislamiento

### 4.1 Hash de auditoría completo (C6)
- **Qué:** El hash encadenado ahora cubre `ts + action + event_id + payload` (antes solo `payload`).
- **Cómo:** `append_entry` hashea `_entry_record(...)`, y `verify_chain` recomputa la misma estructura; el `payload` que se pasa ahora incluye la evidencia real del evento (`src_ip`, `path`, `method`, `target`, `verdict`, `rule_id`, `category`, `severity`, `technique_id`, `engine_us`, `payload_sample`).
- **Por qué:** Alterar `ts`, `action` o cualquier campo de `event` (por ejemplo la IP de origen) no rompía la cadena: quedaban fuera del hash.
- **Para qué:** Que la cadena detecte cualquier manipulación de la evidencia, no solo del diccionario `payload`.

### 4.2 Ancla anti-truncamiento `audit_anchor` (C6)
- **Qué:** Nueva tabla `audit_anchor` (fila única `id=1`) con el `id` y el `hash` del último eslabón.
- **Cómo:** `append_entry` actualiza el ancla en cada alta; `verify_chain` compara el último eslabón contra el ancla y reporta `truncated: true` si no coinciden.
- **Por qué:** El hash encadenado por sí solo **no detecta** el borrado del final de la cadena (la cola): si un atacante borra los últimos N registros, la cadena interna sigue "válida".
- **Para qué:** Detectar truncamiento (borrado de la cola), la manipulación que la cadena sola no puede ver.

### 4.3 Serialización de altas (C6)
- **Qué:** `append_entry` se serializa con un `asyncio.Lock` a nivel de módulo.
- **Cómo:** `async with _append_lock:` envuelve la lectura del `last` y la escritura del eslabón.
- **Por qué:** Dos escritores concurrentes podían leer el mismo `last` y bifurcar la cadena (dos eslabones con el mismo `prev_hash`).
- **Para qué:** Integridad de la cadena bajo concurrencia dentro del proceso (en réplicas múltiples, sustituir por `pg_advisory_xact_lock`).

### 4.4 Drenado de cola al apagar (B9)
- **Qué:** `EventQueue.stop()` drena los eventos pendientes antes de terminar.
- **Cómo:** Tras cancelar el worker, `_drain_remaining()` extrae todo lo que quede en `asyncio.Queue` y llama a `_flush`.
- **Por qué:** Al apagar (`docker stop`), solo se descargaba el lote en curso; el resto de la cola (evidencia) se perdía.
- **Para qué:** No perder evidencia forense durante el apagado.

### 4.5 Segmentación de red (M7)
- **Qué:** La red plana única `dmz-net` se dividió en tres: `edge-net` (gateway + objetivos + frontend + simulador), `data-net` **internal** (solo core ↔ centinela-db) y `targets-db-net` **internal** (solo gov-pago ↔ gov-mysql).
- **Cómo:** Se reasignaron los `networks:` de cada servicio en `docker-compose.yml` (el core queda en `edge-net` y `data-net`; gov-pago en `edge-net` y `targets-db-net`).
- **Por qué:** Los objetivos vulnerables por diseño (RCE) compartían red con la BD de evidencia y con la API; comprometer un objetivo daba acceso directo a ambas bases de datos.
- **Para qué:** Aislar la evidencia (`centinela-db`) y la BD del objetivo (`gov-mysql`) de los contenedores comprometibles.

### 4.6 Hardening del core (M8)
- **Qué:** `centinela-core` ahora corre **no-root** y restringido.
- **Cómo:** `user: "10001:10001"`, `cap_drop: [ALL]`, `security_opt: no-new-privileges:true`, `read_only: true` + `tmpfs: /tmp`, `mem_limit: 512m`, `cpus: 1.0`.
- **Por qué:** El contenedor corría como root sin límites; un RCE (p. ej. vía `joblib.load`) tendría acceso total.
- **Para qué:** Limitar el impacto de un compromiso del core (sin root, sin capacidades, con recursos acotados).

### 4.7 MySQL 8.0 y frontend nginx (M8)
- **Qué:** `gov-mysql` pasó de `mysql:5.7` (EOL) a `mysql:8.0`; el frontend dejó de usar el servidor de desarrollo de Vite.
- **Cómo:** `image: mysql:8.0`; `frontend/Dockerfile` multi-etapa (build con Node → servir con `nginx:alpine`) + `frontend/nginx.conf` con `try_files` para el SPA; el puerto pasa a `5173:80`.
- **Por qué:** MySQL 5.7 está EOL desde oct-2023 (CVEs sin parche); Vite dev no es para producción (superficie de dev server, sin build minificado).
- **Para qué:** Versiones mantenidas y servido estático de producción. *(Nota: requiere `docker compose down -v` para recrear el volumen de MySQL.)*

---

## 5. Fase 4 — Robustez de IA y hardening menor

### 5.1 Parseo del LLM validado (M4)
- **Qué:** `_parse_llm_json` valida que la respuesta sea un **objeto** con las tres claves del esquema.
- **Cómo:** `if not isinstance(data, dict): raise ValueError(...)` y comprobación de `resumen`/`severidad_sugerida`/`mitigacion_sugerida` antes de indexar.
- **Por qué:** Si el LLM devolvía `[...]`, `"texto"` o `null`, `data["resumen"]` lanzaba **`TypeError`** (no capturado), el evento quedaba `pending` y el worker lo reintentaba **indefinidamente** (1 llamada al LLM por segundo).
- **Para qué:** Que cualquier salida malformada caiga a la plantilla de respaldo, sin livelock.

### 5.2 Estado terminal `failed` (M4)
- **Qué:** El worker marca `ai_status='failed'` ante un error inesperado del proveedor.
- **Cómo:** `try/except` alrededor de `provider.triage` en `_process_pending_batch`; en el `except` se escribe `ai_summary="[error] ..."` y `ai_status="failed"`; el `CHECK` de `ai_status` acepta `'failed'`.
- **Por qué:** Sin un estado terminal, cualquier excepción residual dejaba el evento en `pending` para siempre.
- **Para qué:** Garantizar que el pipeline de triage siempre converge (el evento no se reintenta indefinidamente).

### 5.3 Anti prompt-injection (M5)
- **Qué:** Se cierran dos vectores: el *fence-escape* del payload y el `path` no delimitado.
- **Cómo:** `sanitize_payload_for_llm` reemplaza `</payload_capturado>` y `<payload_capturado>` por marcadores inertes; `prompts.py` envuelve la ruta en `<ruta>…</ruta>` (declarada como DATO en el system prompt) y la acota a 512 caracteres; `provider` usa `looks_like_prompt_injection` para caer a la plantilla si detecta marcadores.
- **Por qué:** Un payload con el cierre `</payload_capturado>` podía "salir" del bloque de datos y convertirse en instrucción; el `path` iba fuera de cualquier bloque delimitado. `looks_like_prompt_injection` existía pero era código muerto.
- **Para qué:** Que el contenido del atacante sea tratado siempre como dato, nunca como instrucción, y que la función defensiva existente se use de verdad.

### 5.4 IP de origen validada y truncada (M1)
- **Qué:** `_client_ip` valida que el valor sea una IP real y lo trunca a 45 caracteres.
- **Cómo:** `ipaddress.ip_address(candidate)` con fallback al peer si no es válida; `return candidate[:45]`.
- **Por qué:** Un `X-Forwarded-For` malformado podía superar `VARCHAR(64)` y provocar `DataError` (pérdida silenciosa de evidencia) o inyectar texto arbitrario en la evidencia.
- **Para qué:** Evidencia íntegra y persistencia garantizada del evento.

### 5.5 Cabeceras hop-by-hop filtradas (B4)
- **Qué:** El gateway ya no reenvía cabeceras hop-by-hop ni metadatos de proxy.
- **Cómo:** Conjuntos `_HOP_BY_HOP_REQUEST_HEADERS` / `_HOP_BY_HOP_RESPONSE_HEADERS` aplicados en el reenvío y en la respuesta (incluye `content-encoding`, ya descomprimido por httpx).
- **Por qué:** Reenviar `transfer-encoding`/`content-length`/`connection` permite desincronización CL/TE en el upstream, y dejar `content-encoding` tras la descompresión corrompe las respuestas.
- **Para qué:** Evitar *request smuggling* y respuestas corruptas.

### 5.6 Purga de la blocklist (M6)
- **Qué:** `snapshot()` purga cuarentenas expiradas y detecciones antiguas.
- **Cómo:** Se eliminan IPs de `_quarantined_until` vencidas y de `_hits`/`_last_block` sin hits dentro de la ventana.
- **Por qué:** Los mapas crecían indefinidamente (una IP que dejó de verse conservaba su entrada para siempre).
- **Para qué:** Memoria acotada en el proceso del gateway.

### 5.7 `/api/health` sin ruta absoluta (B2)
- **Qué:** `ml_scorer.status()` ya no expone `model_path`.
- **Cómo:** Se eliminó la clave `model_path` del dict de estado.
- **Por qué:** Filtrar la ruta absoluta del host a cualquiera facilita el reconocimiento del entorno.
- **Para qué:** No revelar rutas del sistema en un endpoint público.

### 5.8 `CHECK` de severidad (B7)
- **Qué:** La severidad de `event` queda restringida a `baja|media|alta|critica` (o NULL).
- **Cómo:** `CheckConstraint` en el modelo `Event` y `CHECK` en `01_schema.sql`.
- **Por qué:** Una severidad desconocida contaba como 0 en `_SEVERITY_WEIGHT` y sesgaba el KPI del Observatorio.
- **Para qué:** Integridad de los datos y de las métricas agregadas.

### 5.9 Logs saneados (B5)
- **Qué:** `run.py` instala un filtro que elimina caracteres de control de los mensajes de log.
- **Cómo:** `_SanitizeLogFilter` reemplaza caracteres `< 0x20` (salvo tab/LF/CR) por `?` en `uvicorn`/`centinela`.
- **Por qué:** El gateway loguea el path decodificado; un path con secuencias ANSI podía inyectar escapes de terminal o forjar líneas.
- **Para qué:** Logs íntegros y terminal del operador no manipulable.

---

## 6. Pruebas añadidas

| Archivo | Cubre |
|---|---|
| `tests/test_f1_security_hardening.py` | ReDoS lineal (< 10 ms), presupuesto fail-closed, 413 de cuerpo |
| `tests/test_evasion_corpus.py` | 14 casos de evasión (11 corpus + 3 cabeceras) + cero FP en tráfico legítimo |
| `tests/test_f3_integrity.py` | Hash cubre `action`/`event_id`, truncamiento detectado, drenado de cola |
| `tests/test_f4_robustez.py` | LLM no-objeto, esquema incompleto, fence-escape, worker `failed`, purga de blocklist |

**Resultado global:** `pytest` → **123 passed** (100 originales + 23 nuevos).

---

## 7. Pendientes (backlog)

1. **Separación de procesos** gateway/API: requiere pub/sub (Redis) o SSE desde BD; hoy comparten cola en memoria. El riesgo original (DoS del gateway tumba el SOC) quedó mitigado por el arreglo del ReDoS y el input acotado.
2. **Validar en runtime** `docker compose up` (mysql:8.0 con `down -v`, build nginx, `read_only`). `docker compose config` ya valida la estructura.
3. **Parseo de `multipart`** y **`corpus_evasion.yaml`** para el `attacker-sim` (hoy los casos de evasión viven como tests unitarios).
4. **Firma/verificación del modelo ML** (`joblib.load` sobre artefacto no verificado) — C5.
5. **Anclaje externo WORM** (export del hash a un fichero/sistema externo) para que ni un superusuario pueda borrar y recalcular la cadena completa.
