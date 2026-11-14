# Asignación de tareas — CENTINELA (contra el esqueleto ya construido)

> Este documento es el complemento operativo de `docs/SPRINT-1.md`. SPRINT-1.md
> describe el plan por fase y por rol tal como se decidió en la planificación;
> este documento parte del **esqueleto ya creado en el repositorio** y dice,
> archivo por archivo, qué existe, qué falta y en qué orden, para que cada
> persona pueda empezar a trabajar sin tener que releer todo el SDD.
>
> Checklist: `[x]` ya existe en el repo (aunque sea una primera versión).
> `[ ]` es trabajo pendiente de esa persona.

---

## Estado general (actualizado 2026-11-14, tarde)

**Ramas:**
- `main` — solo el esqueleto inicial (`411c3fe`), congelado.
- `develop` — fuente de verdad actual del equipo. Ya incluye la infraestructura de devops de Karla (PR #1) y las correcciones de privilegios/auditoría de la rama `mli` (PR #2, Luis). Backend compila, **52/52 tests en verde**, `docker compose config` válido, frontend compila y tipa sin errores (`tsc -b` y `vite build` limpios).
- `motor` (Iván) — **lista para PR a `develop`**: sube el catálogo de reglas de 14 a 20, endurece el normalizador (null bytes, separadores invertidos) y amplía la suite a 43 tests propios. Tenía conflictos reales contra `develop` (no solo de texto) en `rules.yaml` y `db/init/02_seed_attack.sql`; ya se resolvieron, se corrigió un orden interno roto durante la resolución (`CNT-CMDI-003` debe evaluarse antes que `CNT-CMDI-001`) y se verificó con **52/52 tests en verde**. Mergeada y pusheada a `origin/motor` (`184dffd`); falta que alguien del equipo abra/apruebe el PR en GitHub.
- Equipo: José Estanga (documentación) es el único rol sin commits propios todavía en el repo.

**Lo que ya funciona de punta a punta (en `develop`):** gateway inline con bloqueo determinista, IPS con cuarentena, cola + auditoría con cadena de hashes verificable, triage de IA con DeepSeek real (con *fallback*), 5 indicadores del Observatorio, separación de privilegios de BD (`centinela_app` sin permisos de `UPDATE`/`DELETE`/`TRUNCATE` salvo las dos columnas de triage), secretos fuera de `.env`, los 6 servicios de `docker compose up` quedan `healthy`.

**Lo que falta de verdad (no evidencia, trabajo real):**
1. Fusionar `motor` → `develop` (PR abierto en GitHub, pendiente de aprobación/merge).
2. Frontend: filtros de eventos, mapa de calor, verificación visual de SSE en navegador, accesibilidad y pulido para proyector — **ahora a cargo de Rafael** (ver sección 4, roles actualizados más abajo).
3. ML: F1 por debajo del objetivo del SDD #23 (0,746–0,755 vs. 0,90 requerido); Plan B activado (el motor de reglas decide, el ML es señal complementaria). No bloquea la demo.
4. Documentación: capturas reales, reporte de métricas visible para el jurado, guion del pitch cronometrado — pendiente de José Estanga.
5. Fase F6 (demo en vivo) y pitch — no iniciado.

---

## Roles (actualizado 2026-11-14)

> **Aclaración de identidades**, porque el documento usa alias de proyecto: la persona detrás de **"José Oropeza"** (sección 3, backend datos/ML/IA) y de **"Rafael"** (el rol que en `docs/SPRINT-1.md` quedó "sin definir") es la misma persona (`Rafael Oropeza`, usuario de git `rafaopz`). A partir de ahora esa persona **se encarga del Frontend** (antes bajo el nombre de Luis en este documento). Las tareas de integración que estaban bocetadas para el rol "Rafael" (ver la sección 6 original de este documento) las terminó haciendo **Luis** — evidencia: commit `12cea61 "fase 1 trabajo realizado"` en la rama `mli` (autor `Hakaraf`), que separó el usuario de BD `centinela_app` del superusuario en `config.py`/`docker-compose.yml`. La sección 4 de abajo (antes "Luis — Frontend") pasa a estar a cargo de **Rafael**; el checklist de tareas pendientes no cambia, solo el dueño.

---

## 0. Bloqueos que afectan a todo el equipo (resolver primero)


- [x] **El entorno ya se corrió de punta a punta** (verificación del 2026-11-14): `docker compose up -d --build --wait` termina con código 0 y los 6 servicios en `healthy`. Evidencia y pendientes en la sección de Karla.
- [x] **El dataset NSL-KDD ya está descargado en `ml/data/` y modelo entrenado.** Se descargaron `KDDTrain+.txt` y `KDDTest+.txt` y se ejecutó `ml/train.py`. Plan B activado tras evaluación de métricas.
- [x] **`DEEPSEEK_API_KEY` configurado y probado contra la API real.** Ya no vive en `.env`: se pega en `secrets/deepseek_api_key.txt` (Docker secret, permisos 600, fuera de git). Triage verificado contra `https://api.deepseek.com` con respuesta `[llm]` en español claro y actualización de estado a `done`.
- [ ] **Rama `motor` lista pero sin mergear.** Pusheada a `origin/motor` (`184dffd`), sin conflictos contra `develop` (ya resueltos localmente). Falta abrir/aprobar el PR en GitHub — bloquea que el catálogo de 20 reglas y los 43 tests de Iván lleguen a `develop`.


---

## 1. Karla — DevOps

**Ya existe:**
- [x] `docker-compose.yml` — 6 servicios (`centinela-db`, `centinela-core`, `frontend`, `gov-mysql`, `gov-pago`, `tickets`) + `attacker-sim` bajo el perfil `demo`, red `dmz-net`, healthchecks, `depends_on` con `condition: service_healthy`.
- [x] Dockerfiles de los 5 servicios que se construyen (`centinela-core`, `frontend`, `gov-pago`, `tickets`, `attacker-sim`).
- [x] `.env.example` con todas las variables necesarias.
- [x] `.gitignore` (excluye `.env`, `node_modules/`, `ml/data/*`, `ml/model/*`, etc.).
- [x] `gov-pago` y `tickets` **sin** bloque `ports:` en `docker-compose.yml` — solo alcanzables vía gateway.
- [x] `Makefile` (`make secrets`, `make up`, `make demo`, `make reset-db`, `make test`) y equivalentes de Windows en `scripts/demo.ps1`, `scripts/reset-db.ps1` y `scripts/gen-secrets.ps1`.
- [x] **Healthchecks en los 6 servicios** (antes solo 3): `frontend` (wget a Vite), `gov-pago` (`fsockopen` de PHP a Apache), `tickets` (`http.get` a Node) y `gov-mysql` (ping con la contraseña leída del secreto). Sin ellos, `docker compose up --wait` devolvía 0 con servicios caídos.
- [x] **Secretos fuera de `.env`**: `secrets/README.md`, `scripts/gen-secrets.sh`/`.ps1` y Docker secrets con `*_FILE` (`POSTGRES_PASSWORD_FILE`, `MYSQL_ROOT_PASSWORD_FILE`, `DATABASE_PASSWORD_FILE`, `DEEPSEEK_API_KEY_FILE`). Archivos con permisos 600, en `.gitignore`, invisibles en `docker inspect`.

**Pendiente (en orden):**
1. [x] `cp .env.example .env` + `make secrets` + `docker compose up --build --wait`. **Verificado:** 6/6 servicios `healthy`, `up --wait` exit 0 (compuerta F0).
2. [x] **Aislamiento verificado:** `docker compose ps` no publica puertos de `gov-pago` (80) ni `tickets` (4000); `curl localhost:4000` y `curl localhost:80` fallan desde el host; ambos responden 200 a través de `localhost:8080` (y `gov-pago/consulta.php` devuelve datos reales de MySQL, lo que prueba el secreto de MySQL cargado por el entrypoint PHP).
3. [x] **Volumen del modelo verificado** con un bundle sintético con el mismo formato: `GET /api/health` reporta `ml.model_path=/app/ml/model/nsl_kdd_rf.joblib`, `model_present`, `model_loaded` y `feature_columns=41`, y el `ml_score` llega a la columna `event.ml_score`. Falta solo el `.joblib` real de José Oropeza.
4. [x] **Higiene de secretos:** `grep -Ei '(password|api_key|secret|token)\s*=' .env .env.example` → sin resultados; `.env` y `secrets/*.txt` ignorados por git; `docker inspect` solo muestra rutas `*_FILE`.
5. [x] **`make reset-db` verificado:** `TRUNCATE` de `event`/`audit_log`, reinicio del core para vaciar la cuarentena en memoria y espera activa hasta `healthy`, en **6,6 s**. Cadena vuelve a GENESIS (`/api/audit/verify` → `valid: true`).
6. [ ] Fase F6: operar la demo en vivo (terminal visible, proyector, `scripts/demo.ps1` listo para disparar).

---

## 2. Iván — Backend (motor y gateway)

**Ya existe:**
- [x] `centinela-core/app/engine/normalizer.py` — decodificación de URL repetida (cubre doble codificación), normalización de mayúsculas.
- [x] `centinela-core/app/engine/rules.yaml` — catálogo de **14 reglas** en `develop` cubriendo las 6 categorías del contrato: `sqli` (4), `xss` (3), `traversal` (2), `cmdi` (2), `scanner` (2), `bruteforce` (1). **Sube a 20 en la rama `motor`** (lista para PR, ver "Estado general" al inicio del documento) con `sqli` (5), `xss` (4), `traversal` (3), `cmdi` (3), `scanner` (3), `bruteforce` (2).
- [x] `centinela-core/app/engine/rules.py` — compila las reglas una vez al arrancar, evalúa con tope de tiempo por regla (5 ms), devuelve el `Verdict` con `engine_us` medido.
- [x] `centinela-core/app/gateway.py` — reverse proxy real con `httpx.AsyncClient`. BLOCK → `403` inmediato sin tocar el objetivo. ALLOW → reenvía por prefijo de ruta (`/gov-pago/...`, `/tickets/...`).
- [x] `centinela-core/app/ips/blocklist.py` — 3 detecciones en 60 s → cuarentena de 5 minutos, consultado por el gateway antes de evaluar reglas.
- [x] `centinela-core/tests/test_rules.py` — casos positivos y negativos por categoría, incluida evasión por doble codificación de URL. **11/11 en verde.**
- [x] **Hallazgo corregido en la primera verificación:** `CNT-SQLI-001` no detectaba la tautología canónica `' OR '1'='1` (el patrón exigía `1=1` sin comillas) y el normalizador no traducía `+` a espacio, así que `union+select` también evadía. Ambos huecos quedaron cerrados y el corpus completo (10/10 plantillas) se bloquea, verificado con la API interna del motor.

**Pendiente (en orden):**
1. [x] Entorno levantado y simulador ejecutado: **1.000 peticiones, 100% de detección, 0% de falsos positivos del motor, p95 1,8 ms** (compuerta F3 superada). Detalle de la medición en la sección de Karla.
2. [x] Medición contra el corpus real hecha. El cambio de patrón se replicó en `db/init/02_seed_attack.sql` (catálogo) y `rules.yaml` (motor), tal como exige la nota de ese archivo.
3. [x] Hueco de evasión cerrado (`+` = espacio y `%20`), además del reordenamiento `cmdi` antes de `traversal` para que `; cat /etc/passwd` se clasifique como ejecución de comandos y no como LFI (era el test que estaba en rojo).
4. [ ] Ampliar `tests/test_rules.py` con los casos nuevos que se descubran al afinar contra el corpus (regla de oro: cada bug de falso negativo/positivo encontrado en la demo debe quedar como test). Los dos huecos de arriba ya están cubiertos por `test_sqli_is_blocked` y `test_double_url_encoding_is_still_caught`; falta un caso explícito para `+` como espacio.
5. [ ] Confirmar que `engine_us` medido en producción (no en los tests) se mantiene bajo 10.000 µs (10 ms) de forma consistente; si no, revisar si alguna regla regex es más costosa de lo esperado (el `PER_RULE_TIMEOUT_SECONDS` en `rules.py` ya descarta reglas lentas, pero es mejor arreglar el patrón que depender del timeout).

**Nota sobre la métrica de falsos positivos:** el simulador sale por una sola IP, así que tras 3 detecciones el IPS pone ese host en cuarentena y absorbe el resto del corpus (legítimo incluido). Por eso `attacker-sim` ahora separa "bloqueos por regla" de "bloqueos por cuarentena": el FP del motor se mide sobre lo que el motor evaluó, y la contención del host se reporta aparte. Una navegación real desde el host (otra IP) sigue devolviendo `200` mientras el atacante está en cuarentena — eso es exactamente lo que se quiere mostrar en el pitch.

---

## 3. José Oropeza — Backend (datos, ML e IA)

**Ya existe:**
- [x] `db/init/01_schema.sql` — tablas `event`, `rule`, `attack_technique`, `audit_log` con los índices compuestos para los filtros del panel (severidad+fecha, IP+fecha, verdict+fecha).
- [x] `db/init/02_seed_attack.sql` — 15 técnicas MITRE ATT&CK y el catálogo de 14 reglas con su `technique_id`, más la fila `CNT-IPS-QUARANTINE` que da FK válida a los eventos de cuarentena (antes rompían la transacción y se perdía el 90% de la evidencia).
- [x] `db/init/03_grants.sh` — rol `centinela_app` con `GRANT SELECT, INSERT` y `REVOKE UPDATE, DELETE, TRUNCATE` explícito sobre `event` y `audit_log`. Pasó de `.sql` a `.sh` para (a) tomar el nombre de la BD de `POSTGRES_DB` en vez de tenerlo hardcodeado y (b) derivar el password del rol con `sha256("centinela_app:" + POSTGRES_PASSWORD)`, sin credenciales en el repositorio.
- [x] `centinela-core/app/queue.py` — cola en memoria + escritura por lotes, ahora con **savepoint por evento**: una fila inválida se reintenta sin `rule_id` y no arrastra al resto del lote. También calcula `ml_score` (vía `engine/features.py`) y marca `ai_status='done'` en los `allow`.
- [x] `centinela-core/app/storage/audit.py` — cadena de hashes `sha256(hash_anterior + contenido)` y `verify_chain()`.
- [x] `centinela-core/app/engine/ml.py` — resuelve el modelo por `ML_MODEL_PATH` → `/app/ml/model` → repo (antes `parents[3]` apuntaba a `/ml/model` dentro del contenedor y nunca lo encontraba), acepta bundle `{model, encoders, feature_columns}` y expone su estado en `/api/health`.
- [x] `ml/train.py` + `ml/README.md` — entrena un `RandomForestClassifier` sobre NSL-KDD, reporta F1-score y tasa de falsos positivos en un `.metrics.json` y guarda el bundle con encoders y orden de columnas para que la inferencia reproduzca la codificación exacta.
- [x] `centinela-core/app/ai/sanitizer.py` — enmascara PII (cédulas, correos, teléfonos, tarjetas) y detecta marcadores de inyección de prompts.
- [x] `centinela-core/app/ai/provider.py` — `LLMProvider` abstracto + `DeepSeekProvider`, salida JSON validada contra esquema cerrado, timeout de 3 s, *fallback* a plantilla determinista.
- [x] `centinela-core/app/ai/worker.py` — procesa eventos `pending` en lotes de 100 y los marca `done` siempre. **Ya se arranca desde `run.py`** (antes estaba definido pero nadie lo invocaba) y drena 1.000 eventos en ~6 s.
- [x] `centinela-core/app/api/public.py` — los 5 indicadores agregados del Observatorio, calculados sobre `event`.

**Pendiente (en orden):**
1. [x] Descargar `KDDTrain+.txt` y `KDDTest+.txt` en `ml/data/` (ver `ml/README.md`) — **Completado**.
2. [x] Correr `python ml/train.py` y revisar `ml/model/nsl_kdd_rf.metrics.json`. Si `meets_sdd23_criteria` es `false`, decidir con el equipo si se ajustan hiperparámetros (`--n-estimators`, `max_depth` en el propio script) o si se activa el plan B de la compuerta de F3 (presentar solo el motor de reglas). — **Completado**: F1=0.7460 / FP=2.84% (`meets_sdd23_criteria: false`). Se probó ajuste de hiperparámetros (`max_depth=30/None`, F1=0.7546) y se activa el **Plan B de F3** (el motor de reglas lidera el bloqueo y el ML opera como señal asíncrona complementaria `ml_score`).
3. [x] Conseguir o confirmar la clave real de `DEEPSEEK_API_KEY` y probar `app/ai/worker.py` contra la API real (no solo el *fallback*). Revisar que `ai_summary` se redacte en español claro y que `ai_status` pase de `pending` a `done`. — **Completado**: Clave real confirmada y configurada en `.env`; probado contra `https://api.deepseek.com/chat/completions`. Se validó la inferencia del LLM (`[llm]`), redacción en español claro de resumen/mitigación y transición de estado a `done`.
4. [x] Verificar en una base ya levantada que el rol `centinela_app` (creado por `db/init/03_grants.sh`) es efectivamente el que usa `DATABASE_URL` — si `centinela-core` se conecta con el usuario admin en vez de `centinela_app`, los `REVOKE` no protegen nada. — **Completado, y corregido durante el merge `develop` → `mli` del 2026-11-14**: se detectó que `centinela-core` seguía conectándose como `${POSTGRES_USER}` (admin) incluso tras la migración de `03_grants.sql` a `03_grants.sh` de `develop`, lo que de nuevo anulaba los `REVOKE`, y que el `GRANT UPDATE (ai_summary, ai_status)` que el worker de IA necesita se había perdido en esa migración. Resolución final: `docker-compose.yml` conecta `centinela-core` como `centinela_app` (hardcodeado, sin variable de entorno propia); `app/config.py::derive_app_db_password()` deriva su contraseña con `sha256("centinela_app:" + <password del superusuario>)` — la misma fórmula que ya aplicaba `03_grants.sh` para fijar esa contraseña, documentada en `secrets/README.md` pero hasta ahora no conectada en el código; y `03_grants.sh` recuperó el `GRANT UPDATE (ai_summary, ai_status)` junto con el `REVOKE DELETE, TRUNCATE` (sin `UPDATE`) en `event`, para no generar ambigüedad con el grant granular. No se añadió ningún secreto nuevo: reutiliza `postgres_password.txt`. `.env.example` ya no lista `CENTINELA_APP_USER`/`CENTINELA_APP_PASSWORD` — no hacían falta.
5. [x] Ejecutar manualmente el "momento de impacto" de la demo: editar a mano una fila de `audit_log` con `psql` y confirmar que `GET /api/audit/verify` detecta la rotura y señala el `id` correcto. — **Completado**: Se creó y ejecutó el script `scripts/demo_momento_impacto.py` y la suite de pruebas `tests/test_audit_verify.py` (3/3 pasadas). Al simular la modificación con `UPDATE audit_log SET payload = '...' WHERE id = 3`, `verify_chain()` y `/api/audit/verify` detectaron inmediatamente la rotura con `valid: false`, `broken_at_id: 3` y señalaron la discordancia entre `expected_hash` y `stored_hash`. Se documentó el comando `psql` exacto para la demo en vivo.
6. [x] Revisar `/api/public/indicadores` con datos reales del simulador: confirmar que `tendencia` y `severidad_promedio` se comportan bien con poco volumen de datos (la lógica actual compara contra los 30 días previos, lo cual con datos de una sola demo de unas horas puede dar `tendencia: "estable"` siempre — decidir si conviene un cálculo distinto para la demo en vivo). — **Completado**: Se creó el script de evaluación `scripts/test_indicadores_sim.py` y la suite `tests/test_public_api.py` (3/3 pasadas). Se confirmó que `severidad_promedio` calcula adecuadamente la distancia euclidiana discreta (`alta`/`critica`), y que `tendencia` cambia limpiamente de `"estable"` (0 eventos al arrancar) a `"al_alza"` (tras la ráfaga de ~300 ataques del simulador). La lógica actual es matemáticamente robusta y narrativamente ideal para la demo sin necesidad de alterar ventanas temporales.

---

## 4. Rafael — Frontend

> Antes a cargo de Luis en este documento; ver nota de "Roles" al inicio. El checklist no cambió, solo el dueño.

**Ya existe:**
- [x] Proyecto Vite + React + TS + Tailwind funcionando (`frontend/`), con modo oscuro por defecto.
- [x] `frontend/src/lib/types.ts` — tipos TypeScript del contrato de evento, calcados de `docs/SPRINT-1.md`.
- [x] `frontend/src/lib/api.ts` — cliente contra los endpoints reales (no mocks) y `subscribeToStream()` para SSE.
- [x] `frontend/src/pages/Soc.tsx` — 4 tarjetas KPI, tabla de eventos (componente `EventsTable`), conexión SSE en vivo, panel de IPs en cuarentena, botón de verificación de auditoría.
- [x] `frontend/src/pages/Observatorio.tsx` — vista pública en `/publico`, 5 indicadores y listado de alertas en lenguaje claro.
- [x] `frontend/src/components/KpiCard.tsx` y `EventsTable.tsx`.

**Pendiente (en orden):**
1. [ ] **Filtros de la tabla de eventos:** `Soc.tsx` hoy solo pide `limit=50` a `/api/events`. Falta la UI de filtros por severidad, IP y rango de fechas que exige el contrato (`api.events({ severity, src_ip, since, until })` ya soporta esos parámetros en `lib/api.ts`, solo falta conectarlos a controles de formulario).
2. [ ] **Mapa de calor categoría × severidad** (fase F3 de `docs/SPRINT-1.md`) — no existe todavía ningún componente para esto; es trabajo nuevo, no solo conectar una API existente.
3. [ ] Probar la conexión SSE contra el backend real una vez levantado (`docker compose up`) — se escribió contra el contrato pero no se verificó en un navegador real todavía.
4. [ ] Accesibilidad mínima (F4): contraste AA ya ayuda el tema oscuro de Tailwind configurado, pero falta revisar navegación por teclado (foco visible en el formulario de filtros, botón de "Verificar auditoría", enlaces del nav).
5. [ ] Pulido visual para proyector (F5): tipografía más grande en las tarjetas KPI, confirmar que nada requiera zoom ni scroll horizontal en una pantalla de proyección.
6. [ ] Revisar `VITE_API_BASE_URL` en `docker-compose.yml` (hoy apunta a `http://localhost:${API_PORT:-3000}`) — confirmar que funciona igual si la demo se corre en una laptop distinta a la que compiló la imagen.

---

## 5. José Estanga — Documentación

**Ya existe:**
- [x] `README.md` (raíz) — qué es, cómo se levanta, arquitectura, endpoints, estructura del repo.
- [x] `docs/SPEC.md` — los 8 bloques que exige el hackathón (problema con cifra, usuarios, propuesta de valor, alcance del MVP, criterios de aceptación, arquitectura, ética y privacidad, riesgos y supuestos).
- [x] `docs/SDD.md` — fusión de los SDD #23 y #40 adaptada a la arquitectura real del Sprint 1.
- [x] `docs/architecture.md` — diagrama de componentes, decisiones de diseño clave, mapeo de servicios Docker.
- [x] `docs/decisiones.md` — registro de decisiones de arquitectura con alternativas descartadas y el porqué.
- [x] `docs/declaracion-ia.md` — declaración obligatoria de uso de IA (tabla herramienta/uso/verificación humana).
- [x] `docs/SPRINT-1.md` — movido a `docs/` (plan original, no se reescribe).

**Pendiente (en orden):**
1. [ ] Revisar y, si hace falta, corregir el tono/contenido de los documentos ya generados — fueron redactados a partir de las decisiones ya tomadas por el equipo, pero José Estanga es quien los firma ante el jurado y debe sentirse dueño del contenido.
2. [ ] Capturas de pantalla reales de la demo (panel SOC, Observatorio, momento de "romper" la auditoría) una vez que el entorno esté levantado — hoy no existen, solo el texto.
3. [ ] Reporte de métricas del modelo ML: una vez que José Oropeza entrene el modelo, copiar/resumir `ml/model/nsl_kdd_rf.metrics.json` en un lugar visible para el jurado (puede ser una sección nueva en `docs/SDD.md` o un `docs/metricas.md` nuevo).
4. [ ] Guion del pitch de 3 minutos: `docs/SPRINT-1.md` sección 8 ya trae un guion minuto a minuto; falta cronometrarlo con el equipo (fase F6, 3 ensayos bajo 3:00).
5. [ ] Si se decide usar NotebookLM para preparar la defensa (ver sección 15 de los SDD originales en `docs/`), reunir como fuentes: este repo, `docs/SPEC.md`, `docs/SDD.md`, `README.md`, y las capturas/métricas una vez existan.

---

## 6. Rol de Rafael — resuelto

Confirmado el 2026-11-14 (ver "Roles" al inicio): Rafael pasa a encargarse del **Frontend** (sección 4). El trabajo de puente que se había bocetado aquí para este rol —sincronizar `rules.yaml` con `02_seed_attack.sql` y resolver conflictos entre ramas— lo cubrió **Luis**:

- [x] Puente entre Iván/José Oropeza para que las reglas (`rules.yaml`) y el seed SQL (`02_seed_attack.sql`) no se desincronicen — commit `12cea61` en `mli` (separación `centinela_app`/superusuario) y, el 2026-11-14, la resolución del merge `motor → develop` (catálogo de 20 reglas, orden `cmdi`/`traversal`, fila `CNT-IPS-QUARANTINE`).
- [ ] Ensayo y cronometraje del pitch con José Estanga en F6 — sigue pendiente, sin dueño fijo todavía.
