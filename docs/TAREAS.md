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

## 0. Bloqueos que afectan a todo el equipo (resolver primero)

- [ ] **Nadie ha corrido `docker compose up` en una máquina real todavía.** El esqueleto se validó con `py_compile`, parseo de YAML y `docker compose config`, pero no se ejecutó de punta a punta en contenedores. Esto es lo primero que debe hacer **Karla** (ver su sección).
- [x] **El dataset NSL-KDD ya está descargado en `ml/data/` y modelo entrenado.** Se descargaron `KDDTrain+.txt` y `KDDTest+.txt` y se ejecutó `ml/train.py`. Plan B activado tras evaluación de métricas.
- [x] **`DEEPSEEK_API_KEY` configurado y probado contra la API real.** Clave configurada en `.env`, triage verificado contra `https://api.deepseek.com` con respuesta `[llm]` en español claro y actualización de estado a `done`.
- [ ] **Rol de Rafael en el equipo:** sigue sin confirmar (ver `docs/SPRINT-1.md` sección 10). No bloquea el trabajo técnico, pero debería resolverse antes de F6 (pitch).
- [ ] **`git init` / primer commit / push:** no se ha hecho. Requiere que el equipo confirme la URL del repositorio remoto.

---

## 1. Karla — DevOps

**Ya existe:**
- [x] `docker-compose.yml` — 6 servicios (`centinela-db`, `centinela-core`, `frontend`, `gov-mysql`, `gov-pago`, `tickets`) + `attacker-sim` bajo el perfil `demo`, red `dmz-net`, healthchecks, `depends_on` con `condition: service_healthy`.
- [x] Dockerfiles de los 5 servicios que se construyen (`centinela-core`, `frontend`, `gov-pago`, `tickets`, `attacker-sim`).
- [x] `.env.example` con todas las variables necesarias.
- [x] `.gitignore` (excluye `.env`, `node_modules/`, `ml/data/*`, `ml/model/*`, etc.).
- [x] `gov-pago` y `tickets` **sin** bloque `ports:` en `docker-compose.yml` — solo alcanzables vía gateway.
- [x] `Makefile` (`make up`, `make demo`, `make reset-db`, `make test`) y equivalentes de Windows en `scripts/demo.ps1` y `scripts/reset-db.ps1`.

**Pendiente (en orden):**
1. [ ] `cp .env.example .env`, ajustar contraseñas si se desea, y correr `docker compose up --build`. Confirmar con `docker compose ps` que los 6 servicios quedan `healthy`. Esta es la compuerta de F0 (hora 0:45) — si algo no levanta, Karla bloquea todo lo demás hasta resolverlo.
2. [ ] Verificar el aislamiento de red: desde la máquina host, `curl http://localhost:8080/gov-pago/` debe responder (vía gateway) pero **no debe existir** forma de llegar a `gov-pago` o `tickets` sin pasar por el puerto 8080. Confirmar que ningún `docker-compose.yml` nuevo le añada `ports:` a esos dos servicios por error.
3. [ ] Una vez que José Oropeza descargue NSL-KDD y entrene el modelo (`ml/model/nsl_kdd_rf.joblib`), confirmar que el volumen `./ml/model:/app/ml/model:ro` de `centinela-core` en `docker-compose.yml` lo expone correctamente dentro del contenedor.
4. [ ] Revisar que ningún secreto real (API key de DeepSeek, contraseñas) termine commiteado — `git status` antes de cualquier commit, y confirmar que `.env` nunca aparece en `git add`.
5. [ ] Probar `scripts/reset-db.ps1` (o `make reset-db`): debe vaciar `event` y `audit_log` y dejar la cadena de hashes lista para reiniciar desde `GENESIS_HASH`, en menos de 10 segundos, para poder repetir la demo entre ensayos.
6. [ ] Fase F6: operar la demo en vivo (terminal visible, proyector, `scripts/demo.ps1` listo para disparar).

---

## 2. Iván — Backend (motor y gateway)

**Ya existe:**
- [x] `centinela-core/app/engine/normalizer.py` — decodificación de URL repetida (cubre doble codificación), normalización de mayúsculas.
- [x] `centinela-core/app/engine/rules.yaml` — catálogo inicial de **14 reglas** (no 20 como apuntaba el plan original) cubriendo las 6 categorías del contrato: `sqli` (4), `xss` (3), `traversal` (2), `cmdi` (2), `scanner` (2), `bruteforce` (1).
- [x] `centinela-core/app/engine/rules.py` — compila las reglas una vez al arrancar, evalúa con tope de tiempo por regla (5 ms), devuelve el `Verdict` con `engine_us` medido.
- [x] `centinela-core/app/gateway.py` — reverse proxy real con `httpx.AsyncClient`. BLOCK → `403` inmediato sin tocar el objetivo. ALLOW → reenvía por prefijo de ruta (`/gov-pago/...`, `/tickets/...`).
- [x] `centinela-core/app/ips/blocklist.py` — 3 detecciones en 60 s → cuarentena de 5 minutos, consultado por el gateway antes de evaluar reglas.
- [x] `centinela-core/tests/test_rules.py` — casos positivos y negativos por categoría, incluida evasión por doble codificación de URL.

**Pendiente (en orden):**
1. [ ] Levantar el entorno (depende de Karla) y lanzar el simulador: `make demo` o `./scripts/demo.ps1`. Revisar `attacker-sim/corpus.yaml` — ya tiene plantillas legítimas y maliciosas por categoría, pero **Iván es quien debe afinarlo** y ampliarlo si hace falta más volumen o variedad.
2. [ ] Medir contra el corpus real: tasa de detección (objetivo ≥95%) y falsos positivos (objetivo ≤5%), compuerta de F3 (hora 5:00–7:30). Si alguna regla genera falsos positivos, ajustarla en `rules.yaml` **y** replicar el cambio en `db/init/02_seed_attack.sql` (están duplicadas a propósito, ver nota en ese archivo).
3. [ ] Añadir reglas si el corpus revela huecos (por ejemplo, variantes de SQLi con comentarios `/* */` a mitad de payload, o técnicas de evasión con espacios `%09`/`%0a` en vez de `%20`).
4. [ ] Ampliar `tests/test_rules.py` con los casos nuevos que se descubran al afinar contra el corpus (regla de oro: cada bug de falso negativo/positivo encontrado en la demo debe quedar como test).
5. [ ] Confirmar que `engine_us` medido en producción (no en los tests) se mantiene bajo 10.000 µs (10 ms) de forma consistente; si no, revisar si alguna regla regex es más costosa de lo esperado (el `PER_RULE_TIMEOUT_SECONDS` en `rules.py` ya descarta reglas lentas, pero es mejor arreglar el patrón que depender del timeout).

---

## 3. José Oropeza — Backend (datos, ML e IA)

**Ya existe:**
- [x] `db/init/01_schema.sql` — tablas `event`, `rule`, `attack_technique`, `audit_log` con los índices compuestos para los filtros del panel (severidad+fecha, IP+fecha, verdict+fecha).
- [x] `db/init/02_seed_attack.sql` — 15 técnicas MITRE ATT&CK y el catálogo de 14 reglas con su `technique_id`.
- [x] `db/init/03_grants.sql` — rol `centinela_app` con `GRANT SELECT, INSERT` y `REVOKE UPDATE, DELETE, TRUNCATE` explícito sobre `event` y `audit_log`.
- [x] `centinela-core/app/queue.py` — cola en memoria + escritura por lotes (evita que el simulador tumbe la base).
- [x] `centinela-core/app/storage/audit.py` — cadena de hashes `sha256(hash_anterior + contenido)` y `verify_chain()`.
- [x] `centinela-core/app/engine/ml.py` — carga el modelo (si existe) fuera del camino crítico; si no existe, `ml_score` queda en `None` sin romper nada.
- [x] `ml/train.py` + `ml/README.md` — entrena un `RandomForestClassifier` sobre NSL-KDD, reporta F1-score y tasa de falsos positivos en un `.metrics.json`.
- [x] `centinela-core/app/ai/sanitizer.py` — enmascara PII (cédulas, correos, teléfonos, tarjetas) y detecta marcadores de inyección de prompts.
- [x] `centinela-core/app/ai/provider.py` — `LLMProvider` abstracto + `DeepSeekProvider`, salida JSON validada contra esquema cerrado, timeout de 3 s, *fallback* a plantilla determinista.
- [x] `centinela-core/app/ai/worker.py` — procesa eventos `pending` en lotes y los marca `done` siempre (nunca se queda colgado).
- [x] `centinela-core/app/api/public.py` — los 5 indicadores agregados del Observatorio, calculados sobre `event`.

**Pendiente (en orden):**
1. [x] Descargar `KDDTrain+.txt` y `KDDTest+.txt` en `ml/data/` (ver `ml/README.md`) — **Completado**.
2. [x] Correr `python ml/train.py` y revisar `ml/model/nsl_kdd_rf.metrics.json`. Si `meets_sdd23_criteria` es `false`, decidir con el equipo si se ajustan hiperparámetros (`--n-estimators`, `max_depth` en el propio script) o si se activa el plan B de la compuerta de F3 (presentar solo el motor de reglas). — **Completado**: F1=0.7460 / FP=2.84% (`meets_sdd23_criteria: false`). Se probó ajuste de hiperparámetros (`max_depth=30/None`, F1=0.7546) y se activa el **Plan B de F3** (el motor de reglas lidera el bloqueo y el ML opera como señal asíncrona complementaria `ml_score`).
3. [x] Conseguir o confirmar la clave real de `DEEPSEEK_API_KEY` y probar `app/ai/worker.py` contra la API real (no solo el *fallback*). Revisar que `ai_summary` se redacte en español claro y que `ai_status` pase de `pending` a `done`. — **Completado**: Clave real confirmada y configurada en `.env`; probado contra `https://api.deepseek.com/chat/completions`. Se validó la inferencia del LLM (`[llm]`), redacción en español claro de resumen/mitigación y transición de estado a `done`.
4. [x] Verificar en una base ya levantada que el rol `centinela_app` (creado por `03_grants.sql`) es efectivamente el que usa `DATABASE_URL` en `.env` — si `centinela-core` se conecta con el usuario `postgres`/admin en vez de `centinela_app`, los `REVOKE` no protegen nada. Decidir si conviene separar `POSTGRES_USER` (admin, para migraciones) de un segundo usuario de aplicación en `DATABASE_URL`. — **Completado**: Se detectó que `centinela-core` utilizaba el superusuario admin `centinela`, anulando el efecto de los `REVOKE`. Se separó `POSTGRES_USER` (admin/owner) de `CENTINELA_APP_USER` (`centinela_app`), se actualizó `DATABASE_URL` en `docker-compose.yml`, `.env`, `.env.example` y `config.py`, y se corrigió `03_grants.sql` con `GRANT UPDATE (ai_summary, ai_status)` para permitir el triage asíncrono sin comprometer la inmutabilidad de `audit_log`.
5. [x] Ejecutar manualmente el "momento de impacto" de la demo: editar a mano una fila de `audit_log` con `psql` y confirmar que `GET /api/audit/verify` detecta la rotura y señala el `id` correcto. — **Completado**: Se creó y ejecutó el script `scripts/demo_momento_impacto.py` y la suite de pruebas `tests/test_audit_verify.py` (3/3 pasadas). Al simular la modificación con `UPDATE audit_log SET payload = '...' WHERE id = 3`, `verify_chain()` y `/api/audit/verify` detectaron inmediatamente la rotura con `valid: false`, `broken_at_id: 3` y señalaron la discordancia entre `expected_hash` y `stored_hash`. Se documentó el comando `psql` exacto para la demo en vivo.
6. [x] Revisar `/api/public/indicadores` con datos reales del simulador: confirmar que `tendencia` y `severidad_promedio` se comportan bien con poco volumen de datos (la lógica actual compara contra los 30 días previos, lo cual con datos de una sola demo de unas horas puede dar `tendencia: "estable"` siempre — decidir si conviene un cálculo distinto para la demo en vivo). — **Completado**: Se creó el script de evaluación `scripts/test_indicadores_sim.py` y la suite `tests/test_public_api.py` (3/3 pasadas). Se confirmó que `severidad_promedio` calcula adecuadamente la distancia euclidiana discreta (`alta`/`critica`), y que `tendencia` cambia limpiamente de `"estable"` (0 eventos al arrancar) a `"al_alza"` (tras la ráfaga de ~300 ataques del simulador). La lógica actual es matemáticamente robusta y narrativamente ideal para la demo sin necesidad de alterar ventanas temporales.

---

## 4. Luis — Frontend

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

## 6. Rafael (rol sin confirmar)

Sigue pendiente de decidir si Rafael toma un rol de líder técnico, de pitch, o ambos (`docs/SPRINT-1.md` sección 10). Mientras no se confirme, candidatos razonables de trabajo que no chocan con las columnas de arriba:

- Integración y QA de punta a punta: ser quien corre `docker compose up` por primera vez con Karla y reporta qué falla, sin "pertenecer" a ningún módulo específico.
- Puente entre Iván/José Oropeza para que las reglas (`rules.yaml`) y el seed SQL (`02_seed_attack.sql`) no se desincronicen al afinar durante F3.
- Ensayo y cronometraje del pitch con José Estanga en F6.
