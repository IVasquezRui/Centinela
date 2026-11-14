# Cuaderno de Progreso — Rol: Iván (Backend: Motor y Gateway)
## Fase 1: Contratos (0:45 – 2:00)

> **Proyecto:** CENTINELA · Hackathon UNETI IA 2026  
> **Responsable:** Iván (Backend — Motor de Detección y Gateway Inline)  
> **Metodología:** Human-in-the-loop (Confirmación explícita previa a cada acción)  
> **Compuerta de Salida F1:** Contratos de normalización y reglas deterministas (~20 reglas) compiladas, sincronizadas con base de datos y validadas con suite de pruebas unitarias sin regresiones.

---

## 1. Base de Conocimiento y Análisis del Sistema

Tras la inspección profunda del código base y la documentación del proyecto (`SPRINT-1.md`, `TAREAS.md`, `SPEC.md`, `architecture.md`, `decisiones.md` y archivos de `centinela-core`):

### 1.1. Principios Arquitectónicos Inmutables
1. **La regla de oro del motor:** El motor determinista de reglas (`RuleEngine`) es la **única entidad que decide un bloqueo (`BLOCK`)**. Ni el modelo de Machine Learning (`ml_score`), ni el copiloto LLM (`DeepSeek`) intervienen en la decisión de denegación: operan en segundo plano, enriqueciendo el evento una vez tomado el veredicto.
2. **Latencia ultra baja:** El camino crítico de inspección en el gateway debe resolverse en menos de 10 ms (`engine_us < 10000`). Cada regla tiene un timeout estricto de 5 ms (`PER_RULE_TIMEOUT_SECONDS = 0.005`) para mitigar ataques de ReDoS.
3. **Aislamiento perimetral:** Los contenedores objetivo (`gov-pago` y `tickets`) carecen de puertos expuestos al host. El único punto de entrada es el Gateway inline (puerto 8080).
4. **Contrato de datos de evento:**
   - Categorías permitidas: `sqli`, `xss`, `traversal`, `cmdi`, `scanner`, `bruteforce`.
   - Severidades permitidas: `baja`, `media`, `alta`, `critica`.
   - Mapeo MITRE ATT&CK: Obligatorio para cada regla (ej. `T1190`, `T1059.007`, `T1083`, `T1059`, `T1595`, `T1110`).

### 1.2. Diagnóstico del Estado Actual (Baseline Fase 1)
- `centinela-core/app/engine/normalizer.py`: Implementado con decodificación iterativa `_decode_fully(max_passes=3)` y estructura `NormalizedRequest`. Debe verificarse frente a evasiones avanzadas (ej. null bytes `%00`, normalización de rutas y espacios).
- `centinela-core/app/engine/rules.yaml`: Contiene únicamente **14 reglas** iniciales. El plan de Fase 1 exige expandirlo a **~20 reglas deterministas** para asegurar cobertura frente al corpus y evitar falsos negativos en la demo.
- `db/init/02_seed_attack.sql`: Contiene la copia de las 14 reglas iniciales. Si no se sincroniza con `rules.yaml`, las consultas y joins con `attack_technique` y la persistencia en `rule` fallarán.
- `centinela-core/tests/test_rules.py`: Dispone de 8 pruebas elementales. Carece de cobertura para `scanner`, `bruteforce`, técnicas avanzadas de inyección de comandos, inclusión de esquemas en path traversal y validación exhaustiva de falsos positivos.

---

## 2. Plan Operativo de Fase 1 (Metodología Human-In-The-Loop)

Cada una de las siguientes tareas requiere **confirmación explícita del usuario** antes de su ejecución:

| ID | Tarea | Descripción Detallada | Estado Pre-Actuación | Estado Post-Actuación |
|---|---|---|---|---|
| **T-01** | Ampliación del Catálogo de Reglas (`rules.yaml`) | Expandir de 14 a 20 reglas deterministas: añadir SQLi DDL/DML, XSS DOM tags, Traversal wrappers, CMDi pipes, Scanner backup probes, Bruteforce dictionary. | **AUTORIZADO** | **COMPLETADO** (20 reglas en `rules.yaml`) |
| **T-02** | Sincronización de Base de Datos (`02_seed_attack.sql`) | Reflejar las nuevas reglas y técnicas ATT&CK en el script seed SQL para preservar integridad referencial de claves foráneas. | **AUTORIZADO** | **COMPLETADO** (20 reglas en `02_seed_attack.sql`) |
| **T-03** | Auditoría y Refuerzo de `normalizer.py` | Validar y proteger el normalizador contra caracteres de terminación nula (`%00`) y unificación de separadores de ruta. | **AUTORIZADO** | **COMPLETADO** (Probado y sanitizado) |
| **T-04** | Ampliación de Suite de Pruebas (`test_rules.py`) | Añadir casos positivos para las 20 reglas, casos negativos (tráfico legítimo libre de falsos positivos) y pruebas de evasión por dobles codificaciones. | **AUTORIZADO** | **COMPLETADO** (Suite completa de 20 reglas) |
| **T-05** | Ejecución y Verificación de Pruebas Unitarias | Ejecutar pytest/suite en entorno local y verificar tasa de acierto del 100% y tiempos de ejecución dentro de los umbrales (<10ms). | **AUTORIZADO** | **COMPLETADO** (43/43 tests superados en 0.13s) |
| **T-06** | Generación de Entregable de Cierre (`Fase1-Ivan/`) | Crear el directorio `Fase1-Ivan/` y redactar el informe final consolidado de la Fase 1 con métricas, evidencias y compuerta de salida aprobada. | **AUTORIZADO** | **COMPLETADO** (Informe en `Fase1-Ivan/resultado-fase1.md`) |

---

## 2.1. Catálogo Completo de las 20 Reglas Declaradas (Pre y Post Trabajo)

A continuación se detalla la especificación de las 20 reglas deterministas que regirán el motor de detección:

| ID Regla | Categoría | Severidad | ATT&CK | Descripción Técnica | Estado Pre-Trabajo | Estado Post-Trabajo |
|---|---|---|---|---|---|---|
| `CNT-SQLI-001` | sqli | critica | T1190 | Tautología clásica (`' OR '1'='1`) | Existente (v1) | Conservada / Validada |
| `CNT-SQLI-002` | sqli | critica | T1190 | Inyección `UNION SELECT` para exfiltración | Existente (v1) | Conservada / Validada |
| `CNT-SQLI-003` | sqli | alta | T1190 | Comentario SQL para truncar consulta (`--`, `#`, `/* */`) | Existente (v1) | Conservada / Validada |
| `CNT-SQLI-004` | sqli | alta | T1190 | Inyección a ciegas por retardo (`SLEEP/BENCHMARK`) | Existente (v1) | Conservada / Validada |
| `CNT-SQLI-005` | sqli | alta | T1190 | Sentencias DDL/DML destructivas (`DROP`, `DELETE`, `UPDATE`) | **Nueva (T-01)** | Implementada en `rules.yaml` |
| `CNT-XSS-001` | xss | alta | T1059.007 | Inyección directa de etiquetas `<script>` | Existente (v1) | Conservada / Validada |
| `CNT-XSS-002` | xss | media | T1059.007 | Atributos/Manejadores inline (`onerror=`, `onload=`, etc.) | Existente (v1) | Conservada / Validada |
| `CNT-XSS-003` | xss | media | T1059.007 | Esquema de ejecución `javascript:` | Existente (v1) | Conservada / Validada |
| `CNT-XSS-004` | xss | alta | T1059.007 | Elementos DOM para inyección (`<iframe>`, `<svg>`, etc.) | **Nueva (T-01)** | Implementada en `rules.yaml` |
| `CNT-TRAVERSAL-001` | traversal | critica | T1083 | Secuencia `../` o variantes codificadas (`..%2f`) | Existente (v1) | Conservada / Validada |
| `CNT-TRAVERSAL-002` | traversal | alta | T1083 | Lectura directa de archivos (`/etc/passwd`, `win.ini`) | Existente (v1) | Conservada / Validada |
| `CNT-TRAVERSAL-003` | traversal | alta | T1083 | Inclusión mediante esquemas de wrapper (`php://`, `file://`) | **Nueva (T-01)** | Implementada en `rules.yaml` |
| `CNT-CMDI-001` | cmdi | critica | T1059 | Concatenación de comandos con binarios (`cat`, `ls`, `id`) | Existente (v1) | Conservada / Validada |
| `CNT-CMDI-002` | cmdi | alta | T1059 | Sustitución de comandos con backticks o `$()` | Existente (v1) | Conservada / Validada |
| `CNT-CMDI-003` | cmdi | critica | T1059 | Pipes directos a shell o redirección de red (`/dev/tcp`) | **Nueva (T-01)** | Implementada en `rules.yaml` |
| `CNT-SCANNER-001` | scanner | baja | T1595 | User-Agent de escáneres (`sqlmap`, `nikto`, `nessus`) | Existente (v1) | Conservada / Validada |
| `CNT-SCANNER-002` | scanner | media | T1595.002 | Sondeo de rutas de admin/versiones (`/.git/`, `/.env`) | Existente (v1) | Conservada / Validada |
| `CNT-SCANNER-003` | scanner | media | T1595.002 | Sondeo de respaldos y volcados (`.bak`, `.sql`, `.zip`) | **Nueva (T-01)** | Implementada en `rules.yaml` |
| `CNT-BRUTEFORCE-001`| bruteforce | media | T1110 | Credenciales por defecto en login (`admin:admin`, etc.) | Existente (v1) | Conservada / Validada |
| `CNT-BRUTEFORCE-002`| bruteforce | media | T1110 | Patrón de diccionario común en parámetros de clave | **Nueva (T-01)** | Implementada en `rules.yaml` |

---

## 3. Bitácora de Ejecución y Evidencias (Post-Actuación)

- **Control de Versiones (Git):** Creada la rama secundaria `motor` (`git checkout -b motor`) y subido exitosamente el 100% del estado actual del repositorio al remoto (`origin/motor`) en GitHub: `https://github.com/IVasquezRui/Centinela/tree/motor`. Todos los entregables, contratos de 20 reglas deterministas, suite de pruebas unitarias y reportes están sincronizados.
- **T-01 [COMPLETADO]:** Catálogo `centinela-core/app/engine/rules.yaml` ampliado exitosamente a **20 reglas deterministas**. Se añadieron 6 nuevas reglas cubriendo vectores críticos (`CNT-SQLI-005`, `CNT-XSS-004`, `CNT-TRAVERSAL-003`, `CNT-CMDI-003`, `CNT-SCANNER-003`, `CNT-BRUTEFORCE-002`) con tipado y esquemas contractuales estrictos.
- **T-02 [COMPLETADO]:** Archivo [`db/init/02_seed_attack.sql`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/db/init/02_seed_attack.sql) sincronizado con las 20 reglas deterministas y sus mapeos de técnicas MITRE ATT&CK (`T1190`, `T1059.007`, `T1083`, `T1059`, `T1595.002`, `T1110`). La integridad de claves foráneas con `rule` y `attack_technique` está 100% garantizada.
- **T-03 [COMPLETADO]:** Archivo [`centinela-core/app/engine/normalizer.py`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/centinela-core/app/engine/normalizer.py) robustecido: se agregó neutralización de terminadores nulos (`\x00`/`%00`) para evitar truncamiento malicioso en aplicaciones PHP (`gov-pago`) y canonicidad de separadores de ruta (`\` a `/`). Comprobado mediante script de ejecución.
- **T-04 [COMPLETADO]:** Archivo [`centinela-core/tests/test_rules.py`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/centinela-core/tests/test_rules.py) completamente extendido: cubre las 20 reglas deterministas, las 6 categorías del contrato, pruebas de evasión avanzada (doble URL-encoding, terminadores nulos, backslashes de Windows) y matriz de tráfico legítimo (cero falsos positivos).
- **T-05 [COMPLETADO]:** Suite completa de pruebas ejecutada con `pytest`: **43 pruebas ejecutadas, 43 pasadas exitosamente (100% efectividad) en 0.13 segundos**. Se verificó que todas las reglas respondan en microsegundos (`engine_us < 1.000 µs`), cumpliendo con holgura el SLA contractual de latencia (< 10.000 µs) y 0% falsos positivos.
- **T-06 [COMPLETADO]:** Creado el directorio [`Fase1-Ivan/`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/Fase1-Ivan) y generado el documento de cierre formal [`Fase1-Ivan/resultado-fase1.md`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/Fase1-Ivan/resultado-fase1.md), consolidando el 100% de los entregables técnicos, métricas de rendimiento, trazabilidad de commits y dictamen de aprobación de la compuerta de salida de la Fase 1. Lista la transición para la Fase 2 (Núcleo).

---

## 4. Fase 2: Núcleo (2:00 – 5:00) — Arquitectura y Plan Operativo

### 4.1. Fundamentos Técnicos de la Fase 2
1. **Desacoplamiento de I/O en Camino Crítico:** El gateway inline procesa peticiones HTTP y toma veredictos (`BLOCK`/`ALLOW`) en menos de 10 ms. Para no saturar conexiones de base de datos durante ráfagas de 1.000+ peticiones, la persistencia se delega a una cola en memoria asíncrona (`asyncio.Queue`) con descarga en lotes (batching: 50 eventos o 0.5 segundos).
2. **Inmutabilidad WORM y Criptográfica:**
   - Cadena de hashes en `audit_log`: $\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{PayloadCanónico}_n)$ partiendo de `GENESIS_HASH` (64 ceros).
   - Control de acceso de motor en PostgreSQL: Revocación explícita de `UPDATE`/`DELETE`/`TRUNCATE` para el rol de aplicación (`centinela_app`) sobre tablas de auditoría e incidentes, acotando `UPDATE` exclusivamente a las columnas de enriquecimiento de IA (`ai_summary`, `ai_status`).
3. **Resiliencia Operativa:** Manejo de savepoints anidados (`session.begin_nested()`) para evitar que un fallo individual descarte un lote completo, y reencolado con tope (`MAX_REQUEUE = 10_000`) con pausa preventiva en caso de caída temporal de la base de datos.

### 4.2. Plan Operativo de Fase 2 (Metodología Human-In-The-Loop)

Cada una de las siguientes tareas requiere **confirmación explícita del usuario** antes de su ejecución:

| ID | Tarea | Descripción Detallada | Estado Pre-Actuación | Estado Post-Actuación |
|---|---|---|---|---|
| **T-07** | Creación y Estandarización de `03_grants.sql` | Desarrollar el archivo SQL estándar `db/init/03_grants.sql` compatible con PostgreSQL nativo/Windows y alineado con `03_grants.sh`, garantizando la creación del rol `centinela_app` y la inmutabilidad de `event` y `audit_log`. | **AUTORIZADO** | **COMPLETADO** (Creado `03_grants.sql` y sincronizado en git) |
| **T-08** | Auditoría y Pruebas Unitarias de `audit.py` | Implementar suite de pruebas automatizadas para la cadena criptográfica: serialización canónica, encadenamiento secuencial y verificación forense de eslabón roto (`broken_at_id`). | **AUTORIZADO** | **COMPLETADO** (7/7 tests aprobados en 0.75s) |
| **T-09** | Validación y Pruebas de Estrés de `queue.py` | Validar el comportamiento del drenador por lotes: descarga por tamaño (50) o tiempo (0.5s), resiliencia de savepoints anidados ante violaciones de FK y contrapresión de reencolado. | **AUTORIZADO** | **COMPLETADO** (4/4 tests aprobados en 1.70s) |
| **T-10** | Verificación de Integración Gateway $\rightarrow$ Cola $\rightarrow$ Auditoría | Validar que la invocación desde `gateway.py` encole `PendingEvent` con latencia `< 10 ms` (`engine_us`) y que el evento se persista atómicamente junto a su registro en `audit_log`. | **AUTORIZADO** | **COMPLETADO** (6/6 tests de integración pasados en 4.09s) |
| **T-11** | Cierre Formal de Fase 2 en `Fase2-Ivan/` y Git Push | Crear el directorio `Fase2-Ivan/`, redactar el informe de cierre de la Fase 2, consolidar commits y sincronizar con la rama remota `origin/motor`. | **AUTORIZADO** | **COMPLETADO** (Informe en `Fase2-Ivan/resultado-fase2.md`) |

---

## 4.3. Bitácora de Ejecución de Fase 2 (Post-Actuación)

*(Esta sección se irá actualizando dinámicamente a medida que el usuario autorice y se complete cada tarea)*

- **T-07 [COMPLETADO]:** Creado [`db/init/03_grants.sql`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/db/init/03_grants.sql) como estándar SQL puro. Se configuró el rol `centinela_app`, los permisos `SELECT, INSERT` para eventos y auditoría, el `UPDATE` restringido por columna únicamente a `(ai_summary, ai_status)` para el triage de IA, y la revocación explícita de `UPDATE, DELETE, TRUNCATE` en `audit_log` y `event` para garantizar inmutabilidad WORM. Commit `3f34e65` subido a `origin/motor`.
- **T-08 [COMPLETADO]:** Creado [`centinela-core/tests/test_audit.py`](file:///c:/Users/USUARIO/Desktop/Hackathon/Centinela/centinela-core/tests/test_audit.py) con 7 pruebas automatizadas (todas superadas al 100%): serialización canónica JSON determinista, efecto avalancha SHA-256, encadenamiento ordenado con `GENESIS_HASH`, y detección forense de eslabón roto (`broken_at_id`) ante adulteración de payloads, alteración de hashes previos o borrado de filas intermedias. Commit `2d6ddb1` sincronizado en `origin/motor`.
- **T-09 [COMPLETADO]:** Creado [`centinela-core/tests/test_queue.py`](file:///c:/Users/USUARIO/Desktop/Hackathon/Centinela/centinela-core/tests/test_queue.py) con 4 pruebas automatizadas (todas superadas al 100% en 1.70s): (1) `test_batch_drain_by_size` — verifica que el drenador vacía la cola al alcanzar `batch_size=2`; (2) `test_batch_drain_by_timer` — verifica que el lote se descarga por `flush_interval=0.1s` sin esperar a llenarse; (3) `test_sse_broadcast_after_commit` — verifica la difusión SSE post-commit sobre `event_bus`; (4) `test_queue_resilience_savepoint` — verifica aislamiento de savepoints anidados ante violación de FK (evento con `rule_id` inexistente se descarta sin abortar el lote completo). Commit `7a0b1fc` sincronizado en `origin/motor`.
- **T-10 [COMPLETADO]:** Creado y ejecutado [`centinela-core/tests/test_integration.py`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/centinela-core/tests/test_integration.py) con 6 pruebas automatizadas (100% superadas en 4.09s): verificación de latencia en el camino crítico dentro del SLA contractual (`engine_us < 10 000 µs`), encolado no bloqueante (`elapsed_ms < 5 ms`), asignación de `ai_status='done'` para tráfico legítimo (`allow`) y `ai_status='pending'` para incidentes bloqueados (`block`), propagación fidedigna de métricas y validación de la cadena de hashes (`verify_chain`) en flujos de tráfico mixto.
- **T-11 [COMPLETADO]:** Creado el directorio [`Fase2-Ivan/`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/Fase2-Ivan) y generado el informe de cierre formal [`Fase2-Ivan/resultado-fase2.md`](file:///c:/Users/Fonacit/Documents/GitHub/Centinela/Fase2-Ivan/resultado-fase2.md). La suite completa de 69 pruebas del proyecto se ejecutó con 100% de éxito en 4.81s. La compuerta de salida de la Fase 2 queda formalmente **APROBADA**.
