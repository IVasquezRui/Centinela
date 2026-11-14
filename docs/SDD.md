# SDD — CENTINELA (unificado)

> Fusiona `SDD — IDSIPS para redes gubernamentales.md` (proyecto #23, biblioteca del hackathon) y
> `SDD — Observatorio nacional de ciberseguridad.md` (proyecto #40), adaptados a la arquitectura real
> del Sprint 1 (Docker Compose local, ver `docs/decisiones.md`). Los documentos originales de ambos
> proyectos se conservan sin modificar en la raíz del repositorio como fuente histórica.

## 1. Problema

Las redes de ministerios y gobernaciones de Venezuela son blanco constante de intrusiones, escaneos y exfiltración de información, sin visibilidad en tiempo real del tráfico malicioso (SDD #23). En paralelo, no existe una fuente pública y consolidada del panorama nacional de amenazas, por lo que decisores, medios y ciudadanía no pueden dimensionar el riesgo ni priorizar acciones preventivas (SDD #40). CENTINELA resuelve ambos problemas con un solo flujo de datos: el motor que protege a un ente es también el que alimenta, agregado y anonimizado, el panel nacional.

## 2. Objetivos

- Detectar en línea tráfico malicioso HTTP (SQLi, XSS, path traversal, command injection, escaneo, fuerza bruta) con un motor híbrido de reglas deterministas + ML.
- Bloquear y poner en cuarentena automáticamente IPs maliciosas recurrentes (modo IPS).
- Persistir cada detección de forma auditable e inmutable, con severidad, técnica MITRE ATT&CK asociada y confianza del modelo.
- Publicar, sin intervención manual, un panel ciudadano con al menos 5 indicadores agregados del panorama de amenazas.
- Redactar el análisis de cada alerta con un copiloto de IA que nunca decide, solo explica.

## 3. Requisitos funcionales (RF)

**Motor y gateway (origen SDD #23, adaptado a capa 7 / HTTP):**
- RF-01: Normalizar cada petición HTTP entrante (decodificación de URL, resolución de doble codificación, normalización de mayúsculas) antes de evaluarla.
- RF-02: Evaluar la petición normalizada contra un catálogo de reglas regex precompiladas y devolver un veredicto `block`/`allow` en menos de 10 ms de CPU del motor.
- RF-03: Reenviar al objetivo únicamente las peticiones con veredicto `allow`; las bloqueadas reciben `403` sin tocar el objetivo.
- RF-04: Añadir una puntuación de un modelo de ML (RandomForest entrenado sobre NSL-KDD) a cada evento, fuera del camino crítico de bloqueo.
- RF-05: Poner en cuarentena automáticamente una IP tras 3 detecciones de bloqueo en una ventana de 60 segundos, durante 5 minutos.
- RF-06: Persistir cada evento (timestamp, IP origen, ruta, veredicto, regla disparada, categoría, severidad, técnica ATT&CK, confianza del modelo) para auditoría y reportes.

**Auditoría:**
- RF-07: Encadenar cada entrada de auditoría con un hash `sha256(hash_anterior + contenido)` y exponer un endpoint que verifique la integridad de toda la cadena.
- RF-08: Revocar a nivel de base de datos los permisos `UPDATE`/`DELETE` del rol de la aplicación sobre las tablas de eventos y auditoría.

**Copiloto de IA (triage, nunca bloqueo):**
- RF-09: Redactar un resumen en español claro y una mitigación sugerida para cada evento bloqueado, con salida JSON validada contra un esquema cerrado.
- RF-10: Enmascarar PII y neutralizar intentos de inyección de prompts embebidos en el payload antes de enviarlo al LLM.
- RF-11: Si el proveedor de IA falla o excede 3 segundos, sustituir la redacción por una plantilla determinista sin interrumpir el flujo.

**Observatorio público (origen SDD #40):**
- RF-12: Publicar un panel con al menos 5 indicadores agregados (incidentes recientes, amenaza predominante, sector más afectado, severidad promedio, tendencia), calculados automáticamente sobre los eventos del motor.
- RF-13: Publicar una vista ciudadana sin autenticación, en lenguaje claro, con alertas activas y recomendaciones básicas.
- RF-14: No exponer en ningún endpoint público IP origen, payload capturado ni ningún identificador directo de una víctima o ente concreto.

## 4. Requisitos no funcionales (RNF)

- RNF-01 (Seguridad/privacidad): datos 100% sintéticos en los objetivos de laboratorio; PII enmascarada antes de llegar al LLM; sin datos personales publicados en el Observatorio; `.env` fuera de git.
- RNF-02 (Rendimiento): veredicto del motor de reglas en <10 ms de CPU por petición; triage de IA con timeout de 3 s.
- RNF-03 (Disponibilidad): la plataforma permanece operativa (bloqueo y auditoría) aunque el proveedor de IA o el modelo ML fallen por completo.
- RNF-04 (Usabilidad/accesibilidad): panel SOC y Observatorio en español, contraste adecuado para proyección, navegación por teclado mínima (WCAG 2.1 AA completo queda para Sprint 2+).
- RNF-05 (Aislamiento): los objetivos vulnerables no publican puertos al host; solo son alcanzables a través del gateway, en una red Docker sin salida a internet.

## 5. Historias de usuario

- Como analista de seguridad de un ente público, quiero ver alertas clasificadas por severidad en tiempo real, para priorizar la respuesta ante incidentes.
- Como responsable de TI del ente, quiero que el sistema bloquee automáticamente IPs maliciosas recurrentes, para contener ataques sin intervención manual inmediata.
- Como responsable de TI, quiero poder verificar en cualquier momento que la bitácora de auditoría no ha sido alterada, para sostener un reporte ante una auditoría externa.
- Como ciudadano, quiero consultar el panorama nacional de amenazas en lenguaje claro sin necesidad de registrarme, para entender el riesgo y protegerme de fraudes.
- Como decisor de gobernanza del riesgo ciber, quiero ver indicadores agregados y su tendencia, para priorizar políticas públicas de ciberseguridad.

## 6. Criterios de aceptación

Ver `docs/SPEC.md` sección 5 (criterios de aceptación formales, formato Given/When/Then).

## 7. Stack tecnológico

Python 3.11 + FastAPI (gateway y API), React + TypeScript + Vite + Tailwind (frontend), PostgreSQL 16 (persistencia), scikit-learn/RandomForest sobre NSL-KDD (ML), DeepSeek API vía interfaz `LLMProvider` intercambiable (triage), Docker Compose (orquestación local). Decisión completa y alternativas descartadas en `docs/decisiones.md`.

## 8. Definition of Done (Sprint 1)

- [ ] `docker compose up` deja los 6 servicios principales en estado *healthy*.
- [ ] Un SQLi contra `gov-pago` recibe `403` y no llega al contenedor objetivo.
- [ ] Un corpus de 1.000 peticiones mixtas mide detección ≥95% y falsos positivos ≤5% (o, si el ML no converge, el motor de reglas solo con sus métricas reales).
- [ ] `/api/audit/verify` detecta una alteración manual de un registro de auditoría.
- [ ] El panel SOC muestra eventos en vivo vía SSE y el Observatorio público muestra los 5 indicadores agregados.
- [ ] `SPEC.md`, este `SDD.md`, `decisiones.md` y la declaración de uso de IA existen y están completos.
