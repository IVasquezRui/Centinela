# SPEC — CENTINELA

> Hackathon UNETI IA 2026 · Eje Ciberseguridad · Metodología Specification-Driven Development (SDD)
> Unificación de los proyectos de biblioteca #23 (IDS/IPS para redes gubernamentales) y #40 (Observatorio nacional de ciberseguridad).

## 1. Problema (con cifra)

Las redes de ministerios y gobernaciones de Venezuela sufren intrusiones, escaneos y exfiltración de forma constante, y sus equipos de TI carecen de visibilidad en tiempo real: según el SDD #23 que origina este proyecto, el objetivo mínimo aceptable de un sistema de detección en este dominio es **detectar al menos el 90% de las intrusiones de un corpus de referencia con una tasa de falsos positivos menor al 5%** — el estado actual, sin automatización, deja ese 90%+ fuera del radar de un analista humano revisando logs manualmente. Al mismo tiempo, no existe una fuente pública consolidada del panorama nacional de amenazas: decisores y ciudadanía toman decisiones a ciegas frente a phishing, ransomware y fraude digital.

## 2. Usuarios

- **Analista de seguridad de un ente público (SOC):** necesita ver alertas priorizadas por severidad y actuar rápido.
- **Responsable de TI / decisor del ente:** necesita evidencia auditable y métricas para justificar inversión en seguridad.
- **Ciudadanía y decisores de gobernanza del riesgo ciber:** necesitan un panorama nacional de amenazas en lenguaje claro, sin tecnicismos ni autenticación.

## 3. Propuesta de valor

CENTINELA es una sola plataforma con dos caras conectadas por un único flujo de datos:

> *"CENTINELA detecta, bloquea y audita en el ente; agrega, anonimiza y publica en el país."*

- **Cara operativa (SOC):** motor híbrido (reglas deterministas + ML) que bloquea en línea y audita con una cadena de hashes inmutable.
- **Cara pública (Observatorio):** cada ataque bloqueado sube, agregado y despersonalizado, al panel nacional — sin captura manual.

El LLM (DeepSeek) solo redacta el análisis de una alerta ya bloqueada por el motor determinista; **nunca tiene autoridad para decidir un bloqueo**.

## 4. Alcance del MVP (Sprint 1, 12 horas)

**Incluido:**
- Gateway inline (reverse proxy) con motor de reglas regex + modelo ML ligero (RandomForest sobre NSL-KDD).
- Modo IPS: cuarentena automática de IPs tras 3 detecciones en 60 segundos.
- Persistencia auditable con cadena de hashes (`sha256` encadenado) y permisos de base de datos que revocan `UPDATE`/`DELETE` al rol de la aplicación.
- Triage de alertas redactado por DeepSeek, con saneamiento de PII, timeout de 3 s y plantilla de respaldo determinista.
- Panel SOC en tiempo real (SSE) y vista pública del Observatorio con 5 indicadores agregados.
- Dos aplicaciones de laboratorio propias e intencionalmente vulnerables (`gov-pago` en PHP, `tickets` en Node.js), aisladas, sin puertos publicados, con datos 100% sintéticos — el mismo patrón que DVWA, OWASP Juice Shop o WebGoat.
- Simulador de tráfico mixto (legítimo + malicioso) para la demo.

**Explícitamente fuera de alcance (Sprint 2+):** RBAC y cifrado de registros, exportación PDF/CSV del Observatorio, ingesta por API externa, WCAG 2.1 AA completo, despliegue multi-sede, Kubernetes/Kafka/Redis, agente multiplataforma de auditoría.

## 5. Criterios de aceptación

- Dado un SQLi contra `gov-pago`, cuando la petición llega al gateway, entonces recibe `403` y **no** llega al contenedor objetivo, en menos de 10 ms de CPU del motor.
- Dado un corpus de 1.000 peticiones mixtas, cuando se mide el resultado, entonces la tasa de detección es ≥95% y los falsos positivos ≤5% (compuerta de F3).
- Dada una IP con 3 detecciones en 60 segundos, cuando se evalúa el IPS, entonces queda en cuarentena 5 minutos y las peticiones siguientes reciben `403` sin reevaluar las reglas.
- Dado un registro de `audit_log` editado manualmente en la base de datos, cuando se consulta `/api/audit/verify`, entonces el sistema reporta el primer eslabón de la cadena de hashes roto.
- Dado un evento bloqueado, cuando el worker de IA lo procesa, entonces queda con `ai_summary` redactado en menos de 3 segundos o con la plantilla de respaldo si el proveedor falla.
- Dado un ciudadano sin sesión, cuando abre `/publico`, entonces ve los 5 indicadores agregados y alertas en lenguaje claro, sin necesidad de autenticarse.

## 6. Arquitectura

Ver diagrama completo en `docs/architecture.md`. Resumen: `attacker-sim` envía tráfico al **gateway inline** (puerto 8080), que normaliza, evalúa reglas y decide BLOCK/ALLOW; solo lo permitido llega a los objetivos (`gov-pago`, `tickets`), que no publican puertos propios. Los eventos se encolan en memoria, se escriben por lotes en PostgreSQL con cadena de hashes, se enriquecen con `ml_score` y con el triage de IA, y se exponen vía la **API** (puerto 3000) al panel SOC (SSE) y al Observatorio público.

## 7. Ética y privacidad

- Las dos aplicaciones de laboratorio son propias, aisladas (red Docker sin salida a internet) y usan **exclusivamente datos sintéticos** (nombres, cédulas y montos inventados): nunca datos reales de ciudadanos.
- El LLM **nunca** tiene autoridad de bloqueo; el veredicto siempre lo decide el motor determinista. Esto mitiga el riesgo de que un ataque de inyección de prompts embebido en el tráfico malicioso se traduzca en una acción del sistema.
- `app/ai/sanitizer.py` enmascara PII (cédulas, correos, teléfonos, tarjetas) antes de que cualquier payload salga hacia la API de DeepSeek.
- El Observatorio público (SDD #40) solo expone agregados: nunca IP origen, payload capturado ni ningún identificador directo de una víctima o de un ente concreto.
- Ver `docs/declaracion-ia.md` para la declaración obligatoria de uso de IA del hackathon.

## 8. Riesgos y supuestos

| Riesgo / supuesto | Mitigación |
|---|---|
| El modelo ML no converge a F1 ≥ 0,90 / FP ≤ 5% sobre NSL-KDD a tiempo | Plan B de la compuerta de F3: se presenta solo el motor de reglas con sus métricas reales (ver `docs/SPRINT-1.md` sección 7). |
| La API de DeepSeek falla, tarda o está sin cuota durante la demo | Timeout de 3 s + plantilla de respaldo determinista; la plataforma sigue funcionando y se presenta como "IA con respaldo determinista". |
| El dataset NSL-KDD no se descarga a tiempo | Bloquea solo el entrenamiento ML, no el IPS (que depende únicamente de las reglas). |
| Se asume Docker Compose local, 100% offline salvo la llamada a DeepSeek | Decisión cerrada del equipo (ver `docs/decisiones.md`); no se reabre durante el sprint. |
| Rol de Rafael en el equipo sin confirmar | Pendiente explícito en `docs/SPRINT-1.md` sección 10; no bloquea el esqueleto técnico. |
