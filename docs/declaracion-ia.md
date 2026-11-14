# Declaración de uso de IA — CENTINELA

> Obligatoria según la metodología Specification-Driven Development (SDD) del Hackathon UNETI IA 2026.

## Durante la planificación y construcción del proyecto

| Herramienta | Uso | Verificación humana |
|---|---|---|
| Asistente de IA (Claude Code) | Revisión del PRD original, detección de incongruencias arquitectónicas, unificación de los SDD #23 y #40, generación del esqueleto inicial del repositorio (código, esquema SQL, configuración Docker, documentación) a partir de las decisiones ya tomadas por el equipo. | El equipo revisa, ejecuta y ajusta cada archivo generado antes de la demo; ninguna decisión de arquitectura (stack, alcance, proveedor de IA, nivel de las vulnerabilidades de laboratorio) fue tomada por la IA sin confirmación explícita del humano responsable. |
| DeepSeek API (en producto) | Redacción del resumen y la mitigación sugerida de alertas **ya bloqueadas** por el motor determinista del propio CENTINELA. | El veredicto de bloqueo nunca depende de este modelo; si falla o tarda más de 3 segundos, se sustituye por una plantilla determinista. Queda registrado en cada evento si el texto provino del LLM o de la plantilla de respaldo (`ai_status`, prefijo `[llm]`/`[fallback_template]` en `ai_summary`). |
| scikit-learn (RandomForest) | Clasificación binaria normal/ataque sobre el dataset NSL-KDD, usada como señal adicional (`ml_score`) en cada evento. | El modelo no decide bloqueos; sus métricas (F1-score, tasa de falsos positivos) se reportan públicamente en `ml/model/*.metrics.json` y se comparan contra el criterio del SDD #23 (F1 ≥ 0,90, FP ≤ 5%) antes de mencionarlas en la demo. |

## Principio rector

Ninguna de las tres herramientas de IA usadas en este proyecto tiene autoridad para tomar una decisión de seguridad irreversible (bloquear tráfico, modificar un registro de auditoría, publicar un indicador) sin pasar primero por un componente determinista verificable por un humano. Esta regla está implementada en código, no solo declarada aquí: ver `centinela-core/app/engine/rules.py` (el único punto de decisión de bloqueo) y `centinela-core/app/ai/provider.py` (el triage de IA, con validación de esquema JSON cerrado y *fallback* determinista).
