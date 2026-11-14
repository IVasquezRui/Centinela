# Arquitectura — CENTINELA (Sprint 1)

## Diagrama de componentes y flujo de datos

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

Diagrama original y contexto completo de las fases del sprint en `docs/SPRINT-1.md` sección 3.

## Decisiones de diseño clave

1. **El gateway es inline, no pasivo.** El PRD original lo describía recibiendo logs después del ataque; en esta arquitectura el gateway está delante de los objetivos y decide antes de que la petición los alcance.
2. **Los objetivos no publican puertos.** Solo son alcanzables a través del gateway (enrutamiento por prefijo de ruta: `/gov-pago/...`, `/tickets/...`), para que no se pueda saltar la inspección.
3. **El veredicto lo decide un motor determinista, nunca el LLM.** El modelo de ML y el copiloto de IA solo añaden contexto después del veredicto; si ambos fallan, el IPS sigue bloqueando con las mismas reglas.
4. **Escritura por lotes, no síncrona.** El gateway nunca bloquea una respuesta esperando una escritura a PostgreSQL: encola el evento en memoria y un worker de fondo lo persiste por lotes, para que un pico de 1.000 peticiones no tumbe la base de datos.
5. **Inmutabilidad en dos capas.** La cadena de hashes (aplicación) hace visible cualquier alteración; los `GRANT`/`REVOKE` de `db/init/03_grants.sql` (base de datos) impiden que el propio rol de la aplicación pueda ejecutar el `UPDATE`/`DELETE` que rompería esa cadena.
6. **Un solo flujo alimenta las dos caras.** El Observatorio público no tiene un formulario de carga manual: sus indicadores son agregados calculados directamente sobre la tabla `event` que llena el motor del SOC.

## Mapeo de servicios Docker

| Servicio | Rol | Puertos publicados |
|---|---|---|
| `centinela-db` | PostgreSQL 16, esquema + seed ATT&CK + grants | ninguno (solo red interna `dmz-net`) |
| `centinela-core` | Gateway inline + API SOC/Observatorio | `8080` (gateway), `3000` (API) |
| `frontend` | Panel SOC + Observatorio público | `5173` |
| `gov-mysql` | MySQL 5.7 del objetivo A | ninguno |
| `gov-pago` | Objetivo vulnerable A (PHP) | ninguno — solo vía gateway |
| `tickets` | Objetivo vulnerable B (Node.js) | ninguno — solo vía gateway |
| `attacker-sim` | Generador de tráfico (perfil `demo`, bajo demanda) | ninguno |
