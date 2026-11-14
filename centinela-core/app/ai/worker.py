"""Worker de fondo que redacta el triage de IA para eventos bloqueados.

Corre fuera del camino crítico del gateway: consulta periódicamente los
eventos con ai_status='pending' y verdict='block', les pide un triage al
LLMProvider configurado, y guarda el resultado. Si el proveedor falla o
tarda más de AI_TIMEOUT_SECONDS, LLMProvider ya habrá devuelto la
plantilla de respaldo, así que este worker siempre termina marcando el
evento como 'done' (nunca se queda bloqueado reintentando indefinidamente
sobre el mismo evento).
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from app.ai.provider import build_provider
from app.config import Settings
from app.storage.db import async_session
from app.storage.models import Event

logger = logging.getLogger("centinela.ai.worker")

POLL_INTERVAL_SECONDS = 1.0
BATCH_SIZE = 100


async def run_worker(settings: Settings, stop_event: asyncio.Event) -> None:
    provider = build_provider(settings)

    while not stop_event.is_set():
        processed = 0
        try:
            processed = await _process_pending_batch(provider)
        except Exception:
            logger.exception("Error procesando el lote de triage de IA")

        if processed >= BATCH_SIZE:
            # Quedan eventos en cola: no se espera el intervalo de sondeo, para
            # que el panel no tarde minutos en mostrar los análisis tras una
            # ráfaga (1.000 eventos en la demo).
            continue

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def _process_pending_batch(provider) -> int:
    async with async_session() as session:
        result = await session.scalars(
            select(Event)
            .where(Event.verdict == "block", Event.ai_status == "pending")
            .order_by(Event.id)
            .limit(BATCH_SIZE)
        )
        pending_events = result.all()
        if not pending_events:
            return 0

        for row in pending_events:
            event_dict = {
                "rule_id": row.rule_id,
                "category": row.category,
                "severity": row.severity,
                "technique_id": row.technique_id,
                "target": row.target,
                "path": row.path,
                "payload_sample": row.payload_sample,
            }
            triage = await provider.triage(event_dict)
            row.ai_summary = f"[{triage.source}] {triage.resumen} Mitigación: {triage.mitigacion_sugerida}"
            row.ai_status = "done"

        await session.commit()
        return len(pending_events)
