"""Cola en memoria + escritura por lotes a PostgreSQL.

El gateway nunca escribe directamente a la base de datos en el camino
crítico de la petición: solo mete el evento ya decidido en un
asyncio.Queue y sigue respondiendo. Un worker de fondo drena la cola cada
`queue_flush_interval_seconds` o cuando se llena un lote de
`queue_batch_size`, lo que ocurra primero. Esto evita que el simulador de
1.000 peticiones tumbe la base de datos (ver SPRINT-1, fase F2).

Cada evento insertado también genera una entrada en audit_log (cadena de
hashes) dentro de la misma transacción, y se reenvía a los suscriptores de
/api/stream (SSE) para que el panel SOC se actualice sin recargar.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
from dataclasses import asdict, dataclass

from app.config import Settings
from app.storage.audit import append_entry
from app.storage.db import async_session
from app.storage.models import Event

logger = logging.getLogger("centinela.queue")


@dataclass
class PendingEvent:
    ts: dt.datetime
    src_ip: str
    method: str
    path: str
    target: str
    verdict: str
    rule_id: str | None
    category: str | None
    severity: str | None
    technique_id: str | None
    ml_score: float | None
    engine_us: int
    payload_sample: str | None


class EventQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[PendingEvent] = asyncio.Queue()
        self._subscribers: set[asyncio.Queue[dict]] = set()
        self._worker_task: asyncio.Task | None = None
        self._settings: Settings | None = None

    async def start(self, settings: Settings) -> None:
        self._settings = settings
        self._worker_task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()

    def subscribe(self) -> asyncio.Queue[dict]:
        sub: asyncio.Queue[dict] = asyncio.Queue()
        self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: asyncio.Queue[dict]) -> None:
        self._subscribers.discard(sub)

    async def publish(self, event: PendingEvent) -> None:
        await self._queue.put(event)

    async def _broadcast(self, payload: dict) -> None:
        for sub in list(self._subscribers):
            await sub.put(payload)

    async def _run(self) -> None:
        assert self._settings is not None
        batch: list[PendingEvent] = []
        while True:
            try:
                timeout = self._settings.queue_flush_interval_seconds
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    batch.append(item)
                except asyncio.TimeoutError:
                    pass

                if batch and (
                    len(batch) >= self._settings.queue_batch_size
                    or self._queue.empty()
                ):
                    await self._flush(batch)
                    batch = []
            except asyncio.CancelledError:
                if batch:
                    await self._flush(batch)
                raise
            except Exception:
                logger.exception("Error drenando la cola de eventos")
                batch = []

    async def _flush(self, batch: list[PendingEvent]) -> None:
        async with async_session() as session:
            async with session.begin():
                for pending in batch:
                    row = Event(**asdict(pending), ai_status="pending")
                    session.add(row)
                    await session.flush()

                    await append_entry(
                        session,
                        event_id=row.id,
                        action="event_created",
                        payload={"event_id": row.id, "verdict": row.verdict, "rule_id": row.rule_id},
                    )

                    await self._broadcast(
                        {
                            "id": row.id,
                            "ts": row.ts.isoformat(),
                            "src_ip": row.src_ip,
                            "method": row.method,
                            "path": row.path,
                            "target": row.target,
                            "verdict": row.verdict,
                            "rule_id": row.rule_id,
                            "category": row.category,
                            "severity": row.severity,
                            "technique_id": row.technique_id,
                            "ml_score": row.ml_score,
                            "engine_us": row.engine_us,
                            "payload_sample": row.payload_sample,
                            "ai_summary": None,
                            "ai_status": "pending",
                        }
                    )


event_queue = EventQueue()
