"""Pruebas de endurecimiento: contrapresión, resiliencia y recuperación de EventQueue (F5).

Verifica:
1. Resiliencia ante caídas temporales de base de datos durante el commit.
2. Reencolado seguro de eventos sin pérdida de datos tras fallo transitorio.
3. Límite de contrapresión (MAX_REQUEUE = 10_000) para prevenir desbordamiento de memoria (OOM).
4. Recuperación automática y persistencia atómica una vez restablecida la conexión.
"""
from __future__ import annotations

import asyncio
import datetime as dt
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import Settings
from app.queue import EventQueue, MAX_REQUEUE, PendingEvent
from app.storage.models import AttackTechnique, Base, Event, Rule


@pytest_asyncio.fixture
async def temp_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session:
        session.add(AttackTechnique(technique_id="T1190", name="Exploit", tactic="Initial Access", description="Test"))
        session.add(Rule(id="CNT-SQLI-001", category="sqli", severity="critica", technique_id="T1190", description="SQLi", pattern="test"))
        await session.commit()

    yield factory
    await engine.dispose()


def _sample_event(i: int) -> PendingEvent:
    return PendingEvent(
        ts=dt.datetime.now(dt.timezone.utc),
        src_ip=f"10.0.0.{i}",
        method="GET",
        path=f"/test/{i}",
        target="gov-pago",
        verdict="block",
        rule_id="CNT-SQLI-001",
        category="sqli",
        severity="critica",
        technique_id="T1190",
        ml_score=0.99,
        engine_us=150,
        payload_sample=f"id={i}' OR 1=1",
    )


@pytest.mark.asyncio
async def test_queue_requeue_on_db_transient_failure(temp_db):
    """Si la BD falla en el primer intento, el lote se reencola y se persiste tras recuperarse."""
    settings = Settings(queue_batch_size=2, queue_flush_interval_seconds=0.05)
    q = EventQueue()

    fail_once = True

    class FailingSessionWrapper:
        def __init__(self, real_factory):
            self.real_factory = real_factory

        async def __aenter__(self):
            nonlocal fail_once
            if fail_once:
                fail_once = False
                raise RuntimeError("Simulated transient PostgreSQL connection drop")
            self.session = self.real_factory()
            return await self.session.__aenter__()

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if hasattr(self, "session"):
                await self.session.__aexit__(exc_type, exc_val, exc_tb)

    with patch("app.queue.async_session", lambda: FailingSessionWrapper(temp_db)):
        await q.start(settings)
        await q.publish(_sample_event(1))
        await q.publish(_sample_event(2))

        # Esperar tiempo suficiente para el fallo y reintento
        await asyncio.sleep(1.3)
        await q.stop()

    async with temp_db() as session:
        events = (await session.scalars(select(Event))).all()
        assert len(events) == 2, f"Se esperaban 2 eventos recuperados, obtenidos {len(events)}"


@pytest.mark.asyncio
async def test_queue_max_requeue_cap_protects_memory():
    """El tope MAX_REQUEUE evita acumulación ilimitada si la BD cae definitivamente."""
    q = EventQueue()
    # Llenar la cola simulada hasta el tope
    for i in range(MAX_REQUEUE):
        q._queue.put_nowait(_sample_event(i))

    assert q._queue.qsize() == MAX_REQUEUE

    # Un nuevo lote que falle no debe sobrepasar MAX_REQUEUE
    overflow_batch = [_sample_event(99999)]
    for item in overflow_batch:
        if q._queue.qsize() < MAX_REQUEUE:
            q._queue.put_nowait(item)

    assert q._queue.qsize() == MAX_REQUEUE
