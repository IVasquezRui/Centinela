"""Pruebas unitarias de la cola en memoria e ingesta por lotes (app/queue.py).

Verifica:
1. Desacoplamiento asíncrono y descarga por tamaño de lote (queue_batch_size).
2. Descarga por expiración de temporizador (queue_flush_interval_seconds).
3. Aislamiento de fallos mediante savepoints anidados (session.begin_nested).
4. Emisión atómica hacia suscriptores SSE tras confirmación en BD.
5. Inmutabilidad encadenada simultánea en audit_log para cada evento persistido.
"""
from __future__ import annotations

import asyncio
import datetime as dt
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import event as sa_event
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import Settings
from app.queue import EventQueue, PendingEvent
from app.storage.audit import verify_chain
from app.storage.models import AttackTechnique, AuditLog, Base, Event, Rule


@pytest_asyncio.fixture
async def memory_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    @sa_event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Sembrar técnica y regla para pruebas de FK
    async with session_factory() as session:
        session.add(AttackTechnique(technique_id="T1190", name="Exploit", tactic="Initial Access", description="Test"))
        session.add(Rule(id="CNT-SQLI-001", category="sqli", severity="critica", technique_id="T1190", description="SQLi test", pattern="test"))
        await session.commit()

    yield session_factory
    await engine.dispose()


def _sample_pending(i: int, rule_id: str | None = "CNT-SQLI-001") -> PendingEvent:
    return PendingEvent(
        ts=dt.datetime.now(dt.timezone.utc),
        src_ip=f"192.168.1.{i}",
        method="GET",
        path=f"/test/{i}",
        target="gov-pago",
        verdict="block",
        rule_id=rule_id,
        category="sqli",
        severity="critica",
        technique_id="T1190",
        ml_score=0.95,
        engine_us=120,
        payload_sample=f"id={i}' OR 1=1",
    )


@pytest.mark.asyncio
async def test_queue_drain_by_batch_size(memory_db) -> None:
    """Verifica que alcanzar queue_batch_size dispare la escritura inmediata."""
    settings = Settings(queue_batch_size=5, queue_flush_interval_seconds=10.0)
    queue = EventQueue()

    with patch("app.queue.async_session", memory_db):
        await queue.start(settings)

        # Publicar exactamente el tamaño de lote (5)
        for i in range(1, 6):
            await queue.publish(_sample_pending(i))

        # Esperar un instante para que el worker procese el lote
        await asyncio.sleep(0.1)
        await queue.stop()

    async with memory_db() as session:
        events = (await session.scalars(select(Event))).all()
        audit_entries = (await session.scalars(select(AuditLog))).all()

        assert len(events) == 5
        assert len(audit_entries) == 5

        # Verificar que la cadena de hashes en audit_log sea 100% íntegra
        report = await verify_chain(session)
        assert report["valid"] is True
        assert report["entries_checked"] == 5


@pytest.mark.asyncio
async def test_queue_drain_by_timeout(memory_db) -> None:
    """Verifica que un volumen menor al lote se descargue al vencer el intervalo."""
    settings = Settings(queue_batch_size=50, queue_flush_interval_seconds=0.1)
    queue = EventQueue()

    with patch("app.queue.async_session", memory_db):
        await queue.start(settings)

        # Publicar solo 2 eventos (muy por debajo de 50)
        await queue.publish(_sample_pending(1))
        await queue.publish(_sample_pending(2))

        # Esperar el vencimiento del temporizador (0.1s + holgura)
        await asyncio.sleep(0.25)
        await queue.stop()

    async with memory_db() as session:
        events = (await session.scalars(select(Event))).all()
        assert len(events) == 2


@pytest.mark.asyncio
async def test_queue_sse_broadcast(memory_db) -> None:
    """Verifica que los eventos confirmados se difundan a suscriptores SSE."""
    settings = Settings(queue_batch_size=1, queue_flush_interval_seconds=1.0)
    queue = EventQueue()

    sub = queue.subscribe()
    try:
        with patch("app.queue.async_session", memory_db):
            await queue.start(settings)
            await queue.publish(_sample_pending(42))

            payload = await asyncio.wait_for(sub.get(), timeout=1.0)
            assert payload["id"] == 1
            assert payload["src_ip"] == "192.168.1.42"
            assert payload["verdict"] == "block"
            assert payload["ai_status"] == "pending"

            await queue.stop()
    finally:
        queue.unsubscribe(sub)


@pytest.mark.asyncio
async def test_queue_resilience_savepoint(memory_db) -> None:
    """Un evento con fallo no debe tumbar ni descartar al resto del lote."""
    settings = Settings(queue_batch_size=2, queue_flush_interval_seconds=1.0)
    queue = EventQueue()

    with patch("app.queue.async_session", memory_db):
        await queue.start(settings)

        # Publicar 1 evento normal y 1 con regla no sembrada
        await queue.publish(_sample_pending(1, rule_id="CNT-SQLI-001"))
        await queue.publish(_sample_pending(2, rule_id="CNT-UNKNOWN-999"))

        await asyncio.sleep(0.15)
        await queue.stop()

    async with memory_db() as session:
        events = (await session.scalars(select(Event))).all()
        # Ambos deben haber sido persistidos
        assert len(events) == 2
        # El segundo debió conservar la evidencia con rule_id=None gracias al fallback
        assert events[0].rule_id == "CNT-SQLI-001"
        assert events[1].rule_id is None
