"""Tests de la Fase 3 — integridad forense y drenado de cola al apagar.

1. El hash cubre ts/action/event_id además del payload (C6).
2. verify_chain detecta el borrado del FINAL de la cadena (truncamiento)
   gracias al ancla audit_anchor.
3. EventQueue.stop() drena los eventos pendientes para no perder evidencia.
"""
from __future__ import annotations

import asyncio
import datetime as dt

import pytest
import pytest_asyncio
from sqlalchemy import event as sa_event
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import Settings
from app.queue import EventQueue, PendingEvent
from app.storage.audit import append_entry, verify_chain
from app.storage.models import AttackTechnique, AuditLog, Base, Event, Rule


@pytest_asyncio.fixture
async def audit_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_hash_cubre_action_y_event_id(audit_db) -> None:
    """Alterar action (fuera del payload) debe romper la cadena."""
    async with audit_db() as session:
        await append_entry(session, event_id=1, action="block", payload={"rule": "SQLI"})
        await session.commit()

        await session.execute(text("UPDATE audit_log SET action = 'allow' WHERE id = 1"))
        await session.commit()

        report = await verify_chain(session)
        assert report["valid"] is False
        assert report["broken_at_id"] == 1


@pytest.mark.asyncio
async def test_verify_detecta_truncamiento_del_final(audit_db) -> None:
    """Borrar el último eslabón (cola) es detectado vía el ancla audit_anchor."""
    async with audit_db() as session:
        for i in range(1, 4):
            await append_entry(session, event_id=i, action="block", payload={"id": f"e{i}"})
        await session.commit()

        await session.execute(text("DELETE FROM audit_log WHERE id = 3"))
        await session.commit()

        report = await verify_chain(session)
        assert report["valid"] is False
        assert report.get("truncated") is True
        assert report["actual_last_id"] == 2
        assert report["expected_last_id"] == 3


@pytest_asyncio.fixture
async def queue_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    @sa_event.listens_for(engine.sync_engine, "connect")
    def _fk_on(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session:
        session.add(AttackTechnique(technique_id="T1190", name="Exploit", tactic="Initial Access", description="Test"))
        session.add(Rule(id="CNT-SQLI-001", category="sqli", severity="critica", technique_id="T1190", description="SQLi", pattern="test"))
        await session.commit()

    yield factory
    await engine.dispose()


def _event(i: int) -> PendingEvent:
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
        ml_score=0.9,
        engine_us=100,
        payload_sample=f"id={i}' OR 1=1",
    )


@pytest.mark.asyncio
async def test_stop_drena_eventos_pendientes(queue_db) -> None:
    """stop() debe persistir los eventos aún no procesados (sin esperar el timer)."""
    from unittest.mock import patch

    settings = Settings(queue_batch_size=50, queue_flush_interval_seconds=10.0)
    q = EventQueue()

    with patch("app.queue.async_session", queue_db):
        await q.start(settings)
        for i in range(1, 6):
            await q.publish(_event(i))
        # Sin dormir: stop() debe drenar la cola completa
        await q.stop()

    async with queue_db() as session:
        events = (await session.scalars(select(Event))).all()
        audit = (await session.scalars(select(AuditLog))).all()
        assert len(events) == 5
        assert len(audit) == 5
        report = await verify_chain(session)
        assert report["valid"] is True
        assert report["entries_checked"] == 5
