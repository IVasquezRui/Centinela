"""Pruebas de integración: Gateway → Cola → Auditoría (T-10).

Verifica el flujo extremo-a-extremo sin infraestructura externa:
  1. El motor de reglas detecta un ataque y produce un Verdict con engine_us medido.
  2. gateway._record() construye PendingEvent y lo publica en la cola sin I/O bloqueante.
  3. El worker de fondo persiste el evento atómicamente junto a su eslabón en audit_log.
  4. El ai_status se asigna correctamente: 'pending' para 'block', 'done' para 'allow'.
  5. La cadena de hashes en audit_log permanece íntegra tras múltiples eventos mixtos.
  6. El engine_us cumple el SLA contractual (< 10 000 µs) para peticiones normales.

Estrategia de aislamiento:
  - Se mockea `app.queue.async_session` con una sesión SQLite en memoria (igual que
    test_queue.py) para no requerir PostgreSQL en el entorno de CI.
  - Se mockea `app.gateway.event_queue` apuntando a una instancia fresca de EventQueue
    controlada por el test, con SQLite en memoria.
  - `rule_engine.load()` carga el YAML real de producción, garantizando que los patrones
    deterministas del sprint están activos durante la integración.
"""
from __future__ import annotations

import asyncio
import datetime as dt
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import event as sa_event
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import Settings
from app.engine.normalizer import normalize
from app.engine.rules import rule_engine
from app.gateway import _record
from app.queue import EventQueue, PendingEvent
from app.storage.audit import verify_chain
from app.storage.models import AttackTechnique, AuditLog, Base, Event, Rule

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
def load_rules():
    """Carga las reglas deterministas reales antes de cada prueba."""
    rules_path = Path(__file__).parent.parent / "app" / "engine" / "rules.yaml"
    rule_engine.load(rules_path)


@pytest_asyncio.fixture
async def memory_db():
    """Base de datos SQLite en memoria con FK activadas y datos semilla."""
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
        session.add(AttackTechnique(
            technique_id="T1190", name="Exploit Public-Facing Application",
            tactic="Initial Access", description="Explotación de app pública"
        ))
        session.add(AttackTechnique(
            technique_id="T1059.007", name="JavaScript",
            tactic="Execution", description="Ejecución de scripts"
        ))
        session.add(Rule(
            id="CNT-SQLI-001", category="sqli", severity="critica",
            technique_id="T1190", description="SQLi tautología", pattern="test"
        ))
        session.add(Rule(
            id="CNT-XSS-001", category="xss", severity="alta",
            technique_id="T1059.007", description="XSS script tag", pattern="test"
        ))
        await session.commit()

    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def queue_and_settings(memory_db):
    """EventQueue arrancado con SQLite en memoria, listo para usar en tests."""
    settings = Settings(queue_batch_size=50, queue_flush_interval_seconds=0.1)
    q = EventQueue()
    with patch("app.queue.async_session", memory_db):
        await q.start(settings)
        yield q, settings, memory_db
        await q.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalized_sqli():
    """Petición normalizada con payload SQLi clásico."""
    return normalize(
        method="GET",
        path="/gov-pago/login",
        query_string="id=1' OR '1'='1",
        headers={"host": "localhost", "user-agent": "pytest"},
        body=b"",
        src_ip="10.0.0.1",
    )


def _normalized_clean():
    """Petición normalizada benigna sin patrones de ataque."""
    return normalize(
        method="GET",
        path="/gov-pago/static/logo.png",
        query_string="v=2",
        headers={"host": "localhost", "user-agent": "Mozilla/5.0"},
        body=b"",
        src_ip="10.0.0.2",
    )


# ---------------------------------------------------------------------------
# T-10 · Pruebas de Integración
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_us_dentro_del_sla() -> None:
    """El motor determinista resuelve una petición en menos de 10 000 µs (SLA)."""
    req = _normalized_sqli()
    verdict = rule_engine.evaluate(req)
    assert verdict.engine_us < 10_000, (
        f"SLA violado: engine_us={verdict.engine_us} ≥ 10 000 µs"
    )


@pytest.mark.asyncio
async def test_block_produce_pending_en_cola(queue_and_settings) -> None:
    """
    _record() con verdict='block' publica un PendingEvent en la cola
    sin ninguna escritura a disco en el hilo principal (non-blocking).
    """
    q, settings, memory_db = queue_and_settings

    req = _normalized_sqli()
    verdict = rule_engine.evaluate(req)
    assert verdict.verdict == "block"

    # Reemplazar el event_queue global del módulo gateway con nuestra instancia
    with patch("app.gateway.event_queue", q):
        t0 = asyncio.get_event_loop().time()
        await _record(
            src_ip="10.0.0.1",
            method="GET",
            path="/gov-pago/login",
            target="gov-pago",
            verdict="block",
            rule_id=verdict.rule_id,
            category=verdict.category,
            severity=verdict.severity,
            technique_id=verdict.technique_id,
            payload_sample=verdict.payload_sample,
            engine_us=verdict.engine_us,
        )
        elapsed_ms = (asyncio.get_event_loop().time() - t0) * 1000

    # _record solo hace queue.put — debe ser instantáneo (< 5 ms)
    assert elapsed_ms < 5, f"_record bloqueó el hilo durante {elapsed_ms:.1f} ms"
    assert q._queue.qsize() == 1


@pytest.mark.asyncio
async def test_allow_produce_ai_status_done(queue_and_settings) -> None:
    """
    Un evento con verdict='allow' se persiste con ai_status='done':
    no requiere triage del copiloto LLM.
    """
    q, settings, memory_db = queue_and_settings

    with patch("app.queue.async_session", memory_db), \
         patch("app.gateway.event_queue", q):
        await _record(
            src_ip="10.0.0.2",
            method="GET",
            path="/gov-pago/static/logo.png",
            target="gov-pago",
            verdict="allow",
            rule_id=None,
            category=None,
            severity=None,
            technique_id=None,
            payload_sample=None,
            engine_us=42,
        )
        # Dar tiempo al worker para drenar
        await asyncio.sleep(0.3)

    async with memory_db() as session:
        events = (await session.scalars(select(Event))).all()
        assert len(events) == 1
        assert events[0].verdict == "allow"
        assert events[0].ai_status == "done"
        assert events[0].engine_us == 42


@pytest.mark.asyncio
async def test_block_produce_ai_status_pending(queue_and_settings) -> None:
    """
    Un evento con verdict='block' se persiste con ai_status='pending':
    está en cola para el triage del copiloto LLM.
    """
    q, settings, memory_db = queue_and_settings

    with patch("app.queue.async_session", memory_db), \
         patch("app.gateway.event_queue", q):
        await _record(
            src_ip="10.0.0.1",
            method="POST",
            path="/gov-pago/login",
            target="gov-pago",
            verdict="block",
            rule_id="CNT-SQLI-001",
            category="sqli",
            severity="critica",
            technique_id="T1190",
            payload_sample="' OR '1'='1",
            engine_us=350,
        )
        await asyncio.sleep(0.3)

    async with memory_db() as session:
        events = (await session.scalars(select(Event))).all()
        assert len(events) == 1
        assert events[0].verdict == "block"
        assert events[0].ai_status == "pending"
        assert events[0].rule_id == "CNT-SQLI-001"
        assert events[0].engine_us == 350


@pytest.mark.asyncio
async def test_engine_us_propagado_al_evento(queue_and_settings) -> None:
    """
    El campo engine_us medido por rule_engine.evaluate() llega intacto
    al registro persistido en la tabla event.
    """
    q, settings, memory_db = queue_and_settings

    req = _normalized_sqli()
    verdict = rule_engine.evaluate(req)
    assert verdict.verdict == "block"
    expected_engine_us = verdict.engine_us

    with patch("app.queue.async_session", memory_db), \
         patch("app.gateway.event_queue", q):
        await _record(
            src_ip="10.0.0.1",
            method="GET",
            path="/gov-pago/login",
            target="gov-pago",
            verdict=verdict.verdict,
            rule_id=verdict.rule_id,
            category=verdict.category,
            severity=verdict.severity,
            technique_id=verdict.technique_id,
            payload_sample=verdict.payload_sample,
            engine_us=expected_engine_us,
        )
        await asyncio.sleep(0.3)

    async with memory_db() as session:
        events = (await session.scalars(select(Event))).all()
        assert len(events) == 1
        assert events[0].engine_us == expected_engine_us


@pytest.mark.asyncio
async def test_audit_chain_integra_eventos_mixtos(queue_and_settings) -> None:
    """
    Tras persistir una mezcla de eventos block y allow, la cadena de hashes
    en audit_log debe ser 100% íntegra (verify_chain retorna valid=True).
    """
    q, settings, memory_db = queue_and_settings

    eventos = [
        dict(src_ip="10.0.0.1", method="POST", path="/gov-pago/login",
             target="gov-pago", verdict="block", rule_id="CNT-SQLI-001",
             category="sqli", severity="critica", technique_id="T1190",
             payload_sample="' OR 1=1", engine_us=180),
        dict(src_ip="10.0.0.3", method="GET", path="/gov-pago/inicio",
             target="gov-pago", verdict="allow", rule_id=None,
             category=None, severity=None, technique_id=None,
             payload_sample=None, engine_us=55),
        dict(src_ip="10.0.0.4", method="GET", path="/tickets/api/buscar",
             target="tickets", verdict="block", rule_id="CNT-XSS-001",
             category="xss", severity="alta", technique_id="T1059.007",
             payload_sample="<script>alert(1)</script>", engine_us=210),
    ]

    with patch("app.queue.async_session", memory_db), \
         patch("app.gateway.event_queue", q):
        for ev in eventos:
            await _record(**ev)
        # Esperar a que el worker drene el lote por timer (0.1s + holgura)
        await asyncio.sleep(0.4)

    async with memory_db() as session:
        persisted = (await session.scalars(select(Event))).all()
        assert len(persisted) == 3

        report = await verify_chain(session)
        assert report["valid"] is True, f"Cadena rota: {report}"
        assert report["entries_checked"] == 3
