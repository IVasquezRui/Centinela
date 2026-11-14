"""Pruebas unitarias de la cadena de hashes inmutable y verificación forense (audit.py).

Verifica:
1. Determinismo en la serialización canónica JSON (invarianza ante el orden de claves).
2. Cálculo de SHA-256 encadenado partiendo de GENESIS_HASH.
3. Detección forense ante manipulación de payloads (tampering).
4. Detección forense ante alteración de hashes previos (prev_hash).
5. Detección forense ante eliminación de filas intermedias en la bitácora.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.storage.audit import GENESIS_HASH, _canonical, append_entry, compute_hash, verify_chain
from app.storage.models import Base


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


def test_canonical_json_determinism() -> None:
    """Verifica que el orden de las claves no altere el hash canónico."""
    payload_a = {"verdict": "block", "rule_id": "CNT-SQLI-001", "ip": "10.0.0.1"}
    payload_b = {"ip": "10.0.0.1", "verdict": "block", "rule_id": "CNT-SQLI-001"}

    assert _canonical(payload_a) == _canonical(payload_b)
    assert compute_hash(GENESIS_HASH, payload_a) == compute_hash(GENESIS_HASH, payload_b)


def test_hash_avalanche_effect() -> None:
    """Cualquier cambio mínimo en el contenido produce un hash radicalmente distinto."""
    base_payload = {"event_id": 1, "verdict": "block"}
    tampered_payload = {"event_id": 1, "verdict": "allow"}

    hash_a = compute_hash(GENESIS_HASH, base_payload)
    hash_b = compute_hash(GENESIS_HASH, tampered_payload)
    assert hash_a != hash_b


@pytest.mark.asyncio
async def test_empty_chain_is_valid(db_session: AsyncSession) -> None:
    """Una cadena sin entradas se considera válida."""
    report = await verify_chain(db_session)
    assert report["valid"] is True
    assert report["broken_at_id"] is None
    assert report["entries_checked"] == 0


@pytest.mark.asyncio
async def test_append_and_verify_clean_chain(db_session: AsyncSession) -> None:
    """Verifica la creación encadenada de 5 eventos y validación exitosa."""
    entries = []
    for i in range(1, 6):
        entry = await append_entry(
            db_session,
            event_id=i,
            action="event_created",
            payload={"event_id": i, "verdict": "block", "rule": f"CNT-RULE-00{i}"},
        )
        entries.append(entry)
    await db_session.commit()

    # Verificar que el primer registro use GENESIS_HASH
    assert entries[0].prev_hash == GENESIS_HASH
    # Verificar que cada fila subsiguiente apunte al hash de la anterior
    for j in range(1, 5):
        assert entries[j].prev_hash == entries[j - 1].hash

    report = await verify_chain(db_session)
    assert report["valid"] is True
    assert report["broken_at_id"] is None
    assert report["entries_checked"] == 5


@pytest.mark.asyncio
async def test_detect_tampered_payload(db_session: AsyncSession) -> None:
    """Modificar el payload de una fila existente debe romper la cadena en esa fila."""
    for i in range(1, 6):
        await append_entry(
            db_session,
            event_id=i,
            action="event_created",
            payload={"event_id": i, "verdict": "block"},
        )
    await db_session.commit()

    # Ataque forense simulado: Un administrador o intruso altera el payload del id=3
    from sqlalchemy import select
    from app.storage.models import AuditLog

    tampered_row = await db_session.scalar(select(AuditLog).where(AuditLog.id == 3))
    assert tampered_row is not None
    tampered_row.payload = '{"event_id":3,"verdict":"allow"}'  # Modificado sin recalcular hash
    await db_session.commit()

    report = await verify_chain(db_session)
    assert report["valid"] is False
    assert report["broken_at_id"] == 3
    assert report["entries_checked"] == 5


@pytest.mark.asyncio
async def test_detect_tampered_prev_hash(db_session: AsyncSession) -> None:
    """Alterar prev_hash debe ser detectado por verify_chain."""
    for i in range(1, 5):
        await append_entry(
            db_session,
            event_id=i,
            action="event_created",
            payload={"event_id": i, "verdict": "block"},
        )
    await db_session.commit()

    from sqlalchemy import select
    from app.storage.models import AuditLog

    row = await db_session.scalar(select(AuditLog).where(AuditLog.id == 2))
    assert row is not None
    row.prev_hash = "f" * 64
    await db_session.commit()

    report = await verify_chain(db_session)
    assert report["valid"] is False
    assert report["broken_at_id"] == 2


@pytest.mark.asyncio
async def test_detect_deleted_middle_row(db_session: AsyncSession) -> None:
    """Eliminar una fila intermedia rompe el encadenamiento del eslabón siguiente."""
    for i in range(1, 5):
        await append_entry(
            db_session,
            event_id=i,
            action="event_created",
            payload={"event_id": i, "verdict": "block"},
        )
    await db_session.commit()

    from sqlalchemy import select
    from app.storage.models import AuditLog

    row_to_delete = await db_session.scalar(select(AuditLog).where(AuditLog.id == 2))
    assert row_to_delete is not None
    await db_session.delete(row_to_delete)
    await db_session.commit()

    # Al borrar el id=2, el id=3 (cuyo prev_hash apuntaba al id=2) ahora no coincide
    report = await verify_chain(db_session)
    assert report["valid"] is False
    assert report["broken_at_id"] == 3
