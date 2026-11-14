import json
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.storage.models import Base, AuditLog
from app.storage.audit import append_entry, verify_chain


@pytest_asyncio.fixture
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield async_session

    await engine.dispose()


@pytest.mark.asyncio
async def test_audit_chain_integrity_normal(async_db):
    async with async_db() as session:
        await append_entry(session, event_id=1, action="block", payload={"rule": "SQLI", "ip": "1.1.1.1"})
        await append_entry(session, event_id=2, action="quarantine", payload={"ip": "1.1.1.1"})
        await append_entry(session, event_id=3, action="block", payload={"rule": "XSS", "ip": "2.2.2.2"})
        await session.commit()

        result = await verify_chain(session)
        assert result["valid"] is True
        assert result["broken_at_id"] is None
        assert result["entries_checked"] == 3


@pytest.mark.asyncio
async def test_audit_chain_detects_manual_psql_tampering(async_db):
    """Prueba el 'Momento de Impacto' del guion de la demo (Fase F5):
    Un atacante modifica una fila existente con UPDATE; el verificador debe detectar
    la rotura y señalar exactamente el id modificado."""
    async with async_db() as session:
        await append_entry(session, event_id=1, action="block", payload={"rule": "SQLI", "ip": "10.0.0.1"})
        await append_entry(session, event_id=2, action="block", payload={"rule": "CMDI", "ip": "10.0.0.2"})
        await append_entry(session, event_id=3, action="block", payload={"rule": "XSS", "ip": "10.0.0.3"})
        await session.commit()

        # Simular UPDATE manual con psql alterando la fila 2 para blanquear el ataque
        tampered_payload = json.dumps({"rule": "CLEAN", "ip": "10.0.0.2"})
        await session.execute(
            text("UPDATE audit_log SET payload = :p WHERE id = 2"),
            {"p": tampered_payload}
        )
        await session.commit()

        result = await verify_chain(session)
        assert result["valid"] is False
        assert result["broken_at_id"] == 2
        assert result["expected_hash"] != result["stored_hash"]
        assert result["entries_checked"] == 3


@pytest.mark.asyncio
async def test_audit_chain_detects_deleted_record(async_db):
    """Si un atacante elimina físicamente una fila intermedia,
    la siguiente fila apuntará a un prev_hash que no coincide."""
    async with async_db() as session:
        await append_entry(session, event_id=1, action="block", payload={"id": "evt-1"})
        await append_entry(session, event_id=2, action="block", payload={"id": "evt-2"})
        await append_entry(session, event_id=3, action="block", payload={"id": "evt-3"})
        await session.commit()

        # Borrar la fila 2
        await session.execute(text("DELETE FROM audit_log WHERE id = 2"))
        await session.commit()

        result = await verify_chain(session)
        assert result["valid"] is False
        assert result["broken_at_id"] == 3
        assert result["expected_prev_hash"] != result["stored_prev_hash"]
