"""Cadena de hashes para la bitácora de auditoría.

Cada fila de audit_log encadena su hash al hash de la fila anterior:

    hash_n = sha256(hash_(n-1) + payload_canónico_n)

Esto hace que modificar una fila vieja (por ejemplo con un UPDATE manual
en psql, como en el guion de la demo) rompa el hash de esa fila y el de
todas las siguientes, aunque el atacante no toque las filas posteriores.
/api/audit/verify recorre la cadena y señala el primer eslabón roto.

La inmutabilidad real no depende solo de este cálculo: db/init/03_grants.sql
revoca UPDATE y DELETE sobre audit_log (y sobre event) al rol que usa la
aplicación, así que ni siquiera un bug en el backend puede alterar una fila
ya escrita sin pasar por un rol con privilegios superiores.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.models import AuditLog

GENESIS_HASH = "0" * 64


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, payload: dict) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(_canonical(payload).encode("utf-8"))
    return digest.hexdigest()


async def append_entry(
    session: AsyncSession, *, event_id: int | None, action: str, payload: dict
) -> AuditLog:
    last = await session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    prev_hash = last.hash if last else GENESIS_HASH

    entry_hash = compute_hash(prev_hash, payload)
    entry = AuditLog(
        ts=dt.datetime.now(dt.timezone.utc),
        event_id=event_id,
        action=action,
        payload=_canonical(payload),
        prev_hash=prev_hash,
        hash=entry_hash,
    )
    session.add(entry)
    await session.flush()
    return entry


async def verify_chain(session: AsyncSession) -> dict:
    """Recorre toda la cadena y reporta el primer eslabón roto, si existe."""
    result = await session.scalars(select(AuditLog).order_by(AuditLog.id.asc()))
    entries = result.all()

    expected_prev = GENESIS_HASH
    for entry in entries:
        payload = json.loads(entry.payload)
        recomputed = compute_hash(expected_prev, payload)

        if entry.prev_hash != expected_prev or entry.hash != recomputed:
            return {
                "valid": False,
                "broken_at_id": entry.id,
                "expected_prev_hash": expected_prev,
                "stored_prev_hash": entry.prev_hash,
                "expected_hash": recomputed,
                "stored_hash": entry.hash,
                "entries_checked": len(entries),
            }
        expected_prev = entry.hash

    return {"valid": True, "broken_at_id": None, "entries_checked": len(entries)}
