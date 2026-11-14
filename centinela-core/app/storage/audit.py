"""Cadena de hashes para la bitácora de auditoría.

Cada fila de audit_log encadena su hash al hash de la fila anterior:

    hash_n = sha256(hash_(n-1) + ts_n + action_n + event_id_n + payload_canónico_n)

Esto hace que modificar una fila vieja (por ejemplo con un UPDATE manual
en psql, como en el guion de la demo) rompa el hash de esa fila y el de
todas las siguientes, aunque el atacante no toque las filas posteriores.
/api/audit/verify recorre la cadena y señala el primer eslabón roto.

Además del encadenamiento, se mantiene un ANCLA externa (audit_anchor) con
el id y el hash del último eslabón: así también se detecta el borrado del
FINAL de la cadena (truncamiento), que el hash encadenado por sí solo no
puede ver. La inmutabilidad a nivel de motor la garantiza db/init/03_grants.sh
(REVOKE UPDATE/DELETE sobre audit_log al rol centinela_app).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.models import AuditAnchor, AuditLog

GENESIS_HASH = "0" * 64

# Serializa las altas dentro del proceso para que dos escritores concurrentes
# no bifurquen la cadena leyendo el mismo `last`. En un despliegue con varias
# réplicas del core, sustituir por pg_advisory_xact_lock(...) a nivel de BD.
_append_lock = asyncio.Lock()


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, payload: dict) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(_canonical(payload).encode("utf-8"))
    return digest.hexdigest()


def _ts_key(ts: dt.datetime) -> str:
    """Normaliza el timestamp a UTC naive para un hash determinista.

    SQLite no conserva la zona horaria (devuelve datetimes naive), mientras
    que PostgreSQL TIMESTAMPTZ devuelve datetimes aware. Normalizar ambos a
    UTC sin tz garantiza que el mismo instante hashee igual en append y verify.
    """
    if ts.tzinfo is not None:
        ts = ts.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return ts.isoformat()


def _entry_record(ts: dt.datetime, action: str, event_id: int | None, payload_canon: str) -> dict:
    """Estructura que se hashea: cubre ts, action, event_id y el payload."""
    return {
        "ts": _ts_key(ts),
        "action": action,
        "event_id": event_id,
        "payload": payload_canon,
    }


async def append_entry(
    session: AsyncSession, *, event_id: int | None, action: str, payload: dict
) -> AuditLog:
    async with _append_lock:
        last = await session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
        prev_hash = last.hash if last else GENESIS_HASH

        ts = dt.datetime.now(dt.timezone.utc)
        payload_canon = _canonical(payload)
        entry_hash = compute_hash(prev_hash, _entry_record(ts, action, event_id, payload_canon))

        entry = AuditLog(
            ts=ts,
            event_id=event_id,
            action=action,
            payload=payload_canon,
            prev_hash=prev_hash,
            hash=entry_hash,
        )
        session.add(entry)
        await session.flush()

        # Ancla externa: id y hash del último eslabón, para detectar truncamiento.
        anchor = await session.get(AuditAnchor, 1)
        if anchor is None:
            session.add(AuditAnchor(id=1, last_id=entry.id, head_hash=entry.hash))
        else:
            anchor.last_id = entry.id
            anchor.head_hash = entry.hash
            anchor.updated_at = dt.datetime.now(dt.timezone.utc)

        return entry


async def verify_chain(session: AsyncSession) -> dict:
    """Recorre la cadena y reporta el primer eslabón roto o el truncamiento."""
    result = await session.scalars(select(AuditLog).order_by(AuditLog.id.asc()))
    entries = result.all()

    expected_prev = GENESIS_HASH
    for entry in entries:
        recomputed = compute_hash(
            expected_prev,
            _entry_record(entry.ts, entry.action, entry.event_id, entry.payload),
        )

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

    # Detección de truncamiento del final: la cadena interna puede seguir siendo
    # consistente, pero ya no coincide con el ancla (id/hash del último eslabón).
    anchor = await session.get(AuditAnchor, 1)
    if entries and anchor is not None:
        last_entry = entries[-1]
        if anchor.last_id != last_entry.id or anchor.head_hash != last_entry.hash:
            return {
                "valid": False,
                "broken_at_id": None,
                "truncated": True,
                "expected_last_id": anchor.last_id,
                "actual_last_id": last_entry.id,
                "entries_checked": len(entries),
            }

    return {"valid": True, "broken_at_id": None, "entries_checked": len(entries)}
