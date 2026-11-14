"""API del panel SOC — puerto 3000.

Implementa los endpoints del contrato congelado en docs/SPRINT-1.md:
/api/health, /api/stats, /api/events, /api/blocklist, /api/audit/verify.
/api/stream y /api/public/* viven en app/api/stream.py y app/api/public.py
respectivamente, pero se montan todos en la misma app (`api_app`).
"""
from __future__ import annotations

import datetime as dt

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select

from app.api.public import public_router
from app.api.stream import stream_router
from app.ips.blocklist import blocklist
from app.storage.audit import verify_chain
from app.storage.db import async_session
from app.storage.models import Event

api_app = FastAPI(title="CENTINELA API", version="0.1.0")

api_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # panel SOC y Observatorio corren en localhost durante el sprint
    allow_methods=["GET"],
    allow_headers=["*"],
)

api_app.include_router(public_router, prefix="/api/public", tags=["observatorio"])
api_app.include_router(stream_router, prefix="/api", tags=["stream"])


@api_app.get("/api/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "centinela-core",
        "time": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


@api_app.get("/api/stats")
async def stats() -> dict:
    async with async_session() as session:
        total = await session.scalar(select(func.count(Event.id))) or 0
        blocked = await session.scalar(
            select(func.count(Event.id)).where(Event.verdict == "block")
        ) or 0
        p95_engine_us = await session.scalar(
            select(func.percentile_cont(0.95).within_group(Event.engine_us))
        )

    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "allowed_requests": total - blocked,
        "quarantined_ips": len(blocklist.snapshot()),
        "engine_latency_p95_us": float(p95_engine_us) if p95_engine_us is not None else None,
    }


@api_app.get("/api/events")
async def list_events(
    severity: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    since: dt.datetime | None = Query(default=None),
    until: dt.datetime | None = Query(default=None),
    limit: int = Query(default=100, le=1000),
) -> list[dict]:
    async with async_session() as session:
        stmt = select(Event).order_by(Event.id.desc()).limit(limit)
        if severity:
            stmt = stmt.where(Event.severity == severity)
        if src_ip:
            stmt = stmt.where(Event.src_ip == src_ip)
        if since:
            stmt = stmt.where(Event.ts >= since)
        if until:
            stmt = stmt.where(Event.ts <= until)

        rows = (await session.scalars(stmt)).all()

    return [_event_to_dict(row) for row in rows]


@api_app.get("/api/blocklist")
async def get_blocklist() -> list[dict]:
    return blocklist.snapshot()


@api_app.get("/api/audit/verify")
async def audit_verify() -> dict:
    async with async_session() as session:
        return await verify_chain(session)


def _event_to_dict(row: Event) -> dict:
    return {
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
        "ai_summary": row.ai_summary,
        "ai_status": row.ai_status,
    }
