"""SSE: /api/stream — el panel SOC recibe eventos en vivo sin recargar."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

from app.queue import event_queue

stream_router = APIRouter()


@stream_router.get("/stream")
async def stream(request: Request) -> EventSourceResponse:
    subscriber = event_queue.subscribe()

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(subscriber.get(), timeout=15.0)
                    yield {"event": "centinela_event", "data": json.dumps(payload)}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            event_queue.unsubscribe(subscriber)

    return EventSourceResponse(event_generator())
