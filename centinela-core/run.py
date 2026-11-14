"""Punto de entrada único del contenedor centinela-core.

Arranca dos servidores Uvicorn en el mismo proceso, uno por cada contrato
congelado en docs/SPRINT-1.md:

- :8080 -> gateway inline (reverse proxy con motor de reglas)
- :3000 -> API del panel SOC y del Observatorio público

Ambos comparten el mismo pool de conexiones a PostgreSQL y la misma cola
en memoria, por eso viven en un solo proceso en vez de dos contenedores.

Además se lanza el worker de triage del copiloto IA (`app/ai/worker.py`)
como tarea de fondo: si no se arranca, los eventos bloqueados se quedan con
ai_status='pending' para siempre y el panel nunca muestra el análisis.
"""
import asyncio
import contextlib
import logging

import uvicorn

from app.ai.worker import run_worker
from app.api.soc import api_app
from app.config import get_settings
from app.gateway import gateway_app
from app.queue import event_queue

_SAFE_CONTROL = {9, 10, 13}  # tab, LF, CR


class _SanitizeLogFilter(logging.Filter):
    """Elimina caracteres de control de los mensajes de log.

    El gateway loguea el path decodificado; sin este filtro, un path con
    secuencias ANSI podría inyectar escapes de terminal o forjar líneas.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = "".join(
                ch if ord(ch) >= 32 or ord(ch) in _SAFE_CONTROL else "?"
                for ch in record.msg
            )
        return True


def _install_log_sanitizer() -> None:
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error", "centinela"):
        logging.getLogger(name).addFilter(_SanitizeLogFilter())


async def main() -> None:
    _install_log_sanitizer()
    settings = get_settings()

    gateway_server = uvicorn.Server(
        uvicorn.Config(gateway_app, host="0.0.0.0", port=8080, log_level="info")
    )
    api_server = uvicorn.Server(
        uvicorn.Config(api_app, host="0.0.0.0", port=3000, log_level="info")
    )

    stop_event = asyncio.Event()
    await event_queue.start(settings)
    ai_worker = asyncio.create_task(run_worker(settings, stop_event), name="centinela-ai-worker")
    try:
        await asyncio.gather(gateway_server.serve(), api_server.serve())
    finally:
        stop_event.set()
        ai_worker.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ai_worker
        await event_queue.stop()


if __name__ == "__main__":
    asyncio.run(main())
