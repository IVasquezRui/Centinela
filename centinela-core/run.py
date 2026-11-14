"""Punto de entrada único del contenedor centinela-core.

Arranca dos servidores Uvicorn en el mismo proceso, uno por cada contrato
congelado en docs/SPRINT-1.md:

- :8080 -> gateway inline (reverse proxy con motor de reglas)
- :3000 -> API del panel SOC y del Observatorio público

Ambos comparten el mismo pool de conexiones a PostgreSQL y la misma cola
en memoria, por eso viven en un solo proceso en vez de dos contenedores.
"""
import asyncio

import uvicorn

from app.api.soc import api_app
from app.config import get_settings
from app.gateway import gateway_app
from app.queue import event_queue


async def main() -> None:
    settings = get_settings()

    gateway_server = uvicorn.Server(
        uvicorn.Config(gateway_app, host="0.0.0.0", port=8080, log_level="info")
    )
    api_server = uvicorn.Server(
        uvicorn.Config(api_app, host="0.0.0.0", port=3000, log_level="info")
    )

    await event_queue.start(settings)
    try:
        await asyncio.gather(gateway_server.serve(), api_server.serve())
    finally:
        await event_queue.stop()


if __name__ == "__main__":
    asyncio.run(main())
