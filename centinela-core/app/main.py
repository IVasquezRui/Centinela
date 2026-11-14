"""Alias de conveniencia para tooling (tests, ASGI servers) que espera
encontrar las apps en app.main en vez de en sus módulos de origen.

Los objetos reales viven en:
  - app.gateway:gateway_app  (puerto 8080, reverse proxy inline)
  - app.api.soc:api_app      (puerto 3000, API SOC/Observatorio)

El arranque de producción del contenedor es run.py, no este módulo.
"""
from app.api.soc import api_app
from app.gateway import gateway_app

__all__ = ["api_app", "gateway_app"]
