"""Cuarentena de IPs (modo IPS).

Regla: 3 detecciones (verdict=block) de la misma IP en 60 segundos ->
cuarentena de 5 minutos. Mientras una IP está en cuarentena, el gateway
responde 403 inmediatamente, sin ni siquiera evaluar las reglas de nuevo.

Implementación en memoria del proceso: suficiente para un sprint de 12
horas con un solo contenedor del gateway; migrar a un store compartido
(Redis) es trabajo de Sprint 2+ si se escala a múltiples réplicas.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from app.config import Settings


class Blocklist:
    def __init__(self, settings: Settings) -> None:
        self._threshold = settings.blocklist_threshold
        self._window_seconds = settings.blocklist_window_seconds
        self._quarantine_seconds = settings.blocklist_quarantine_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._quarantined_until: dict[str, float] = {}

    def is_quarantined(self, ip: str) -> bool:
        until = self._quarantined_until.get(ip)
        if until is None:
            return False
        if time.monotonic() >= until:
            del self._quarantined_until[ip]
            return False
        return True

    def quarantined_until(self, ip: str) -> float | None:
        return self._quarantined_until.get(ip)

    def record_block(self, ip: str) -> bool:
        """Registra una detección bloqueada para `ip`.

        Devuelve True si esta detección acaba de disparar la cuarentena.
        """
        now = time.monotonic()
        hits = self._hits[ip]
        hits.append(now)
        cutoff = now - self._window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()

        if len(hits) >= self._threshold and ip not in self._quarantined_until:
            self._quarantined_until[ip] = now + self._quarantine_seconds
            return True
        return False

    def snapshot(self) -> list[dict]:
        now = time.monotonic()
        return [
            {"ip": ip, "quarantined_for_seconds": max(0, int(until - now))}
            for ip, until in self._quarantined_until.items()
            if until > now
        ]


blocklist = Blocklist(Settings())
