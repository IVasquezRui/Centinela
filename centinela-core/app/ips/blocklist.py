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
        # Último bloqueo observado por IP: la cuarentena no vuelve a evaluar
        # reglas, así que sin esto el evento de cuarentena perdería la causa
        # real (SQLi, traversal, etc.) y se etiquetaría como genérico.
        self._last_block: dict[str, dict] = {}

    def last_block_context(self, ip: str) -> dict:
        return self._last_block.get(
            ip, {"category": None, "severity": "alta", "technique_id": None}
        )

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

    def record_block(
        self,
        ip: str,
        *,
        category: str | None = None,
        severity: str | None = None,
        technique_id: str | None = None,
    ) -> bool:
        """Registra una detección bloqueada para `ip`.

        Devuelve True si esta detección acaba de disparar la cuarentena.
        """
        now = time.monotonic()
        self._last_block[ip] = {
            "category": category,
            "severity": severity or "alta",
            "technique_id": technique_id,
        }
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
        cutoff = now - self._window_seconds
        # Purga cuarentenas expiradas y detecciones antiguas (memoria acotada):
        # sin esto, IPs que dejaron de verse mantienen entradas para siempre.
        for ip in [ip for ip, until in self._quarantined_until.items() if until <= now]:
            del self._quarantined_until[ip]
        for ip, hits in list(self._hits.items()):
            while hits and hits[0] < cutoff:
                hits.popleft()
            if not hits:
                del self._hits[ip]
                self._last_block.pop(ip, None)
        return [
            {"ip": ip, "quarantined_for_seconds": max(0, int(until - now))}
            for ip, until in self._quarantined_until.items()
            if until > now
        ]


blocklist = Blocklist(Settings())
