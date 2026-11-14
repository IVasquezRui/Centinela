"""Tests de regresión de la Fase 1 de auditoría de seguridad.

Cubre los hallazgos críticos corregidos en esta fase:
1. C1 — ReDoS en CNT-BRUTEFORCE-001: patrón lineal, evaluación en milisegundos.
2. C1 — Presupuesto por regla fail-closed: una regla lenta bloquea con
   CNT-ENGINE-BUDGET en vez de descartarse en silencio (fail-open).
3. C4 — Cuerpo HTTP limitado: el gateway responde 413 + evento de evidencia.
"""
from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

import app.engine.rules as rules_mod
import app.gateway as gateway_mod
from app.engine.normalizer import normalize
from app.engine.rules import RuleEngine


def _norm(query: str = "", body: str = "", headers: dict | None = None):
    return normalize(
        method="GET",
        path="/consulta.php",
        query_string=query,
        headers=headers or {},
        body=body.encode("utf-8"),
        src_ip="10.0.0.1",
    )


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    e = RuleEngine()
    e.load()
    return e


def test_redos_bruteforce_pattern_is_linear(engine: RuleEngine) -> None:
    """El patrón que antes era catastrófico ahora evalúa en milisegundos.

    Antes del arreglo, 'usuario=admin ' repetido disparaba backtracking
    catastrófico en el '.*' de CNT-BRUTEFORCE-001 (27 KiB ~ 977 ms).
    """
    payload = "usuario=admin " * 4000  # ~56 KiB de repetición no coincidente
    norm = _norm(query=payload)

    brute = next(r for r in engine.rules if r.id == "CNT-BRUTEFORCE-001")
    t0 = time.perf_counter()
    match = brute.pattern.search(norm.inspectable_text)
    rule_ms = (time.perf_counter() - t0) * 1000

    assert match is None  # el payload no contiene credenciales por defecto
    assert rule_ms < 10.0, f"CNT-BRUTEFORCE-001 no es lineal: {rule_ms:.2f} ms"

    # El motor completo no debe producir falsos positivos ni colgarse.
    t0 = time.perf_counter()
    verdict = engine.evaluate(norm)
    total_ms = (time.perf_counter() - t0) * 1000
    assert verdict.verdict == "allow"
    assert total_ms < 150.0, f"motor lento: {total_ms:.2f} ms"


def test_engine_budget_is_fail_closed(monkeypatch) -> None:
    """Si una regla excede el presupuesto, el motor bloquea (no descarta).

    Con el presupuesto forzado a 0, la primera regla sin match dispara el
    bloqueo preventivo CNT-ENGINE-BUDGET en vez del antiguo 'continue'.
    """
    monkeypatch.setattr(rules_mod, "PER_RULE_TIMEOUT_SECONDS", 0.0)
    e = RuleEngine()
    e.load()

    verdict = e.evaluate(_norm(query="cedula=V11111111"))

    assert verdict.verdict == "block"
    assert verdict.rule_id == "CNT-ENGINE-BUDGET"
    assert verdict.category == "ips"


@pytest.mark.asyncio
async def test_gateway_rejects_oversized_body(monkeypatch) -> None:
    """El gateway responde 413 y registra el evento al superar MAX_BODY_BYTES."""
    monkeypatch.setattr(gateway_mod, "MAX_BODY_BYTES", 16)

    recorded: list = []

    class FakeQueue:
        async def publish(self, event) -> None:
            recorded.append(event)

    monkeypatch.setattr(gateway_mod, "event_queue", FakeQueue())

    transport = ASGITransport(app=gateway_mod.gateway_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/gov-pago/consulta.php", content=b"A" * 100)

    assert resp.status_code == 413
    assert resp.json()["error"] == "payload_too_large"
    assert len(recorded) == 1
    assert recorded[0].rule_id == "CNT-BODY-TOO-LARGE"
    assert recorded[0].verdict == "block"
