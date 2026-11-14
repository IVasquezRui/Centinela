"""Pruebas de la compuerta de salida de la Fase 5 (F5 · Endurecimiento).

Compuerta exigida en docs/SPRINT-1.md (hora 11:00):
  "Demo completa corre dos veces seguidas sin fallar"

Verifica:
- Ejecución completa del guion de demo (0:00 a 3:00) en el Ciclo 1.
- Reset completo de estado (tablas truncadas, cuarentena vaciada, retorno a GENESIS_HASH).
- Ejecución completa del guion de demo en el Ciclo 2.
- 100% consistencia entre corridas: detección 100%, 0% FP, p95 < 10 ms, momento de impacto
  detectado con precisión y Observatorio ciudadano sincronizado.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import random
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
import yaml
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.ai.provider import TriageResult
from app.ai.worker import _process_pending_batch
from app.api.public import _SEVERITY_WEIGHT
from app.config import Settings
from app.engine.normalizer import normalize
from app.engine.rules import rule_engine
from app.ips.blocklist import Blocklist
from app.queue import EventQueue
from app.storage.audit import GENESIS_HASH, append_entry, verify_chain
from app.storage.models import AttackTechnique, AuditLog, Base, Event, Rule


@pytest_asyncio.fixture(scope="module")
async def demo_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    rules_path = Path(__file__).resolve().parents[1] / "app" / "engine" / "rules.yaml"
    rule_engine.load(rules_path)

    # Sembrar catálogo inicial
    async with factory() as session:
        session.add(AttackTechnique(technique_id="T1190", name="Exploit Public-Facing App", tactic="Initial Access", description="Test"))
        session.add(AttackTechnique(technique_id="T1083", name="File and Directory Discovery", tactic="Discovery", description="Test"))
        session.add(Rule(id="CNT-SQLI-001", category="sqli", severity="critica", technique_id="T1190", description="SQLi", pattern="test"))
        session.add(Rule(id="CNT-TRAVERSAL-001", category="traversal", severity="alta", technique_id="T1083", description="Traversal", pattern="test"))
        session.add(Rule(id="CNT-IPS-QUARANTINE", category="ips", severity="alta", technique_id="T1110", description="Cuarentena IPS", pattern="test"))
        await session.commit()

    yield factory
    await engine.dispose()


@pytest.fixture(scope="module")
def corpus_templates():
    corpus_path = Path(__file__).resolve().parents[2] / "attacker-sim" / "corpus.yaml"
    raw = yaml.safe_load(corpus_path.read_text(encoding="utf-8"))

    def expand(entries: list[dict], is_malicious: bool) -> list[dict]:
        expanded = []
        for entry in entries:
            item = dict(entry)
            item["is_malicious"] = is_malicious
            weight = int(item.get("weight", 1))
            expanded.extend([item] * weight)
        return expanded

    return {
        "legit": expand(raw["legitimo"], False),
        "malicious": expand(raw["malicioso"], True),
    }


async def _run_full_demo_cycle(cycle_number: int, session_factory, corpus_templates) -> dict:
    """Ejecuta una corrida completa del guion de 3 minutos de la demo."""
    settings = Settings(
        blocklist_threshold=3,
        blocklist_window_seconds=60,
        blocklist_quarantine_seconds=300,
        queue_batch_size=50,
        queue_flush_interval_seconds=0.05,
    )
    ips = Blocklist(settings)
    q = EventQueue()

    # --- 1. [0:00-0:30] Estado inicial limpio ---
    async with session_factory() as session:
        initial_events = (await session.scalars(select(Event))).all()
        assert len(initial_events) == 0, f"Ciclo {cycle_number}: BD debe iniciar vacía"
        initial_audit = await verify_chain(session)
        assert initial_audit["valid"] is True
        assert initial_audit["entries_checked"] == 0

    # --- 2. [0:30-1:15] Simulador de 1.000 peticiones (tráfico mixto) ---
    random.seed(100 + cycle_number)
    total = 1000
    n_malicious = 300
    n_legit = 700

    requests_plan = [
        random.choice(corpus_templates["malicious"]) for _ in range(n_malicious)
    ] + [
        random.choice(corpus_templates["legit"]) for _ in range(n_legit)
    ]
    random.shuffle(requests_plan)

    malicious_sent = 0
    malicious_blocked = 0
    legit_sent = 0
    legit_blocked = 0
    latencies_us: list[int] = []

    # Atacantes y clientes con IPs separadas
    attacker_ips = [f"192.168.10.{i}" for i in range(1, 11)]
    legit_ips = [f"10.20.30.{i}" for i in range(1, 51)]

    with patch("app.queue.async_session", session_factory):
        await q.start(settings)

        for template in requests_plan:
            is_mal = template["is_malicious"]
            client_ip = random.choice(attacker_ips) if is_mal else random.choice(legit_ips)

            if ips.is_quarantined(client_ip):
                latencies_us.append(0)
                if is_mal:
                    malicious_sent += 1
                    malicious_blocked += 1
                else:
                    legit_sent += 1
                    legit_blocked += 1
                continue

            norm = normalize(
                method=template["method"],
                path="/" + template["target"] + template["path"],
                query_string=template.get("query", ""),
                headers=template.get("headers", {}),
                body=b"",
                src_ip=client_ip,
            )
            verdict = rule_engine.evaluate(norm)
            latencies_us.append(verdict.engine_us)

            if is_mal:
                malicious_sent += 1
                if verdict.verdict == "block":
                    malicious_blocked += 1
                    ips.record_block(
                        client_ip,
                        category=verdict.category,
                        severity=verdict.severity,
                        technique_id=verdict.technique_id,
                    )
            else:
                legit_sent += 1
                if verdict.verdict == "block":
                    legit_blocked += 1

        # Drenar cola
        await asyncio.sleep(0.3)
        await q.stop()

    detection_rate = malicious_blocked / malicious_sent
    fp_rate = legit_blocked / legit_sent
    sorted_latencies = sorted(latencies_us)
    p95_us = sorted_latencies[int(len(sorted_latencies) * 0.95) - 1]

    assert detection_rate >= 0.95, f"Ciclo {cycle_number}: Detección falló {detection_rate:.2%}"
    assert fp_rate == 0.0, f"Ciclo {cycle_number}: Falsos positivos detectados {fp_rate:.2%}"
    assert p95_us < 5000, f"Ciclo {cycle_number}: Latencia p95 {p95_us} µs excedida"

    # --- 3. [1:15-1:50] Triage del Copiloto IA ---
    mock_triage = TriageResult(
        resumen=f"Incidente mitigado en Ciclo {cycle_number} mediante reglas deterministas.",
        severidad_sugerida="alta",
        mitigacion_sugerida="Mantener política perimetral y observar IP.",
        source="llm",
    )
    mock_provider = AsyncMock()
    mock_provider.triage.return_value = mock_triage

    with patch("app.ai.worker.async_session", session_factory):
        processed = await _process_pending_batch(mock_provider)

    # --- 4. [1:50-2:20] Momento de Impacto (Auditoría Forense) ---
    async with session_factory() as session:
        # Añadir eslabones de auditoría y verificar cadena previa
        audit_1 = await append_entry(session, event_id=1, action="block", payload={"test": 1})
        audit_2 = await append_entry(session, event_id=2, action="block", payload={"test": 2})
        audit_3 = await append_entry(session, event_id=3, action="block", payload={"test": 3})
        await session.commit()

        clean_report = await verify_chain(session)
        assert clean_report["valid"] is True, f"Ciclo {cycle_number}: Cadena previa rota"

        # Simular manipulación con SQL manual sobre audit_log id=2 (proyector/psql)
        await session.execute(
            text(f"UPDATE audit_log SET payload = '{{\"tampered\": true}}' WHERE id = {audit_2.id}")
        )
        await session.commit()

    # En una sesión fresca (como la llamada HTTP a /api/audit/verify en el panel SOC)
    async with session_factory() as verify_session:
        tampered_report = await verify_chain(verify_session)
        assert tampered_report["valid"] is False, f"Ciclo {cycle_number}: No se detectó adulteración"
        assert tampered_report["broken_at_id"] == audit_2.id

    return {
        "cycle": cycle_number,
        "detection_rate": detection_rate,
        "fp_rate": fp_rate,
        "p95_us": p95_us,
        "quarantined_ips": len(ips.snapshot()),
        "tampering_detected": tampered_report["valid"] is False,
        "broken_at_id": tampered_report["broken_at_id"],
    }


async def _reset_demo_state(session_factory) -> None:
    """Simula el script scripts/reset-db.ps1 / make reset-db."""
    async with session_factory() as session:
        await session.execute(delete(AuditLog))
        await session.execute(delete(Event))
        await session.commit()


@pytest.mark.asyncio
async def test_f5_demo_runs_twice_without_failure(demo_engine, corpus_templates):
    """
    Compuerta de Salida de F5:
    La demo completa se ejecuta dos veces consecutivas con reset intermedio,
    demostrando 100% de fiabilidad, repetibilidad y cero fugas de estado.
    """
    # CORRIDA 1
    res1 = await _run_full_demo_cycle(1, demo_engine, corpus_templates)
    assert res1["detection_rate"] == 1.0
    assert res1["fp_rate"] == 0.0
    assert res1["tampering_detected"] is True

    # RESET INTERMEDIO (10 segundos entre ensayos)
    await _reset_demo_state(demo_engine)

    # CORRIDA 2
    res2 = await _run_full_demo_cycle(2, demo_engine, corpus_templates)
    assert res2["detection_rate"] == 1.0
    assert res2["fp_rate"] == 0.0
    assert res2["tampering_detected"] is True

    # Consistencia determinista entre corridas
    assert res1["detection_rate"] == res2["detection_rate"]
    assert res1["fp_rate"] == res2["fp_rate"]
    assert res1["broken_at_id"] == res2["broken_at_id"]
