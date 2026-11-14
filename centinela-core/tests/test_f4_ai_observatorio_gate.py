"""Pruebas de integración para la compuerta de salida de la Fase 4 (F4 · IA + Observatorio).

Compuerta exigida en docs/SPRINT-1.md:
  "Alertas con análisis redactado y panel ciudadano visible"

Verifica:
1. El worker de IA (_process_pending_batch) toma eventos en 'pending' con veredicto 'block'
   y los marca como 'done' con un ai_summary redactado.
2. Los eventos 'allow' nunca quedan en 'pending'.
3. /api/public/indicadores calcula con precisión los 5 indicadores agregados (SDD #40).
4. /api/public/alertas traduce categorías técnicas a explicaciones ciudadanas y recomendaciones
   preventivas con anonimización absoluta (sin IPs de origen ni payloads sin sanitizar).
5. Resiliencia ante caídas del copiloto LLM: fallback automático a plantilla determinista.
"""
from __future__ import annotations

import datetime as dt
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.ai.provider import DeepSeekProvider, TriageResult, build_provider
from app.ai.worker import _process_pending_batch
from app.api.public import public_router
from app.config import Settings
from app.storage.models import AttackTechnique, Base, Event, Rule
from fastapi import FastAPI


@pytest_asyncio.fixture
async def f4_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    # Sembrar catálogo básico
    async with factory() as session:
        session.add(AttackTechnique(technique_id="T1190", name="Exploit Public-Facing App", tactic="Initial Access", description="Test"))
        session.add(AttackTechnique(technique_id="T1083", name="File and Directory Discovery", tactic="Discovery", description="Test"))
        session.add(Rule(id="CNT-SQLI-001", category="sqli", severity="critica", technique_id="T1190", description="SQLi", pattern="test"))
        session.add(Rule(id="CNT-TRAVERSAL-001", category="traversal", severity="alta", technique_id="T1083", description="Traversal", pattern="test"))
        await session.commit()

    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_ai_worker_processes_pending_blocks(f4_db):
    """El worker de IA procesa eventos en 'pending' y actualiza ai_summary y ai_status a 'done'."""
    now = dt.datetime.now(dt.timezone.utc)
    async with f4_db() as session:
        session.add(Event(
            ts=now, src_ip="172.20.0.9", method="GET", path="/gov-pago/consulta.php",
            target="gov-pago", verdict="block", rule_id="CNT-SQLI-001",
            category="sqli", severity="critica", technique_id="T1190",
            engine_us=1200, payload_sample="id=1' OR '1'='1",
            ai_status="pending", ai_summary=None
        ))
        session.add(Event(
            ts=now, src_ip="172.20.0.10", method="GET", path="/gov-pago/inicio",
            target="gov-pago", verdict="allow", rule_id=None,
            category=None, severity=None, technique_id=None,
            engine_us=80, payload_sample=None,
            ai_status="done", ai_summary=None
        ))
        await session.commit()

    # Ejecutar worker con provider en fallback
    settings = Settings(deepseek_api_key="")
    provider = build_provider(settings)

    with patch("app.ai.worker.async_session", f4_db):
        processed = await _process_pending_batch(provider)

    assert processed == 1

    async with f4_db() as session:
        events = (await session.scalars(select(Event).order_by(Event.id))).all()
        block_event = events[0]
        allow_event = events[1]

        assert block_event.ai_status == "done"
        assert block_event.ai_summary is not None
        assert "[fallback_template]" in block_event.ai_summary
        assert "Mitigación:" in block_event.ai_summary

        assert allow_event.ai_status == "done"
        assert allow_event.ai_summary is None


@pytest.mark.asyncio
async def test_ai_worker_with_simulated_llm(f4_db):
    """Verifica enriquecimiento táctico cuando la API de DeepSeek responde exitosamente."""
    now = dt.datetime.now(dt.timezone.utc)
    async with f4_db() as session:
        session.add(Event(
            ts=now, src_ip="192.168.1.100", method="GET", path="/tickets/comprobante",
            target="tickets", verdict="block", rule_id="CNT-TRAVERSAL-001",
            category="traversal", severity="alta", technique_id="T1083",
            engine_us=950, payload_sample="archivo=../../../../etc/passwd",
            ai_status="pending", ai_summary=None
        ))
        await session.commit()

    mock_result = TriageResult(
        resumen="Intento de exfiltración de archivos del sistema mediante salto de directorio.",
        severidad_sugerida="alta",
        mitigacion_sugerida="Restringir permisos de lectura en el servidor y validar canonicidad de rutas.",
        source="llm",
    )

    mock_provider = AsyncMock()
    mock_provider.triage.return_value = mock_result

    with patch("app.ai.worker.async_session", f4_db):
        processed = await _process_pending_batch(mock_provider)

    assert processed == 1

    async with f4_db() as session:
        event = (await session.scalars(select(Event).where(Event.category == "traversal"))).first()
        assert event.ai_status == "done"
        assert "[llm]" in event.ai_summary
        assert "salto de directorio" in event.ai_summary
        assert "Restringir permisos" in event.ai_summary


@pytest.mark.asyncio
async def test_observatorio_public_api_anonymization_and_indicators(f4_db):
    """
    Verifica que la API pública del Observatorio (/api/public/indicadores y /api/public/alertas)
    entregue indicadores agregados y alertas en lenguaje ciudadano sin exponer IPs ni payloads.
    """
    now = dt.datetime.now(dt.timezone.utc)
    async with f4_db() as session:
        # Añadir 3 incidentes bloqueados con distintas categorías
        session.add(Event(
            ts=now, src_ip="10.0.0.5", method="GET", path="/gov-pago/consulta.php",
            target="gov-pago", verdict="block", rule_id="CNT-SQLI-001",
            category="sqli", severity="critica", technique_id="T1190",
            engine_us=400, payload_sample="1' OR 1=1",
            ai_status="done", ai_summary="[llm] Intento SQLi detectado."
        ))
        session.add(Event(
            ts=now, src_ip="10.0.0.6", method="GET", path="/gov-pago/descargar.php",
            target="gov-pago", verdict="block", rule_id="CNT-TRAVERSAL-001",
            category="traversal", severity="alta", technique_id="T1083",
            engine_us=300, payload_sample="../../etc/passwd",
            ai_status="done", ai_summary="[llm] Intento Traversal detectado."
        ))
        session.add(Event(
            ts=now, src_ip="10.0.0.7", method="GET", path="/gov-pago/login",
            target="gov-pago", verdict="block", rule_id="CNT-SQLI-001",
            category="sqli", severity="critica", technique_id="T1190",
            engine_us=350, payload_sample="admin' --",
            ai_status="done", ai_summary="[llm] Intento SQLi detectado."
        ))
        await session.commit()

    with patch("app.api.public.async_session", f4_db):
        test_app = FastAPI()
        test_app.include_router(public_router, prefix="/api/public")
        transport = ASGITransport(app=test_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Verificar /api/public/indicadores
            res_ind = await client.get("/api/public/indicadores")
            assert res_ind.status_code == 200
            data_ind = res_ind.json()

            assert data_ind["incidentes_ultimos_30_dias"] == 3
            assert "inyección SQL" in data_ind["tipo_amenaza_predominante"]
            assert data_ind["sector_mas_afectado"] == "gov-pago"
            assert data_ind["severidad_promedio"] in {"alta", "critica"}
            assert data_ind["tendencia"] in {"al_alza", "estable"}

            # Verificación de privacidad: ningún campo sensible expuesto
            for sensitive_key in ("src_ip", "payload_sample", "rule_id", "technique_id"):
                assert sensitive_key not in data_ind

            # 2. Verificar /api/public/alertas
            res_alertas = await client.get("/api/public/alertas")
            assert res_alertas.status_code == 200
            alertas = res_alertas.json()
            assert len(alertas) == 3

            for alerta in alertas:
                assert "fecha" in alerta
                assert "descripcion" in alerta
                assert "severidad" in alerta
                assert "recomendacion" in alerta

                # Lenguaje ciudadano sin tecnicismos
                assert "inyección" in alerta["descripcion"] or "archivos" in alerta["descripcion"]
                assert "Mantén" in alerta["recomendacion"] or "valida" in alerta["recomendacion"]

                # Privacidad absoluta
                assert "src_ip" not in alerta
                assert "payload_sample" not in alerta
                assert "10.0.0" not in str(alerta)
