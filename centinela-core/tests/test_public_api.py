import datetime as dt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.storage.models import Base, Event
from app.api.public import public_router
from fastapi import FastAPI


@pytest_asyncio.fixture
async def app_with_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async_session = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    fastapi_app = FastAPI()
    fastapi_app.include_router(public_router, prefix="/api/public")

    # Reemplazar async_session global de app.api.public
    import app.api.public as pub_mod
    original_session = pub_mod.async_session
    pub_mod.async_session = async_session

    yield fastapi_app, async_session

    pub_mod.async_session = original_session
    await engine.dispose()


@pytest.mark.asyncio
async def test_indicadores_empty_db(app_with_db):
    app, _ = app_with_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/public/indicadores")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incidentes_ultimos_30_dias"] == 0
        assert data["tipo_amenaza_predominante"] is None
        assert data["sector_mas_afectado"] is None
        assert data["severidad_promedio"] is None
        assert data["tendencia"] == "estable"


@pytest.mark.asyncio
async def test_indicadores_with_simulator_volume(app_with_db):
    app, async_session = app_with_db
    now = dt.datetime.now(dt.timezone.utc)

    # Insertar lote mixto simulando el corpus del simulador
    async with async_session() as session:
        # 5 eventos SQLi críticos contra gov-pago
        for i in range(5):
            session.add(Event(
                ts=now, src_ip=f"10.0.0.{i}", method="GET", path="/consulta",
                target="gov-pago", verdict="block", category="sqli",
                severity="critica", engine_us=300
            ))
        # 3 eventos XSS altos contra tickets
        for i in range(3):
            session.add(Event(
                ts=now, src_ip=f"10.0.1.{i}", method="GET", path="/tickets",
                target="tickets", verdict="block", category="xss",
                severity="alta", engine_us=250
            ))
        # 2 eventos permitidos (no deben contar en los indicadores públicos)
        for i in range(2):
            session.add(Event(
                ts=now, src_ip=f"10.0.2.{i}", method="GET", path="/home",
                target="gov-pago", verdict="allow", engine_us=100
            ))
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/public/indicadores")
        assert resp.status_code == 200
        data = resp.json()

        assert data["incidentes_ultimos_30_dias"] == 8
        assert "inyección SQL" in data["tipo_amenaza_predominante"]
        assert data["sector_mas_afectado"] == "gov-pago"
        assert data["severidad_promedio"] in ("alta", "critica")
        assert data["tendencia"] == "al_alza"


@pytest.mark.asyncio
async def test_alertas_publicas_anonymization(app_with_db):
    app, async_session = app_with_db
    now = dt.datetime.now(dt.timezone.utc)

    async with async_session() as session:
        session.add(Event(
            ts=now, src_ip="192.168.1.100", method="POST", path="/admin",
            target="gov-pago", verdict="block", category="cmdi",
            severity="critica", engine_us=400, payload_sample="; cat /etc/shadow"
        ))
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/public/alertas")
        assert resp.status_code == 200
        alertas = resp.json()
        assert len(alertas) == 1
        alerta = alertas[0]
        # Validar anonimización (no expone IP, target ni payload según SDD #40)
        assert "src_ip" not in alerta
        assert "payload" not in alerta
        assert "target" not in alerta
        assert "comandos" in alerta["descripcion"]
        assert alerta["severidad"] == "critica"
