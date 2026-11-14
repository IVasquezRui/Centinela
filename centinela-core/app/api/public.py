"""API pública del Observatorio — /api/public/*.

Regla de diseño del Observatorio (SDD #40): sin autenticación, sin datos
personales ni identificadores directos de víctimas, en lenguaje claro.
Todo lo que se expone aquí son agregados calculados sobre `event`; nunca
se expone src_ip, payload_sample ni ningún campo que identifique a una
víctima o atacante concretos.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter
from sqlalchemy import func, select

from app.storage.db import async_session
from app.storage.models import Event

public_router = APIRouter()

_SEVERITY_WEIGHT = {"baja": 1, "media": 2, "alta": 3, "critica": 4}

_CATEGORY_LABEL_CLARO = {
    "sqli": "Intentos de manipular bases de datos (inyección SQL)",
    "xss": "Intentos de insertar código malicioso en páginas web",
    "traversal": "Intentos de leer archivos no autorizados del servidor",
    "cmdi": "Intentos de ejecutar comandos no autorizados",
    "scanner": "Escaneos automatizados en busca de puntos débiles",
    "bruteforce": "Intentos repetidos de adivinar contraseñas",
}

_RECOMENDACION_CLARO = {
    "sqli": "Si administras un sistema, valida y filtra siempre los datos que vienen de formularios.",
    "xss": "Evita pegar código de fuentes no confiables en campos de texto de sitios web.",
    "traversal": "Mantén actualizado el software de tus servidores y restringe el acceso a archivos sensibles.",
    "cmdi": "No ejecutes comandos sugeridos por fuentes desconocidas en tus sistemas.",
    "scanner": "Revisa periódicamente los registros de acceso de tus servidores.",
    "bruteforce": "Usa contraseñas fuertes y activa el bloqueo tras varios intentos fallidos.",
}


@public_router.get("/indicadores")
async def indicadores() -> dict:
    """Los 5 indicadores agregados que exige el SDD #40."""
    async with async_session() as session:
        since_30_days = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)

        incidentes_mes = await session.scalar(
            select(func.count(Event.id)).where(
                Event.verdict == "block", Event.ts >= since_30_days
            )
        ) or 0

        categoria_predominante_row = (
            await session.execute(
                select(Event.category, func.count(Event.id).label("total"))
                .where(Event.verdict == "block")
                .group_by(Event.category)
                .order_by(func.count(Event.id).desc())
                .limit(1)
            )
        ).first()

        sector_mas_afectado_row = (
            await session.execute(
                select(Event.target, func.count(Event.id).label("total"))
                .where(Event.verdict == "block")
                .group_by(Event.target)
                .order_by(func.count(Event.id).desc())
                .limit(1)
            )
        ).first()

        severidades = (
            await session.scalars(
                select(Event.severity).where(Event.verdict == "block", Event.severity.is_not(None))
            )
        ).all()

        severidad_promedio = None
        if severidades:
            promedio_num = sum(_SEVERITY_WEIGHT.get(s, 0) for s in severidades) / len(severidades)
            severidad_promedio = min(
                _SEVERITY_WEIGHT, key=lambda s: abs(_SEVERITY_WEIGHT[s] - promedio_num)
            )

        since_60_days = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60)
        incidentes_periodo_anterior = await session.scalar(
            select(func.count(Event.id)).where(
                Event.verdict == "block",
                Event.ts >= since_60_days,
                Event.ts < since_30_days,
            )
        ) or 0

        if incidentes_periodo_anterior == 0:
            tendencia = "estable" if incidentes_mes == 0 else "al_alza"
        else:
            variacion = (incidentes_mes - incidentes_periodo_anterior) / incidentes_periodo_anterior
            if variacion > 0.1:
                tendencia = "al_alza"
            elif variacion < -0.1:
                tendencia = "a_la_baja"
            else:
                tendencia = "estable"

    return {
        "incidentes_ultimos_30_dias": incidentes_mes,
        "tipo_amenaza_predominante": (
            _CATEGORY_LABEL_CLARO.get(categoria_predominante_row[0], categoria_predominante_row[0])
            if categoria_predominante_row
            else None
        ),
        "sector_mas_afectado": sector_mas_afectado_row[0] if sector_mas_afectado_row else None,
        "severidad_promedio": severidad_promedio,
        "tendencia": tendencia,
    }


@public_router.get("/alertas")
async def alertas(limit: int = 20) -> list[dict]:
    """Alertas recientes en lenguaje ciudadano, sin datos que identifiquen a nadie."""
    async with async_session() as session:
        rows = (
            await session.scalars(
                select(Event)
                .where(Event.verdict == "block")
                .order_by(Event.id.desc())
                .limit(limit)
            )
        ).all()

    return [
        {
            "fecha": row.ts.date().isoformat(),
            "descripcion": _CATEGORY_LABEL_CLARO.get(row.category, "Actividad sospechosa detectada"),
            "severidad": row.severity,
            "recomendacion": _RECOMENDACION_CLARO.get(row.category, "Mantén tus sistemas actualizados."),
        }
        for row in rows
    ]
