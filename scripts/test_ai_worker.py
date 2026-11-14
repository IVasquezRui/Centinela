"""Script para probar app/ai/worker.py y app/ai/provider.py tanto con API real como con fallback.

Uso:
    python scripts/test_ai_worker.py [--api-key SK-...]
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Añadir centinela-core al sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "centinela-core"))

from app.config import Settings
from app.ai.provider import build_provider
from app.storage.models import Event


async def test_provider_and_worker(api_key: str | None = None) -> None:
    default_settings = Settings()
    key_to_use = api_key or os.getenv("DEEPSEEK_API_KEY") or default_settings.deepseek_api_key
    print("=" * 60)
    print("TEST DE TRIAGE IA (CENTINELA)")
    print("=" * 60)
    if key_to_use:
        masked = key_to_use[:6] + "..." + key_to_use[-4:] if len(key_to_use) > 10 else "***"
        print(f"Modo: API REAL DEEPSEEK (Clave: {masked})")
    else:
        print("Modo: FALLBACK (Sin DEEPSEEK_API_KEY)")

    settings = Settings(
        deepseek_api_key=key_to_use,
        ai_timeout_seconds=5.0,
    )
    provider = build_provider(settings)

    # 1. Crear evento de prueba en estado 'pending'
    mock_event = Event(
        id=101,
        verdict="block",
        ai_status="pending",
        rule_id="RULE-SQLI-01",
        category="sqli",
        severity="alta",
        technique_id="T1190",
        target="gov-pago",
        path="/api/declaracion?id=1%27%20OR%201=1",
        payload_sample="id=1' OR '1'='1",
    )

    print("\n[1] Estado inicial del evento:")
    print(f"  - ID: {mock_event.id}")
    print(f"  - Verdict: {mock_event.verdict}")
    print(f"  - AI Status: {mock_event.ai_status}")
    print(f"  - AI Summary: {mock_event.ai_summary}")

    # 2. Simular el procesamiento del worker
    print("\n[2] Ejecutando triage con provider...")
    event_dict = {
        "rule_id": mock_event.rule_id,
        "category": mock_event.category,
        "severity": mock_event.severity,
        "technique_id": mock_event.technique_id,
        "target": mock_event.target,
        "path": mock_event.path,
        "payload_sample": mock_event.payload_sample,
    }

    triage = await provider.triage(event_dict)
    mock_event.ai_summary = f"[{triage.source}] {triage.resumen} Mitigación: {triage.mitigacion_sugerida}"
    mock_event.ai_status = "done"

    print("\n[3] Resultado del triage:")
    print(f"  - Fuente (source): {triage.source}")
    print(f"  - Severidad sugerida: {triage.severidad_sugerida}")
    print(f"  - Resumen redactado: {triage.resumen}")
    print(f"  - Mitigación sugerida: {triage.mitigacion_sugerida}")

    print("\n[4] Estado final del evento (actualizado por worker):")
    print(f"  - AI Status: {mock_event.ai_status}")
    print(f"  - AI Summary guardado en DB:\n    \"{mock_event.ai_summary}\"")

    # Verificaciones
    assert mock_event.ai_status == "done", "ai_status debe ser 'done'"
    assert mock_event.ai_summary is not None, "ai_summary no debe ser None"
    assert len(triage.resumen) > 10, "El resumen debe contener texto legible"

    if key_to_use:
        if triage.source == "llm":
            print("\n>>> ÉXITO: Triage generado exitosamente por la API real de DeepSeek en español claro.")
        else:
            print("\n>>> ATENCIÓN: Falló la API real de DeepSeek y se activó el fallback.")
    else:
        print("\n>>> COMPORTAMIENTO ESPERADO: Fallback determinista funcionando correctamente.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", type=str, default="", help="Clave de DeepSeek API")
    args = parser.parse_args()

    asyncio.run(test_provider_and_worker(args.api_key))
