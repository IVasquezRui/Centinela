import json
import pytest
from unittest.mock import patch, AsyncMock
import httpx

from app.config import Settings
from app.ai.provider import DeepSeekProvider, build_provider, _parse_llm_json
from app.storage.models import Event


@pytest.fixture
def sample_event():
    return Event(
        id=1,
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


@pytest.mark.asyncio
async def test_worker_fallback_when_api_key_empty(sample_event):
    settings = Settings(deepseek_api_key="")
    provider = build_provider(settings)

    event_dict = {
        "rule_id": sample_event.rule_id,
        "category": sample_event.category,
        "severity": sample_event.severity,
        "technique_id": sample_event.technique_id,
        "target": sample_event.target,
        "path": sample_event.path,
        "payload_sample": sample_event.payload_sample,
    }

    triage = await provider.triage(event_dict)
    sample_event.ai_summary = f"[{triage.source}] {triage.resumen} Mitigación: {triage.mitigacion_sugerida}"
    sample_event.ai_status = "done"

    assert sample_event.ai_status == "done"
    assert triage.source == "fallback_template"
    assert "Se detectó y bloqueó tráfico" in sample_event.ai_summary
    assert "[fallback_template]" in sample_event.ai_summary


@pytest.mark.asyncio
async def test_worker_with_successful_llm_response(sample_event):
    settings = Settings(deepseek_api_key="sk-real-key-simulation")
    provider = build_provider(settings)

    mock_llm_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "resumen": "Intento de inyección SQL mediante manipulación de parámetros booleanos contra el portal tributario.",
                        "severidad_sugerida": "alta",
                        "mitigacion_sugerida": "Implementar consultas preparadas o parametrizadas en el endpoint y mantener la regla en el WAF."
                    })
                }
            }
        ]
    }

    mock_response = httpx.Response(
        status_code=200,
        json=mock_llm_payload,
        request=httpx.Request("POST", "https://api.deepseek.com/chat/completions")
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        event_dict = {
            "rule_id": sample_event.rule_id,
            "category": sample_event.category,
            "severity": sample_event.severity,
            "technique_id": sample_event.technique_id,
            "target": sample_event.target,
            "path": sample_event.path,
            "payload_sample": sample_event.payload_sample,
        }

        triage = await provider.triage(event_dict)
        sample_event.ai_summary = f"[{triage.source}] {triage.resumen} Mitigación: {triage.mitigacion_sugerida}"
        sample_event.ai_status = "done"

    assert sample_event.ai_status == "done"
    assert triage.source == "llm"
    assert "[llm]" in sample_event.ai_summary
    assert "Intento de inyección SQL" in sample_event.ai_summary
    assert "Mitigación: Implementar consultas preparadas" in sample_event.ai_summary


@pytest.mark.asyncio
async def test_worker_fallback_on_api_error_401(sample_event):
    settings = Settings(deepseek_api_key="sk-invalid-key")
    provider = build_provider(settings)

    mock_response = httpx.Response(
        status_code=401,
        content=b"Unauthorized",
        request=httpx.Request("POST", "https://api.deepseek.com/chat/completions")
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        event_dict = {
            "rule_id": sample_event.rule_id,
            "category": sample_event.category,
            "severity": sample_event.severity,
            "technique_id": sample_event.technique_id,
            "target": sample_event.target,
            "path": sample_event.path,
            "payload_sample": sample_event.payload_sample,
        }

        triage = await provider.triage(event_dict)
        sample_event.ai_summary = f"[{triage.source}] {triage.resumen} Mitigación: {triage.mitigacion_sugerida}"
        sample_event.ai_status = "done"

    assert sample_event.ai_status == "done"
    assert triage.source == "fallback_template"
    assert "[fallback_template]" in sample_event.ai_summary
