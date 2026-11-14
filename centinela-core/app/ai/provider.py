"""Interfaz LLMProvider intercambiable + implementación DeepSeek.

`LLMProvider` es la única abstracción que el resto del código conoce,
precisamente para no acoplar CENTINELA a DeepSeek: cambiar de proveedor de
IA en el futuro significa escribir otra clase que implemente `triage()`,
no tocar gateway.py, worker.py ni la base de datos.

Salida validada contra un esquema cerrado, timeout corto y *fallback* a
una plantilla determinista si el proveedor falla, tarda o responde algo
que no es JSON válido. La plataforma sigue funcionando sin IA.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from app.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from app.ai.sanitizer import looks_like_prompt_injection, sanitize_payload_for_llm
from app.config import Settings

logger = logging.getLogger("centinela.ai")

VALID_SEVERITIES = {"baja", "media", "alta", "critica"}


@dataclass
class TriageResult:
    resumen: str
    severidad_sugerida: str
    mitigacion_sugerida: str
    source: str  # "llm" | "fallback_template"


class LLMProvider(ABC):
    @abstractmethod
    async def triage(self, event: dict) -> TriageResult:
        ...


def _fallback_template(event: dict) -> TriageResult:
    category = event.get("category") or "actividad sospechosa"
    severity = event.get("severity") or "media"
    return TriageResult(
        resumen=(
            f"Se detectó y bloqueó tráfico de tipo '{category}' contra "
            f"{event.get('target', 'un objetivo')} mediante la regla "
            f"{event.get('rule_id', 'desconocida')}."
        ),
        severidad_sugerida=severity if severity in VALID_SEVERITIES else "media",
        mitigacion_sugerida=(
            "Revisar el origen de la petición y mantener la IP en observación; "
            "la regla determinista ya bloqueó el intento."
        ),
        source="fallback_template",
    )


def _parse_llm_json(raw_text: str, event: dict) -> TriageResult:
    data = json.loads(raw_text)
    # El LLM puede devolver una lista, un string o null: sin esta comprobación
    # data["resumen"] lanzaría TypeError (no capturado) y el evento quedaría
    # en 'pending' reintentándose para siempre (livelock).
    if not isinstance(data, dict):
        raise ValueError(f"respuesta del LLM no es un objeto JSON: {type(data).__name__}")
    for key in ("resumen", "severidad_sugerida", "mitigacion_sugerida"):
        if key not in data:
            raise ValueError(f"respuesta del LLM sin la clave {key!r}")
    resumen = str(data["resumen"])[:500]
    severidad = str(data["severidad_sugerida"]).lower()
    mitigacion = str(data["mitigacion_sugerida"])[:500]

    if severidad not in VALID_SEVERITIES:
        raise ValueError(f"severidad_sugerida fuera de esquema: {severidad!r}")

    return TriageResult(
        resumen=resumen,
        severidad_sugerida=severidad,
        mitigacion_sugerida=mitigacion,
        source="llm",
    )


class DeepSeekProvider(LLMProvider):
    """Cliente mínimo para la API de DeepSeek (compatible con el formato OpenAI)."""

    def __init__(self, settings: Settings) -> None:
        self._api_key = settings.deepseek_api_key
        self._base_url = settings.deepseek_api_base.rstrip("/")
        self._model = settings.deepseek_model
        self._timeout = settings.ai_timeout_seconds

    async def triage(self, event: dict) -> TriageResult:
        if not self._api_key:
            logger.warning("DEEPSEEK_API_KEY vacío: se usa la plantilla de respaldo")
            return _fallback_template(event)

        sanitized_payload = sanitize_payload_for_llm(event.get("payload_sample"))
        if looks_like_prompt_injection(sanitized_payload):
            logger.warning("Payload con marcadores de prompt injection: se usa la plantilla")
            return _fallback_template(event)
        user_prompt = build_user_prompt(event, sanitized_payload)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json={
                        "model": self._model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"},
                    },
                )
                response.raise_for_status()
                body = response.json()
                raw_text = body["choices"][0]["message"]["content"]
                return _parse_llm_json(raw_text, event)
        except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError):
            logger.exception("Fallo en el triage de DeepSeek, se usa la plantilla de respaldo")
            return _fallback_template(event)


def build_provider(settings: Settings) -> LLMProvider:
    return DeepSeekProvider(settings)
