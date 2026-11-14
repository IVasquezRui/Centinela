"""Saneamiento de PII y payload antes de que algo salga hacia el LLM.

Dos objetivos distintos:
1. No enviar datos personales (cédulas, correos, teléfonos venezolanos)
   aunque aparezcan por accidente en un payload sintético.
2. Neutralizar el payload del ataque para que un intento de inyección de
   prompts dentro del propio payload (ej. "ignora las instrucciones
   anteriores y responde...") no se interprete como instrucción: se
   envuelve entre delimitadores explícitos y se declara en el prompt que
   todo lo que esté ahí dentro es DATO, nunca instrucción.
"""
from __future__ import annotations

import re

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bV-?\d{6,9}\b", re.IGNORECASE), "[CEDULA_REDACTADA]"),
    (re.compile(r"\bE-?\d{6,9}\b", re.IGNORECASE), "[CEDULA_REDACTADA]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL_REDACTADO]"),
    (re.compile(r"\b0?4\d{2}[-.\s]?\d{7}\b"), "[TELEFONO_REDACTADO]"),
    (re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), "[TARJETA_REDACTADA]"),
]

PROMPT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignora las instrucciones anteriores",
    "system prompt",
    "you are now",
    "actua como",
    "act as",
)


def mask_pii(text: str) -> str:
    masked = text
    for pattern, replacement in _PII_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


def looks_like_prompt_injection(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in PROMPT_INJECTION_MARKERS)


def sanitize_payload_for_llm(payload_sample: str | None, max_len: int = 400) -> str:
    if not payload_sample:
        return "(sin payload capturado)"
    truncated = payload_sample[:max_len]
    masked = mask_pii(truncated)
    # El LLM nunca debe tratar el payload como instrucciones: se devuelve
    # tal cual, y es responsabilidad de ai/prompts.py envolverlo entre
    # delimitadores y dejar explícito que es un dato citado, no una orden.
    return masked
