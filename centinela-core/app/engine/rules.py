"""Motor de reglas deterministas.

Se compila una sola vez al arrancar el proceso (RuleEngine.load) y evalúa
cada petición normalizada con un tope de tiempo por regla, para que una
expresión regular patológica nunca pueda convertirse en un DoS del propio
gateway. Esta es la ÚNICA pieza del sistema que decide un bloqueo; el
modelo de ML y el LLM solo añaden contexto después del veredicto.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.engine.normalizer import NormalizedRequest

RULES_PATH = Path(__file__).parent / "rules.yaml"

# Tope de tiempo por regla individual, en segundos. Si una regla lo supera
# se descarta esa regla para esta petición (no se cuelga el gateway) y se
# sigue evaluando el resto.
PER_RULE_TIMEOUT_SECONDS = 0.005


@dataclass(frozen=True)
class CompiledRule:
    id: str
    category: str
    severity: str
    technique_id: str
    description: str
    pattern: re.Pattern[str]
    applies_to: str  # "body" (texto inspeccionable completo) | "headers"


@dataclass
class Verdict:
    verdict: str  # "block" | "allow"
    rule_id: str | None
    category: str | None
    severity: str | None
    technique_id: str | None
    payload_sample: str | None
    engine_us: int


class RuleEngine:
    def __init__(self) -> None:
        self._rules: list[CompiledRule] = []

    def load(self, path: Path = RULES_PATH) -> None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        compiled: list[CompiledRule] = []
        for item in raw["rules"]:
            compiled.append(
                CompiledRule(
                    id=item["id"],
                    category=item["category"],
                    severity=item["severity"],
                    technique_id=item["technique_id"],
                    description=item["description"],
                    pattern=re.compile(item["pattern"]),
                    applies_to=item.get("applies_to", "body"),
                )
            )
        self._rules = compiled

    @property
    def rules(self) -> list[CompiledRule]:
        return self._rules

    def evaluate(self, request: NormalizedRequest) -> Verdict:
        start = time.perf_counter()

        headers_text = "\n".join(f"{k}: {v}" for k, v in request.headers.items())

        for rule in self._rules:
            rule_start = time.perf_counter()
            haystack = headers_text if rule.applies_to == "headers" else request.inspectable_text
            match = rule.pattern.search(haystack)
            if (time.perf_counter() - rule_start) > PER_RULE_TIMEOUT_SECONDS:
                # Regla demasiado costosa para esta petición: se ignora y se
                # continúa, no se bloquea el pipeline por ella.
                continue
            if match:
                engine_us = int((time.perf_counter() - start) * 1_000_000)
                sample = match.group(0)[:200]
                return Verdict(
                    verdict="block",
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    technique_id=rule.technique_id,
                    payload_sample=sample,
                    engine_us=engine_us,
                )

        engine_us = int((time.perf_counter() - start) * 1_000_000)
        return Verdict(
            verdict="allow",
            rule_id=None,
            category=None,
            severity=None,
            technique_id=None,
            payload_sample=None,
            engine_us=engine_us,
        )


rule_engine = RuleEngine()
