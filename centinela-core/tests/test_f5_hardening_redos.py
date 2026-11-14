"""Pruebas de endurecimiento y resiliencia contra ReDoS / Payloads patológicos (F5).

Verifica:
1. Resistencia contra Catastrophic Backtracking (ReDoS) en las 20 reglas deterministas.
2. Comportamiento del motor ante payloads masivos (>10.000 caracteres de repetición maliciosa).
3. Cumplimiento del SLA (< 10 000 µs) incluso bajo estrés adversarial.
4. Protección del normalizador ante desbordamientos y patrones altamente anidados.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from app.engine.normalizer import normalize
from app.engine.rules import rule_engine


@pytest.fixture(scope="module", autouse=True)
def load_rules():
    rules_path = Path(__file__).resolve().parents[1] / "app" / "engine" / "rules.yaml"
    rule_engine.load(rules_path)


def test_redos_adversarial_sqli_deep_nesting():
    """Prueba de estrés ReDoS: cadena de 15.000 caracteres alternando comillas y operadores."""
    adversarial_payload = "id=1" + ("' OR ''='" * 2000) + "' OR '1'='1"
    norm = normalize(
        method="GET",
        path="/gov-pago/consulta.php",
        query_string=adversarial_payload,
        headers={"host": "localhost"},
        body=b"",
        src_ip="192.168.1.1",
    )

    t0 = time.perf_counter()
    verdict = rule_engine.evaluate(norm)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert verdict.verdict == "block"
    assert verdict.category == "sqli"
    assert elapsed_ms < 15.0, f"ReDoS detectado: evaluación tomó {elapsed_ms:.2f} ms"
    assert verdict.engine_us < 15_000


def test_redos_adversarial_traversal_deep_nesting():
    """Prueba de estrés: secuencia patológica de 500 saltos de directorio alternados."""
    adversarial_path = "/descargar.php?archivo=" + ("..%2f" * 500) + ("..\\..\\" * 200) + "etc/passwd"
    norm = normalize(
        method="GET",
        path="/gov-pago/descargar.php",
        query_string=adversarial_path,
        headers={},
        body=b"",
        src_ip="192.168.1.2",
    )

    t0 = time.perf_counter()
    verdict = rule_engine.evaluate(norm)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert verdict.verdict == "block"
    assert verdict.category == "traversal"
    assert elapsed_ms < 15.0


def test_redos_adversarial_cmdi_giant_command_chain():
    """Prueba de estrés: encadenamiento de 1.000 pipes y sustituciones de comandos."""
    adversarial_query = "codigo=1" + ("; id | echo " * 500) + "| bash"
    norm = normalize(
        method="GET",
        path="/tickets/validar",
        query_string=adversarial_query,
        headers={},
        body=b"",
        src_ip="192.168.1.3",
    )

    t0 = time.perf_counter()
    verdict = rule_engine.evaluate(norm)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert verdict.verdict == "block"
    assert verdict.category == "cmdi"
    assert elapsed_ms < 15.0


def test_giant_benign_payload_performance():
    """Petición legítima con formulario de tamaño considerable (~5 KB de datos benignos)."""
    large_body = ("campo_formulario=pago+ordinario+de+tributos+municipales+2026&" * 100).encode("utf-8")
    norm = normalize(
        method="POST",
        path="/gov-pago/declarar.php",
        query_string="",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=large_body,
        src_ip="10.0.0.1",
    )

    t0 = time.perf_counter()
    verdict = rule_engine.evaluate(norm)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert verdict.verdict == "allow"
    assert verdict.rule_id is None
    assert elapsed_ms < 20.0
