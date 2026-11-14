"""Casos positivos y negativos por categoría del motor de reglas.

Objetivo de la fase F5 del sprint: evidencia real de precisión del motor
determinista, no solo del modelo ML, antes de la demo.
"""
from __future__ import annotations

import pytest

from app.engine.normalizer import normalize
from app.engine.rules import RuleEngine


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    rule_engine = RuleEngine()
    rule_engine.load()
    return rule_engine


def _request(path: str = "/consulta.php", query: str = "", body: str = ""):
    return normalize(
        method="GET",
        path=path,
        query_string=query,
        headers={},
        body=body.encode("utf-8"),
        src_ip="10.0.0.1",
    )


@pytest.mark.parametrize(
    "query,expected_category",
    [
        ("id=1' OR '1'='1", "sqli"),
        ("id=1 UNION SELECT user,password FROM users", "sqli"),
        ("id=1' AND SLEEP(5)--", "sqli"),
    ],
)
def test_sqli_is_blocked(engine: RuleEngine, query: str, expected_category: str) -> None:
    verdict = engine.evaluate(_request(query=query))
    assert verdict.verdict == "block"
    assert verdict.category == expected_category


@pytest.mark.parametrize(
    "query",
    [
        "comentario=<script>alert(1)</script>",
        "comentario=<img src=x onerror=alert(1)>",
    ],
)
def test_xss_is_blocked(engine: RuleEngine, query: str) -> None:
    verdict = engine.evaluate(_request(query=query))
    assert verdict.verdict == "block"
    assert verdict.category == "xss"


def test_path_traversal_is_blocked(engine: RuleEngine) -> None:
    verdict = engine.evaluate(_request(path="/descargar.php", query="archivo=../../../../etc/passwd"))
    assert verdict.verdict == "block"
    assert verdict.category == "traversal"


def test_command_injection_is_blocked(engine: RuleEngine) -> None:
    verdict = engine.evaluate(_request(query="host=127.0.0.1; cat /etc/passwd"))
    assert verdict.verdict == "block"
    assert verdict.category == "cmdi"


@pytest.mark.parametrize(
    "query",
    [
        "id=42",
        "nombre=Maria%20Perez",
        "monto=150.50&concepto=pago+de+tasa",
    ],
)
def test_legit_traffic_is_allowed(engine: RuleEngine, query: str) -> None:
    verdict = engine.evaluate(_request(query=query))
    assert verdict.verdict == "allow"


def test_double_url_encoding_is_still_caught(engine: RuleEngine) -> None:
    # %2527 -> %27 -> ' tras la doble decodificación del normalizador.
    verdict = engine.evaluate(_request(query="id=1%2527%20OR%20%25271%2527%3D%25271"))
    assert verdict.verdict == "block"
    assert verdict.category == "sqli"
