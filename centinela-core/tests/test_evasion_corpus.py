"""Tests de regresión de la Fase 2 — evasión del motor y cabeceras.

Verifica que los payloads que antes evadían el motor (C3 de la auditoría)
ahora se bloquean, y que el tráfico legítimo con cabeceras estándar no
genera falsos positivos.
"""
from __future__ import annotations

import pytest

from app.engine.normalizer import normalize
from app.engine.rules import RuleEngine

# backslash, para construir el caso de escape JSON sin backslashes literales
BS = chr(92)


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    e = RuleEngine()
    e.load()
    return e


def _req(query: str = "", headers: dict | None = None, path: str = "/consulta.php"):
    return normalize(
        method="GET",
        path=path,
        query_string=query,
        headers=headers or {},
        body=b"",
        src_ip="10.0.0.1",
    )


# Los 11 casos de evasión confirmados en la auditoría (C3) + 3 por cabecera.
@pytest.mark.parametrize(
    "name,query,headers",
    [
        ("tautologia a=a", "cedula=1' OR 'a'='a", None),
        ("union all select", "cedula=1' union all select 1,2,3,4-- -", None),
        ("or 2=2 comentario", "cedula=1' OR 2=2-- -", None),
        ("subconsulta bool", "cedula=1' AND (SELECT 1)=(SELECT 1)-- -", None),
        ("or true", "cedula=1' OR true-- -", None),
        ("sleep sin parentesis", "codigo=;sleep 5", None),
        ("echo ejecucion", "codigo=;echo pwned", None),
        ("python3 -c", "codigo=;python3 -c import os", None),
        ("cat con IFS", "codigo=;cat${IFS}/etc/passwd", None),
        ("union tab encoding", "cedula=1' union%09all%09select 1", None),
        ("escape JSON unicode", "cedula=1' OR " + BS + "u0061'=" + BS + "u0061", None),
        ("sqli en cabecera", "cedula=V1", {"X-Perfil": "1' OR '1'='1"}),
        ("xss en cabecera", "c=1", {"X-Test": "<script>alert(1)</script>"}),
        ("traversal en cabecera", "c=1", {"X-Test": "../../etc/passwd"}),
    ],
)
def test_evasiones_son_bloqueadas(engine, name, query, headers):
    verdict = engine.evaluate(_req(query=query, headers=headers))
    assert verdict.verdict == "block", f"evasión no bloqueada: {name}"
    assert verdict.rule_id is not None


def test_trafico_legitimo_con_cabeceras_no_genera_fp(engine):
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    for query in [
        "cedula=V11111111",
        "nombre=Maria Perez",
        "codigo=ABC123",
        "archivo=recibo_0001.txt",
    ]:
        verdict = engine.evaluate(_req(query=query, headers=ua))
        assert verdict.verdict == "allow", f"FP en tráfico legítimo: {query}"
