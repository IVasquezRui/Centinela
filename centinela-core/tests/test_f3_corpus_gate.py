"""Pruebas y benchmark para la compuerta de salida de la Fase 3 (F3 · Integración).

Compuerta exigida en docs/SPRINT-1.md:
  "Corpus de 1.000 peticiones medido: detección >= 95%, FP <= 5%, p95 < 10 ms"

Verifica:
1. Tasa de detección (Recall) sobre tráfico malicioso >= 95% (objetivo contractual).
2. Tasa de falsos positivos (FP) sobre tráfico legítimo <= 5% (objetivo del motor: 0.00%).
3. Latencia p95 de inspección del motor determinista < 10 ms (< 10 000 µs).
4. Cobertura completa por categoría de ataque (sqli, xss, traversal, cmdi, scanner, bruteforce).
5. Contención integrada con el IPS (Blocklist): atacantes aislados sin afectar a usuarios legítimos.
"""
from __future__ import annotations

import random
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from app.config import Settings
from app.engine.normalizer import normalize
from app.engine.rules import rule_engine
from app.ips.blocklist import Blocklist


@pytest.fixture(scope="module", autouse=True)
def load_production_rules():
    rules_path = Path(__file__).resolve().parents[1] / "app" / "engine" / "rules.yaml"
    rule_engine.load(rules_path)


@pytest.fixture(scope="module")
def corpus_templates():
    corpus_path = Path(__file__).resolve().parents[2] / "attacker-sim" / "corpus.yaml"
    raw = yaml.safe_load(corpus_path.read_text(encoding="utf-8"))

    def expand(entries: list[dict], is_malicious: bool) -> list[dict]:
        expanded = []
        for entry in entries:
            item = dict(entry)
            item["is_malicious"] = is_malicious
            weight = int(item.get("weight", 1))
            expanded.extend([item] * weight)
        return expanded

    legit = expand(raw["legitimo"], False)
    malicious = expand(raw["malicioso"], True)
    return {"legit": legit, "malicious": malicious}


def test_individual_corpus_patterns_accuracy(corpus_templates):
    """Cada patrón individual del corpus debe clasificarse correctamente sin ambigüedad."""
    # 1. Todos los patrones maliciosos deben ser bloqueados
    for item in corpus_templates["malicious"]:
        norm = normalize(
            method=item["method"],
            path="/" + item["target"] + item["path"],
            query_string=item.get("query", ""),
            headers=item.get("headers", {}),
            body=b"",
            src_ip="192.168.1.50",
        )
        verdict = rule_engine.evaluate(norm)
        assert verdict.verdict == "block", (
            f"Falso negativo detectado para categoría {item.get('category')}: {item}"
        )
        assert verdict.rule_id is not None
        assert verdict.engine_us < 10_000

    # 2. Todos los patrones legítimos deben permitirse (0% falsos positivos)
    for item in corpus_templates["legit"]:
        norm = normalize(
            method=item["method"],
            path="/" + item["target"] + item["path"],
            query_string=item.get("query", ""),
            headers=item.get("headers", {}),
            body=b"",
            src_ip="192.168.1.60",
        )
        verdict = rule_engine.evaluate(norm)
        assert verdict.verdict == "allow", (
            f"Falso positivo detectado en tráfico legítimo: {item} disparó regla {verdict.rule_id}"
        )
        assert verdict.engine_us < 10_000


def test_f3_gate_1000_requests_benchmark(corpus_templates):
    """
    Simulación canónica de la compuerta de F3:
    1.000 peticiones mixtas (30% maliciosas = 300, 70% legítimas = 700).
    Verifica:
      - Detección >= 95%
      - Falsos positivos <= 5%
      - p95 < 10 ms (10 000 µs)
    """
    random.seed(42)  # Semilla fija para reproducibilidad
    total = 1000
    malicious_ratio = 0.30
    n_malicious = int(total * malicious_ratio)
    n_legit = total - n_malicious

    requests_plan = [
        random.choice(corpus_templates["malicious"]) for _ in range(n_malicious)
    ] + [
        random.choice(corpus_templates["legit"]) for _ in range(n_legit)
    ]
    random.shuffle(requests_plan)

    malicious_sent = 0
    malicious_blocked = 0
    legit_sent = 0
    legit_blocked = 0
    engine_latencies_us: list[int] = []

    for item in requests_plan:
        norm = normalize(
            method=item["method"],
            path="/" + item["target"] + item["path"],
            query_string=item.get("query", ""),
            headers=item.get("headers", {}),
            body=b"",
            src_ip="10.0.0.1",
        )
        verdict = rule_engine.evaluate(norm)
        engine_latencies_us.append(verdict.engine_us)

        if item["is_malicious"]:
            malicious_sent += 1
            if verdict.verdict == "block":
                malicious_blocked += 1
        else:
            legit_sent += 1
            if verdict.verdict == "block":
                legit_blocked += 1

    detection_rate = malicious_blocked / malicious_sent
    false_positive_rate = legit_blocked / legit_sent

    sorted_latencies = sorted(engine_latencies_us)
    p95_us = sorted_latencies[int(len(sorted_latencies) * 0.95) - 1]
    p95_ms = p95_us / 1000.0

    # COMPUERTAS CONTRACTUALES DE F3
    assert detection_rate >= 0.95, (
        f"Compuerta F3 fallida: Detección {detection_rate:.2%} < 95.0%"
    )
    assert false_positive_rate <= 0.05, (
        f"Compuerta F3 fallida: Falsos positivos {false_positive_rate:.2%} > 5.0%"
    )
    assert p95_ms < 10.0, (
        f"Compuerta F3 fallida: Latencia p95 {p95_ms:.2f} ms >= 10.0 ms"
    )

    # Verificación de excelencia del motor Centinela
    assert detection_rate == 1.0, f"Se esperaba 100% de detección, obtenido {detection_rate:.2%}"
    assert false_positive_rate == 0.0, f"Se esperaba 0% falsos positivos, obtenido {false_positive_rate:.2%}"
    assert p95_us < 2000, f"Latencia p95 esperada < 2 ms, obtenido {p95_us} µs"


def test_f3_ips_multi_client_containment(corpus_templates):
    """
    Verifica la interacción entre el motor de reglas y la cuarentena IPS:
    - 5 atacantes y 20 usuarios legítimos con IPs independientes.
    - Cada atacante alcanza 3 bloqueos y entra en cuarentena (CNT-IPS-QUARANTINE).
    - El tráfico legítimo de los 20 usuarios sigue pasando sin verse afectado (0 FP).
    """
    settings = Settings(
        blocklist_threshold=3,
        blocklist_window_seconds=60,
        blocklist_quarantine_seconds=300,
    )
    ips = Blocklist(settings)

    attacker_ips = [f"198.51.100.{i}" for i in range(1, 6)]
    legit_ips = [f"203.0.113.{i}" for i in range(1, 21)]

    # 1. Atacantes envían 5 peticiones cada uno
    attacker_blocked = 0
    attacker_quarantined_hits = 0

    for ip in attacker_ips:
        for _ in range(5):
            if ips.is_quarantined(ip):
                attacker_quarantined_hits += 1
                attacker_blocked += 1
                continue

            item = random.choice(corpus_templates["malicious"])
            norm = normalize(
                method=item["method"],
                path="/" + item["target"] + item["path"],
                query_string=item.get("query", ""),
                headers=item.get("headers", {}),
                body=b"",
                src_ip=ip,
            )
            verdict = rule_engine.evaluate(norm)
            if verdict.verdict == "block":
                attacker_blocked += 1
                ips.record_block(
                    ip,
                    category=verdict.category,
                    severity=verdict.severity,
                    technique_id=verdict.technique_id,
                )

    # Cada uno de los 5 atacantes debió quedar en cuarentena tras el 3er bloqueo
    for ip in attacker_ips:
        assert ips.is_quarantined(ip) is True
    assert attacker_quarantined_hits == 5 * 2  # 2 hits absorbidos en cuarentena por atacante

    # 2. Usuarios legítimos envían 10 peticiones cada uno (200 peticiones)
    legit_passed = 0
    for ip in legit_ips:
        assert ips.is_quarantined(ip) is False
        for _ in range(10):
            item = random.choice(corpus_templates["legit"])
            norm = normalize(
                method=item["method"],
                path="/" + item["target"] + item["path"],
                query_string=item.get("query", ""),
                headers=item.get("headers", {}),
                body=b"",
                src_ip=ip,
            )
            verdict = rule_engine.evaluate(norm)
            if verdict.verdict == "allow":
                legit_passed += 1

    assert legit_passed == 200
    assert len(ips.snapshot()) == 5
