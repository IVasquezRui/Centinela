"""Generador de tráfico mixto (legítimo + malicioso) contra el gateway.

Uso:
    python sim.py --total 1000 --malicious-ratio 0.3

Todas las peticiones pasan por el gateway inline de CENTINELA (nunca
directo a los objetivos, que no publican puertos). El resultado impreso al
final es el mismo tipo de medición que exige la compuerta de F3 en
docs/SPRINT-1.md: cuántas maliciosas fueron bloqueadas (recall) y cuántas
legítimas fueron bloqueadas por error (falsos positivos).

Los bloqueos se separan por origen, porque un 403 puede venir de dos sitios:

- el motor de reglas (precisión del motor, es la métrica de FP de F3);
- la cuarentena del IPS, que aísla al host completo y por diseño también
  corta su tráfico legítimo (se reporta aparte como contención).
"""
from __future__ import annotations

import argparse
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml

CORPUS_PATH = Path(__file__).parent / "corpus.yaml"

# rule_id con el que el gateway marca los 403 emitidos por la cuarentena del IPS
# (app/ips/blocklist.py) en vez de por el motor de reglas.
IPS_QUARANTINE_RULE = "CNT-IPS-QUARANTINE"


@dataclass
class Template:
    method: str
    target: str
    path: str
    query: str
    category: str | None
    headers: dict[str, str]
    is_malicious: bool


def load_templates() -> tuple[list[Template], list[Template]]:
    raw = yaml.safe_load(CORPUS_PATH.read_text(encoding="utf-8"))

    def expand(entries: list[dict], malicious: bool) -> list[Template]:
        expanded: list[Template] = []
        for entry in entries:
            template = Template(
                method=entry["method"],
                target=entry["target"],
                path=entry["path"],
                query=entry.get("query", ""),
                category=entry.get("category"),
                headers=entry.get("headers", {}),
                is_malicious=malicious,
            )
            expanded.extend([template] * int(entry.get("weight", 1)))
        return expanded

    return expand(raw["legitimo"], False), expand(raw["malicioso"], True)


def run(total: int, malicious_ratio: float, gateway_url: str, delay_ms: int, rotate_ips: bool = False) -> None:
    legit_pool, malicious_pool = load_templates()

    n_malicious = int(total * malicious_ratio)
    n_legit = total - n_malicious

    requests_plan = (
        [random.choice(malicious_pool) for _ in range(n_malicious)]
        + [random.choice(legit_pool) for _ in range(n_legit)]
    )
    random.shuffle(requests_plan)

    stats = {
        "total": 0,
        "malicious_sent": 0,
        "malicious_blocked": 0,
        "malicious_rule_blocked": 0,
        "malicious_quarantine": 0,
        "legit_sent": 0,
        "legit_blocked": 0,
        "legit_rule_blocked": 0,
        "legit_quarantine": 0,
        "latencies_ms": [],
        "quarantine_first_index": None,
    }

    with httpx.Client(timeout=5.0) as client:
        for template in requests_plan:
            url = f"{gateway_url}/{template.target}{template.path}"
            start = time.perf_counter()
            rule_id: str | None = None
            headers = dict(template.headers)
            if rotate_ips:
                headers["x-forwarded-for"] = f"172.20.0.{random.randint(10, 250)}"
            try:
                response = client.request(
                    template.method,
                    url,
                    params=_parse_query(template.query),
                    headers=headers,
                )
                blocked = response.status_code == 403
                if blocked:
                    rule_id = _blocked_rule_id(response)
            except httpx.HTTPError:
                blocked = False

            elapsed_ms = (time.perf_counter() - start) * 1000
            stats["latencies_ms"].append(elapsed_ms)
            stats["total"] += 1

            # El IPS responde igual (403) que el motor de reglas, pero por una
            # razón distinta: la IP está aislada y la petición ni se evalúa. Se
            # separan para no atribuir a las reglas falsos positivos que en
            # realidad son contención del host.
            quarantined = rule_id == IPS_QUARANTINE_RULE

            if template.is_malicious:
                stats["malicious_sent"] += 1
                if blocked:
                    stats["malicious_blocked"] += 1
                    if quarantined:
                        stats["malicious_quarantine"] += 1
                    else:
                        stats["malicious_rule_blocked"] += 1
            else:
                stats["legit_sent"] += 1
                if blocked:
                    stats["legit_blocked"] += 1
                    if quarantined:
                        stats["legit_quarantine"] += 1
                    else:
                        stats["legit_rule_blocked"] += 1

            if quarantined and stats["quarantine_first_index"] is None:
                stats["quarantine_first_index"] = stats["total"]

            if delay_ms:
                time.sleep(delay_ms / 1000)

    _print_report(stats)


def _blocked_rule_id(response: httpx.Response) -> str | None:
    """Lee el cuerpo 403 del gateway para clasificar el bloqueo.

    Un 403 puede venir del motor de reglas (trae rule_id) o de la cuarentena del
    IPS (trae error="ip_quarantined"), y esa distinción es la que separa la
    precisión del motor de la contención del host.
    """
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict) and body.get("error") == "ip_quarantined":
        return IPS_QUARANTINE_RULE
    rule_id = body.get("rule_id") if isinstance(body, dict) else None
    return rule_id if isinstance(rule_id, str) else None


def _parse_query(query: str) -> dict[str, str]:
    if not query:
        return {}
    pairs = [p.split("=", 1) for p in query.split("&") if "=" in p]
    return {k: v for k, v in pairs}


def _print_report(stats: dict) -> None:
    latencies = sorted(stats["latencies_ms"])
    p95 = latencies[int(len(latencies) * 0.95) - 1] if latencies else 0

    detection_rate = (
        stats["malicious_blocked"] / stats["malicious_sent"] if stats["malicious_sent"] else 0
    )
    rule_false_positive_rate = (
        stats["legit_rule_blocked"] / stats["legit_sent"] if stats["legit_sent"] else 0
    )
    total_false_positive_rate = (
        stats["legit_blocked"] / stats["legit_sent"] if stats["legit_sent"] else 0
    )

    print("--- Corpus de simulación CENTINELA ---")
    print(f"Total de peticiones enviadas: {stats['total']}")
    print(
        f"Maliciosas enviadas / bloqueadas: {stats['malicious_sent']} / "
        f"{stats['malicious_blocked']} (por regla: {stats['malicious_rule_blocked']}, "
        f"por cuarentena IPS: {stats['malicious_quarantine']})"
    )
    print(
        f"Legítimas enviadas / bloqueadas: {stats['legit_sent']} / "
        f"{stats['legit_blocked']} (por regla: {stats['legit_rule_blocked']}, "
        f"por cuarentena IPS: {stats['legit_quarantine']})"
    )
    print(f"Tasa de detección: {detection_rate:.2%} (objetivo SDD #23: >= 95%)")
    print(
        f"Tasa de falsos positivos del motor de reglas: {rule_false_positive_rate:.2%} "
        "(objetivo SDD #23: <= 5%)"
    )
    print(
        "Tasa de falsos positivos total (incluye cuarentena IPS): "
        f"{total_false_positive_rate:.2%}"
    )

    absorbed = stats["malicious_quarantine"] + stats["legit_quarantine"]
    if stats["quarantine_first_index"] is not None:
        print(
            f"Contención IPS: la cuarentena se activó en la petición "
            f"#{stats['quarantine_first_index']} y absorbió {absorbed} peticiones "
            "del mismo origen."
        )
        print(
            "  Nota: el simulador sale por una sola IP, así que el IPS ve un único "
            "host y aísla su tráfico completo (legítimo incluido). El FP 'por regla' "
            "mide la precisión del motor; el total incluye esta contención deliberada."
        )
    print(f"Latencia p95 (end-to-end, incluye red): {p95:.2f} ms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--total", type=int, default=1000)
    parser.add_argument("--malicious-ratio", type=float, default=0.3)
    parser.add_argument(
        "--gateway-url", default=os.environ.get("GATEWAY_URL", "http://localhost:8080")
    )
    parser.add_argument("--delay-ms", type=int, default=0, help="Pausa entre peticiones, en ms")
    parser.add_argument(
        "--rotate-ips",
        action="store_true",
        help="Simula peticiones desde un pool distribuido de IPs usando X-Forwarded-For",
    )
    args = parser.parse_args()

    run(args.total, args.malicious_ratio, args.gateway_url, args.delay_ms, args.rotate_ips)
