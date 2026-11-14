"""Gateway inline: punto 8080, único camino de entrada a los objetivos.

Los contenedores vulnerables (gov-pago, tickets) no publican puertos; solo
son alcanzables a través de aquí. El enrutamiento es por prefijo de ruta:

    /gov-pago/...  -> TARGET_GOV_PAGO_URL (prefijo recortado)
    /tickets/...   -> TARGET_TICKETS_URL  (prefijo recortado)

Orden de decisión por petición:
  1. IP en cuarentena -> 403 inmediato, ni se evalúan las reglas de nuevo.
  2. Normalizar petición.
  3. Motor de reglas (determinista) -> BLOCK o ALLOW. Esta es la única
     fuente de verdad del veredicto; nada más en el sistema puede bloquear.
  4. BLOCK -> 403 y el evento se encola para auditoría; la petición NUNCA
     llega al objetivo.
  5. ALLOW -> se reenvía la petición tal cual al objetivo correspondiente.

El scoring de ML (engine/ml.py) ocurre después del veredicto y nunca lo
cambia: solo enriquece el evento que se persiste.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import time

import httpx
from fastapi import FastAPI, Request, Response

from app.config import get_settings
from app.engine.normalizer import normalize
from app.engine.rules import rule_engine
from app.ips.blocklist import blocklist
from app.queue import PendingEvent, event_queue

logger = logging.getLogger("centinela.gateway")

gateway_app = FastAPI(title="CENTINELA Gateway", docs_url=None, redoc_url=None)

_http_client: httpx.AsyncClient | None = None

ROUTES: dict[str, str] = {}


@gateway_app.on_event("startup")
async def _startup() -> None:
    global _http_client, ROUTES
    settings = get_settings()
    rule_engine.load()
    ROUTES = {
        "gov-pago": settings.target_gov_pago_url,
        "tickets": settings.target_tickets_url,
    }
    _http_client = httpx.AsyncClient(timeout=5.0)


@gateway_app.on_event("shutdown")
async def _shutdown() -> None:
    if _http_client is not None:
        await _http_client.aclose()


def _resolve_target(path: str) -> tuple[str, str, str] | None:
    """Devuelve (nombre_del_target, url_base, path_restante) o None si no matchea."""
    for name, base_url in ROUTES.items():
        prefix = f"/{name}"
        if path == prefix or path.startswith(prefix + "/"):
            remainder = path[len(prefix):] or "/"
            return name, base_url, remainder
    return None


def _is_trusted_proxy(peer: str) -> bool:
    networks = get_settings().trusted_proxy_networks
    if not networks:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(address in network for network in networks)


def _client_ip(request: Request) -> str:
    """IP de origen usada por el IPS para decidir la cuarentena.

    X-Forwarded-For solo se acepta si la conexión viene de un proxy declarado
    en TRUSTED_PROXIES: cualquiera puede escribir esa cabecera, y confiar en
    ella sin más permitiría a un atacante (a) esquivar su propia cuarentena
    rotando el valor o (b) envenenar la cuarentena de una IP ajena.
    """
    peer = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and _is_trusted_proxy(peer):
        return forwarded.split(",")[0].strip()
    return peer


@gateway_app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def proxy(full_path: str, request: Request) -> Response:
    src_ip = _client_ip(request)
    path = "/" + full_path
    target_match = _resolve_target(path)
    target_name = target_match[0] if target_match else "unknown"

    if blocklist.is_quarantined(src_ip):
        # La cuarentena no reevalúa reglas, pero el evento debe conservar la
        # causa que llevó al bloqueo (SQLi, traversal, ...) en vez de inventarla.
        context = blocklist.last_block_context(src_ip)
        await _record(
            src_ip=src_ip,
            method=request.method,
            path=path,
            target=target_name,
            verdict="block",
            rule_id="CNT-IPS-QUARANTINE",
            category=context["category"],
            severity=context["severity"],
            technique_id=context["technique_id"],
            payload_sample=None,
            engine_us=0,
        )
        return Response(
            content='{"error": "ip_quarantined", "rule_id": "CNT-IPS-QUARANTINE"}',
            status_code=403,
            media_type="application/json",
        )

    body = await request.body()
    normalized = normalize(
        method=request.method,
        path=request.url.path,
        query_string=request.url.query,
        headers=dict(request.headers),
        body=body,
        src_ip=src_ip,
    )

    verdict = rule_engine.evaluate(normalized)

    if verdict.verdict == "block":
        blocklist.record_block(
            src_ip,
            category=verdict.category,
            severity=verdict.severity,
            technique_id=verdict.technique_id,
        )
        await _record(
            src_ip=src_ip,
            method=request.method,
            path=path,
            target=target_name,
            verdict="block",
            rule_id=verdict.rule_id,
            category=verdict.category,
            severity=verdict.severity,
            technique_id=verdict.technique_id,
            payload_sample=verdict.payload_sample,
            engine_us=verdict.engine_us,
        )
        return Response(
            content='{"error": "blocked_by_centinela", "rule_id": "%s"}' % verdict.rule_id,
            status_code=403,
            media_type="application/json",
        )

    # ALLOW: solo aquí se toca la red hacia el objetivo.
    await _record(
        src_ip=src_ip,
        method=request.method,
        path=path,
        target=target_name,
        verdict="allow",
        rule_id=None,
        category=None,
        severity=None,
        technique_id=None,
        payload_sample=None,
        engine_us=verdict.engine_us,
    )

    if target_match is None:
        return Response(
            content='{"error": "unknown_target", "hint": "usa /gov-pago/... o /tickets/..."}',
            status_code=404,
            media_type="application/json",
        )

    _, base_url, remainder = target_match
    assert _http_client is not None
    upstream_url = base_url.rstrip("/") + remainder

    try:
        upstream_response = await _http_client.request(
            request.method,
            upstream_url,
            params=request.query_params,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            content=body,
        )
    except httpx.HTTPError:
        logger.exception("Fallo reenviando al objetivo %s", target_name)
        return Response(
            content='{"error": "upstream_unavailable"}',
            status_code=502,
            media_type="application/json",
        )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers={
            k: v
            for k, v in upstream_response.headers.items()
            if k.lower() not in {"content-length", "transfer-encoding", "connection"}
        },
    )


async def _record(
    *,
    src_ip: str,
    method: str,
    path: str,
    target: str,
    verdict: str,
    rule_id: str | None,
    category: str | None,
    severity: str | None,
    technique_id: str | None,
    payload_sample: str | None,
    engine_us: int,
) -> None:
    await event_queue.publish(
        PendingEvent(
            ts=dt.datetime.now(dt.timezone.utc),
            src_ip=src_ip,
            method=method,
            path=path,
            target=target,
            verdict=verdict,
            rule_id=rule_id,
            category=category,
            severity=severity,
            technique_id=technique_id,
            ml_score=None,  # lo añade engine/ml.py de forma asíncrona (Sprint 1, F3)
            engine_us=engine_us,
            payload_sample=payload_sample,
        )
    )
