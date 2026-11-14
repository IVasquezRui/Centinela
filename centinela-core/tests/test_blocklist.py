"""Pruebas unitarias para el subsistema de cuarentena e IPS (app/ips/blocklist.py).

Verifica los requisitos contractuales de F3:
1. Umbral: 3 detecciones (verdict=block) de la misma IP en <= 60 s -> cuarentena de 300 s (5 min).
2. Cortocircuito: IP en cuarentena es identificada inmediatamente (is_quarantined=True).
3. Preservación del contexto del último ataque (categoría, severidad, técnica MITRE).
4. Ventana deslizante: eventos con antigüedad > 60 s son descartados.
5. Expiración de cuarentena: trascurridos los 300 s, el host sale de cuarentena limpiamente.
6. Aislamiento por IP: bloquear IP_A no afecta el estado de IP_B.
7. Snapshot para el panel SOC (/api/blocklist).
"""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from app.config import Settings
from app.ips.blocklist import Blocklist


@pytest.fixture
def custom_settings():
    return Settings(
        blocklist_threshold=3,
        blocklist_window_seconds=60,
        blocklist_quarantine_seconds=300,
    )


@pytest.fixture
def bl(custom_settings):
    return Blocklist(custom_settings)


def test_blocks_under_threshold_do_not_quarantine(bl):
    """1 y 2 bloqueos no disparan la cuarentena."""
    ip = "192.168.1.10"
    
    # Bloqueo 1
    triggered = bl.record_block(ip, category="sqli", severity="critica", technique_id="T1190")
    assert triggered is False
    assert bl.is_quarantined(ip) is False

    # Bloqueo 2
    triggered = bl.record_block(ip, category="sqli", severity="critica", technique_id="T1190")
    assert triggered is False
    assert bl.is_quarantined(ip) is False


def test_third_block_triggers_quarantine(bl):
    """El 3er bloqueo dentro de 60 s dispara la cuarentena de 300 s."""
    ip = "192.168.1.20"
    
    bl.record_block(ip, category="sqli", severity="critica", technique_id="T1190")
    bl.record_block(ip, category="xss", severity="alta", technique_id="T1059.007")
    triggered = bl.record_block(ip, category="cmdi", severity="critica", technique_id="T1059")

    assert triggered is True
    assert bl.is_quarantined(ip) is True
    assert bl.quarantined_until(ip) is not None


def test_last_block_context_preserved(bl):
    """El contexto del último bloqueo se preserva para auditoría y métricas del SOC."""
    ip = "192.168.1.30"
    
    bl.record_block(ip, category="sqli", severity="critica", technique_id="T1190")
    bl.record_block(ip, category="traversal", severity="alta", technique_id="T1083")
    
    ctx = bl.last_block_context(ip)
    assert ctx["category"] == "traversal"
    assert ctx["severity"] == "alta"
    assert ctx["technique_id"] == "T1083"

    # Contexto por defecto para IP desconocida
    unknown_ctx = bl.last_block_context("10.99.99.99")
    assert unknown_ctx["category"] is None
    assert unknown_ctx["severity"] == "alta"
    assert unknown_ctx["technique_id"] is None


def test_sliding_window_discards_old_hits(bl):
    """Bloqueos ocurridos hace más de 60 s no cuentan para el umbral."""
    ip = "192.168.1.40"
    current_time = 1000.0

    with patch("time.monotonic", return_value=current_time):
        bl.record_block(ip, category="sqli", severity="critica")
        bl.record_block(ip, category="sqli", severity="critica")

    assert bl.is_quarantined(ip) is False

    # Avanzar el tiempo 65 segundos (la ventana de 60s expira los hits anteriores)
    with patch("time.monotonic", return_value=current_time + 65.0):
        # Este nuevo hit es el primero en la nueva ventana
        triggered = bl.record_block(ip, category="sqli", severity="critica")
        assert triggered is False
        assert bl.is_quarantined(ip) is False


def test_quarantine_expiration(bl):
    """Tras 300 s (5 min), la IP sale automáticamente de cuarentena."""
    ip = "192.168.1.50"
    start_time = 1000.0

    with patch("time.monotonic", return_value=start_time):
        bl.record_block(ip)
        bl.record_block(ip)
        bl.record_block(ip)
        assert bl.is_quarantined(ip) is True

    # A los 299 segundos sigue en cuarentena
    with patch("time.monotonic", return_value=start_time + 299.0):
        assert bl.is_quarantined(ip) is True

    # A los 301 segundos ya expiró
    with patch("time.monotonic", return_value=start_time + 301.0):
        assert bl.is_quarantined(ip) is False


def test_multiple_ips_isolation(bl):
    """Bloquear una IP atacante no afecta a otras IPs en la red."""
    ip_malicious = "192.168.1.100"
    ip_legit = "192.168.1.200"

    for _ in range(3):
        bl.record_block(ip_malicious)

    assert bl.is_quarantined(ip_malicious) is True
    assert bl.is_quarantined(ip_legit) is False


def test_snapshot_active_quarantines(bl):
    """snapshot() lista únicamente las IPs con cuarentena vigente y sus segundos restantes."""
    ip1 = "10.0.0.1"
    ip2 = "10.0.0.2"
    start_time = 2000.0

    with patch("time.monotonic", return_value=start_time):
        for _ in range(3):
            bl.record_block(ip1)
        for _ in range(3):
            bl.record_block(ip2)

        snap = bl.snapshot()
        assert len(snap) == 2
        ips = {entry["ip"] for entry in snap}
        assert ips == {ip1, ip2}
        for entry in snap:
            assert entry["quarantined_for_seconds"] == 300

    # 100 segundos después, quedan 200 segundos
    with patch("time.monotonic", return_value=start_time + 100.0):
        snap = bl.snapshot()
        assert len(snap) == 2
        for entry in snap:
            assert entry["quarantined_for_seconds"] == 200
