"""Simulación y ejecución del 'Momento de Impacto' de la demo de CENTINELA (Fase F5).

Guion del momento de impacto (docs/SPRINT-1.md min 1:50-2:20):
1. El sistema acumula eventos y bitácora forense encadenada con hashes SHA-256.
2. Se consulta GET /api/audit/verify: la cadena es íntegra (valid: true).
3. Un atacante con acceso a la BD intenta alterar a mano un registro en audit_log
   (ej. para encubrir la IP de un ataque o cambiar la evidencia).
4. Se vuelve a consultar GET /api/audit/verify: el sistema detecta la alteración,
   marca valid: false e identifica exactamente el registro modificado (broken_at_id).
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Añadir centinela-core al path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "centinela-core"))

from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.storage.models import Base, AuditLog
from app.storage.audit import append_entry, verify_chain


async def run_momento_de_impacto() -> None:
    print("=" * 70)
    print("CENTINELA - SIMULACIÓN: 'MOMENTO DE IMPACTO' (AUDITORÍA INMUTABLE)")
    print("=" * 70)

    # 1. Configurar base de datos en memoria para la simulación
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("\n[Paso 1] Generando 5 registros legítimos en la bitácora de auditoría...")
    sample_records = [
        {"action": "block", "rule": "RULE-SQLI-01", "ip": "192.168.1.50", "target": "gov-pago"},
        {"action": "block", "rule": "RULE-XSS-01", "ip": "192.168.1.55", "target": "tickets"},
        {"action": "block", "rule": "RULE-SQLI-02", "ip": "192.168.1.50", "target": "gov-pago"},
        {"action": "quarantine", "ip": "192.168.1.50", "duration_seconds": 300},
        {"action": "block", "rule": "RULE-CMDI-01", "ip": "10.0.0.99", "target": "gov-pago"},
    ]

    async with session_factory() as session:
        for idx, rec in enumerate(sample_records, start=1):
            entry = await append_entry(session, event_id=idx, action=rec["action"], payload=rec)
            print(f"  + Creado AuditLog id={entry.id}: Hash={entry.hash[:16]}... (Prev={entry.prev_hash[:16]}...)")
        await session.commit()

    # 2. Primera verificación: Todo íntegro
    print("\n[Paso 2] Ejecutando GET /api/audit/verify antes de la alteración:")
    async with session_factory() as session:
        res1 = await verify_chain(session)
    print(f"  Resultado de verificación: {json.dumps(res1, indent=2)}")
    assert res1["valid"] is True, "La cadena inicial debe ser válida"
    assert res1["broken_at_id"] is None
    print("  >>> ESTADO: Cadena íntegra. Todos los hashes son coherentes.")

    # 3. El Momento de Impacto: Alteración manual en la BD
    tampered_id = 3
    print(f"\n[Paso 3] ¡MOMENTO DE IMPACTO!")
    print(f"  Simulando alteración manual con psql sobre audit_log (id={tampered_id}):")
    print(f"  SQL ejecutado: UPDATE audit_log SET payload = '{{\"action\":\"allow\",\"ip\":\"192.168.1.50\",\"rule\":\"NONE\"}}' WHERE id = {tampered_id};")

    async with session_factory() as session:
        tampered_payload = json.dumps({"action": "allow", "ip": "192.168.1.50", "rule": "NONE"})
        await session.execute(
            text(f"UPDATE audit_log SET payload = :p WHERE id = :id"),
            {"p": tampered_payload, "id": tampered_id}
        )
        await session.commit()
    print("  Registro modificado directamente en la base de datos.")

    # 4. Segunda verificación: Detección inmediata de la rotura
    print(f"\n[Paso 4] Ejecutando GET /api/audit/verify después de la alteración:")
    async with session_factory() as session:
        res2 = await verify_chain(session)
    print(f"  Resultado de verificación:\n{json.dumps(res2, indent=2)}")

    # 5. Validación de resultados
    print("\n[Paso 5] Comprobación de criterios forenses:")
    print(f"  - ¿Cadena detectada como inválida?: {not res2['valid']} (valid={res2['valid']})")
    print(f"  - ¿Registro roto detectado correctamente?: {res2['broken_at_id'] == tampered_id} (id detectado={res2['broken_at_id']})")
    print(f"  - Hash esperado: {res2['expected_hash']}")
    print(f"  - Hash almacenado: {res2['stored_hash']}")

    assert res2["valid"] is False, "La cadena debe ser reportada como inválida"
    assert res2["broken_at_id"] == tampered_id, f"El ID roto debe ser exactamente {tampered_id}"

    print("\n" + "=" * 70)
    print(">>> ÉXITO: El 'Momento de Impacto' funcionó exactamente según el guion.")
    print("    El sistema detectó la manipulación forense y aisló el registro exacto.")
    print("=" * 70)

    # Instrucción para la demo en vivo con Docker
    print("\nComando de psql para la demo en vivo (proyector/escenario):")
    print(f'  docker compose exec -T centinela-db psql -U centinela -d centinela -c "UPDATE audit_log SET payload = \'\\"{{\\\"tampered\\\": true}}\\"\' WHERE id = 3;"')


if __name__ == "__main__":
    asyncio.run(run_momento_de_impacto())
