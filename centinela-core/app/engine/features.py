"""Proyección de un evento HTTP a las 41 features del esquema NSL-KDD.

CENTINELA decide en capa 7 (HTTP), mientras que el modelo de ml/train.py se
entrena con features de flujo de red de NSL-KDD. Este módulo define una
proyección explícita y auditable:

- Las features que el gateway no puede observar (duración, bytes de respuesta,
  agregados de ventana por host) se fijan a 0 y quedan documentadas así.
- Las que sí se derivan de la petición (protocolo, servicio, tamaño del
  payload, veredicto, categoría de la regla que disparó) se mapean a sus
  valores NSL-KDD reales.

Es una señal AUXILIAR: el veredicto lo sigue tomando app/engine/rules.py y
ml_score nunca cambia un bloqueo. Si el modelo no está entrenado, la cola
guarda ml_score=None sin afectar al pipeline.

Los nombres coinciden exactamente con COLUMN_NAMES de ml/train.py (esquema
congelado del dataset NSL-KDD). Cualquier cambio aquí exige reentrenar, porque
el modelo aprende sobre estos mismos nombres de columna.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # solo para tipado: importar queue en runtime crearía un ciclo
    from app.queue import PendingEvent

# 41 features de NSL-KDD (sin 'label' ni 'difficulty'), en el orden del dataset.
NSL_KDD_FEATURES: tuple[str, ...] = (
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
)

CATEGORICAL_FEATURES = ("protocol_type", "service", "flag")

# Categorías de rules.yaml que implican manipulación de datos/entrada.
INJECTION_CATEGORIES = {"sqli", "xss", "traversal", "cmdi"}


def event_features(event: "PendingEvent") -> dict[str, float | str]:
    """Construye el vector NSL-KDD proyectado para un evento ya decidido."""
    payload_bytes = len(event.payload_sample or "") or len(event.path)
    blocked = event.verdict == "block"

    features: dict[str, float | str] = {
        name: 0.0 for name in NSL_KDD_FEATURES if name not in CATEGORICAL_FEATURES
    }

    features.update(
        {
            # Todo el tráfico del laboratorio es HTTP/1.1 sobre TCP.
            "protocol_type": "tcp",
            "service": "http",
            # SF = conexión completada; REJ = rechazada. Un bloqueo del IPS
            # equivale a que el objetivo nunca fue alcanzado.
            "flag": "REJ" if blocked else "SF",
            "src_bytes": float(payload_bytes),
            "logged_in": 0.0 if blocked else 1.0,
            "hot": 1.0 if event.category in INJECTION_CATEGORIES else 0.0,
            "num_failed_logins": 1.0 if event.category == "bruteforce" else 0.0,
            "is_guest_login": 1.0 if event.category == "bruteforce" else 0.0,
            # No hay agregación de ventana en el gateway: se declara una
            # conexión por evento al mismo servicio (valor neutro explícito).
            "count": 1.0,
            "srv_count": 1.0,
            "same_srv_rate": 1.0,
            "dst_host_same_srv_rate": 1.0,
            "serror_rate": 1.0 if blocked else 0.0,
            "srv_serror_rate": 1.0 if blocked else 0.0,
            "dst_host_serror_rate": 1.0 if blocked else 0.0,
            "dst_host_srv_serror_rate": 1.0 if blocked else 0.0,
        }
    )
    return features