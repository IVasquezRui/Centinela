"""Puntuación ML, deliberadamente FUERA del camino crítico de bloqueo.

El veredicto ya lo tomó app/engine/rules.py antes de que este módulo se
ejecute. ml_score es solo una señal adicional que se adjunta al evento de
forma asíncrona (ver app/queue.py) para enriquecer el panel SOC y para
reportar las métricas F1 / falsos positivos que exige el SDD #23. Si el
modelo no está entrenado todavía (ml/model/*.joblib ausente), el sistema
sigue funcionando normalmente con ml_score=None.

La ruta del modelo se resuelve en este orden:

    1. ML_MODEL_PATH (variable de entorno, permite montar el artefacto donde
       convenga sin recompilar la imagen).
    2. /app/ml/model/nsl_kdd_rf.joblib, que es donde docker-compose monta
       ./ml/model dentro del contenedor.
    3. <repo>/ml/model/nsl_kdd_rf.joblib, para ejecutar el core en el host.

La versión anterior usaba solo ``Path(__file__).parents[3]``, que dentro del
contenedor resolvía a /ml/model (fuera del volumen) y hacía que el modelo
nunca se encontrara aunque el volumen estuviera correctamente montado.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np

logger = logging.getLogger("centinela.ml")

MODEL_FILENAME = "nsl_kdd_rf.joblib"

# Ruta del volumen declarado en docker-compose.yml (./ml/model:/app/ml/model:ro)
CONTAINER_MODEL_PATH = Path("/app/ml/model") / MODEL_FILENAME
# Fallback para ejecución local: centinela-core/app/engine/ml.py -> <repo>/ml/model
REPO_MODEL_PATH = Path(__file__).resolve().parents[3] / "ml" / "model" / MODEL_FILENAME


def resolve_model_path() -> Path:
    override = os.environ.get("ML_MODEL_PATH", "").strip()
    if override:
        return Path(override)
    if CONTAINER_MODEL_PATH.exists():
        return CONTAINER_MODEL_PATH
    return REPO_MODEL_PATH


class MlScorer:
    def __init__(self) -> None:
        self._model: Any = None
        self._encoders: dict[str, Any] = {}
        self._feature_columns: list[str] = []
        self._load_attempted = False
        self._missing_logged = False

    @property
    def model_path(self) -> Path:
        return resolve_model_path()

    def status(self) -> dict:
        """Estado del artefacto, para /api/health (evidencia de F3 sin logs)."""
        self._ensure_loaded()
        return {
            "model_loaded": self._model is not None,
            "model_path": str(self.model_path),
            "model_present": self.model_path.exists(),
            "feature_columns": len(self._feature_columns),
        }

    def _ensure_loaded(self) -> None:
        if self._load_attempted:
            return

        path = self.model_path
        if not path.exists():
            # No se marca como intentado: si el modelo se entrega con el core ya
            # arrancado, se recoge en el siguiente evento sin reiniciar nada.
            if not self._missing_logged:
                self._missing_logged = True
                logger.warning(
                    "No existe %s todavía (ver ml/train.py). ml_score quedará en None "
                    "hasta que José Oropeza entregue el modelo entrenado sobre NSL-KDD.",
                    path,
                )
            return

        self._load_attempted = True
        try:
            artifact = joblib.load(path)
        except Exception:  # modelo corrupto o incompatible: seguimos sin él
            logger.exception("No se pudo cargar el modelo ML, se continúa sin score")
            return

        # ml/train.py guarda un bundle con modelo + encoders + orden de columnas.
        # También se acepta un estimador "pelado" por si llega un .joblib suelto.
        if isinstance(artifact, dict) and "model" in artifact:
            self._model = artifact["model"]
            self._encoders = dict(artifact.get("encoders") or {})
            self._feature_columns = list(artifact.get("feature_columns") or [])
        else:
            self._model = artifact
        logger.info(
            "Modelo ML cargado desde %s (%d columnas con encoder)",
            path,
            len(self._feature_columns),
        )

    def score(self, features: dict[str, float | str]) -> float | None:
        self._ensure_loaded()
        if self._model is None:
            return None
        try:
            vector = self._build_vector(features)
            proba = self._model.predict_proba(vector)[0]
            # Convención: índice 1 = clase "ataque" en el entrenamiento de ml/train.py
            return float(proba[1])
        except Exception:
            logger.exception("Fallo puntuando con el modelo ML, se descarta el score")
            return None

    def _build_vector(self, features: dict[str, float | str]):
        if self._feature_columns:
            import pandas as pd  # import local: el modelo puede no estar presente

            row = {
                column: self._encode(column, features.get(column, 0))
                for column in self._feature_columns
            }
            return pd.DataFrame([row], columns=self._feature_columns)

        # Estimador sin metadatos: si fue entrenado con DataFrame respeta el
        # orden de sus feature_names_in_; si no, no hay forma de garantizar el
        # orden y solo se reporta como señal aproximada.
        names = list(getattr(self._model, "feature_names_in_", []) or [])
        values = [float(features.get(name, 0) or 0) for name in names] if names else [
            float(value) for value in features.values()
        ]
        return np.array([values])

    def _encode(self, column: str, value: float | str) -> float:
        encoder = self._encoders.get(column)
        if encoder is None:
            return float(value or 0)
        text = str(value)
        if text not in set(encoder.classes_):
            text = "__unknown__"
        return float(encoder.transform([text])[0])


ml_scorer = MlScorer()
