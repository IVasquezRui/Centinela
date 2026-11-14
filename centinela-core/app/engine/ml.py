"""Puntuación ML, deliberadamente FUERA del camino crítico de bloqueo.

El veredicto ya lo tomó app/engine/rules.py antes de que este módulo se
ejecute. ml_score es solo una señal adicional que se adjunta al evento de
forma asíncrona (ver app/queue.py) para enriquecer el panel SOC y para
reportar las métricas F1 / falsos positivos que exige el SDD #23. Si el
modelo no está entrenado todavía (ml/model/*.joblib ausente), el sistema
sigue funcionando normalmente con ml_score=None.
"""
from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np

logger = logging.getLogger("centinela.ml")

MODEL_PATH = Path(__file__).resolve().parents[3] / "ml" / "model" / "nsl_kdd_rf.joblib"


class MlScorer:
    def __init__(self) -> None:
        self._model = None
        self._load_attempted = False

    def _ensure_loaded(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True
        if MODEL_PATH.exists():
            try:
                self._model = joblib.load(MODEL_PATH)
                logger.info("Modelo ML cargado desde %s", MODEL_PATH)
            except Exception:  # modelo corrupto o incompatible: seguimos sin él
                logger.exception("No se pudo cargar el modelo ML, se continúa sin score")
                self._model = None
        else:
            logger.warning(
                "No existe %s todavía (ver ml/train.py). ml_score quedará en None "
                "hasta que José Oropeza entrene el modelo sobre NSL-KDD.",
                MODEL_PATH,
            )

    def score(self, features: dict[str, float]) -> float | None:
        self._ensure_loaded()
        if self._model is None:
            return None
        try:
            vector = np.array([list(features.values())])
            proba = self._model.predict_proba(vector)[0]
            # Convención: índice 1 = clase "ataque" en el entrenamiento de ml/train.py
            return float(proba[1])
        except Exception:
            logger.exception("Fallo puntuando con el modelo ML, se descarta el score")
            return None


ml_scorer = MlScorer()
