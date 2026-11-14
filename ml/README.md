# ML — CENTINELA

Entrena el modelo que añade `ml_score` a cada evento (fuera del camino
crítico de bloqueo; el motor de reglas en `centinela-core/app/engine/rules.py`
nunca depende de este modelo para decidir).

## 1. Descargar NSL-KDD (pendiente de ejecución por el equipo)

Descargar `KDDTrain+.txt` y `KDDTest+.txt` desde el sitio oficial del
Canadian Institute for Cybersecurity (NSL-KDD) y colocarlos en `ml/data/`:

```
ml/data/KDDTrain+.txt
ml/data/KDDTest+.txt
```

`ml/data/` está en `.gitignore`: el dataset no se commitea.

## 2. Entrenar

```bash
pip install -r ../centinela-core/requirements.txt
python train.py --train data/KDDTrain+.txt --test data/KDDTest+.txt --out model/nsl_kdd_rf.joblib
```

Esto genera:

- `model/nsl_kdd_rf.joblib` — el modelo entrenado (lo carga `engine/ml.py`).
- `model/nsl_kdd_rf.metrics.json` — F1-score y tasa de falsos positivos,
  el reporte que exige el SDD #23 (criterio: F1 ≥ 0,90, FP ≤ 5%).

## 3. Verificar la compuerta de F3

Si `meets_sdd23_criteria` en el `.metrics.json` es `false`, según el plan B
de `docs/SPRINT-1.md` (hora 7:30) se presenta solo el motor de reglas con
sus métricas reales — el ML es una señal adicional, no un requisito para
que el IPS funcione.
