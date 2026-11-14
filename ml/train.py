"""Entrena un RandomForest sobre NSL-KDD y reporta F1 / falsos positivos.

Uso (una vez descargado el dataset, ver ml/README.md):

    python ml/train.py \
        --train ml/data/KDDTrain+.txt \
        --test  ml/data/KDDTest+.txt \
        --out   ml/model/nsl_kdd_rf.joblib

Guarda el modelo entrenado en ml/model/, que centinela-core/app/engine/ml.py
carga en caliente (fuera del camino crítico de bloqueo) para añadir
`ml_score` a cada evento. Si este script no se ha corrido todavía, el
sistema sigue funcionando con `ml_score=None` (el motor de reglas no
depende del modelo para decidir).

Criterio de aceptación (SDD #23 / contrato de F3 en docs/SPRINT-1.md):
F1-score >= 0.90 y tasa de falsos positivos <= 5% sobre el split de test.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder

# Encabezados oficiales de NSL-KDD (41 características + label + nivel de dificultad).
# Fuente: https://www.unb.ca/cic/datasets/nsl.html
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]


def load_dataset(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, names=COLUMN_NAMES, header=None)
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df


def encode_features(
    train_df: pd.DataFrame, test_df: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, LabelEncoder]]:
    """Codifica columnas categóricas con el mismo encoder ajustado en train.

    Categorías del test no vistas en train (frecuente en NSL-KDD, ej. algunos
    valores de `service`) se mapean a una categoría "unknown" explícita para
    no romper en inferencia.

    Devuelve también los encoders: se guardan junto al modelo porque en
    inferencia (centinela-core/app/engine/ml.py) hay que reproducir exactamente
    la misma codificación; sin ellos, "tcp" o "http" no se pueden transformar.
    """
    encoders: dict[str, LabelEncoder] = {}
    for column in CATEGORICAL_COLUMNS:
        encoder = LabelEncoder()
        train_values = train_df[column].astype(str).tolist()
        encoder.fit(train_values + ["__unknown__"])
        encoders[column] = encoder

        train_df[column] = encoder.transform(train_df[column].astype(str))

        test_values = test_df[column].astype(str).apply(
            lambda v: v if v in set(train_values) else "__unknown__"
        )
        test_df[column] = encoder.transform(test_values)

    return train_df, test_df, encoders


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, default=Path("ml/data/KDDTrain+.txt"))
    parser.add_argument("--test", type=Path, default=Path("ml/data/KDDTest+.txt"))
    parser.add_argument("--out", type=Path, default=Path("ml/model/nsl_kdd_rf.joblib"))
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    if not args.train.exists() or not args.test.exists():
        raise SystemExit(
            f"No se encontró el dataset NSL-KDD en {args.train} / {args.test}.\n"
            "Ver ml/README.md para la descarga (bloquea la fase F3 de José Oropeza)."
        )

    train_df = load_dataset(args.train)
    test_df = load_dataset(args.test)
    train_df, test_df, encoders = encode_features(train_df, test_df)

    feature_columns = [c for c in COLUMN_NAMES if c not in ("label", "difficulty")]
    X_train, y_train = train_df[feature_columns], train_df["is_attack"]
    X_test, y_test = test_df[feature_columns], test_df["is_attack"]

    model = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=20,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    f1 = f1_score(y_test, y_pred)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    metrics = {
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(false_positive_rate), 4),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "meets_sdd23_criteria": bool(f1 >= 0.90 and false_positive_rate <= 0.05),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Se guarda un bundle autocontenido: modelo + encoders + orden de columnas.
    # app/engine/ml.py lo consume tal cual; un .joblib con solo el estimador
    # obligaría a adivinar la codificación de protocol_type/service/flag.
    artifact = {
        "model": model,
        "encoders": encoders,
        "feature_columns": feature_columns,
        "categorical_columns": CATEGORICAL_COLUMNS,
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    joblib.dump(artifact, args.out)

    metrics_path = args.out.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Modelo guardado en {args.out}")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
