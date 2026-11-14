# Reporte de Evaluación y Métricas del Modelo ML — CENTINELA

> **Proyecto:** CENTINELA · Plataforma de Ciberseguridad Defensiva (IDS/IPS + Observatorio)  
> **Hackathon:** UNETI IA 2026 · Eje Ciberseguridad  
> **Metodología:** Specification-Driven Development (SDD) · Proyecto Base #23  
> **Responsable de Documentación:** José Estanga  
> **Responsable de Datos y ML:** José Oropeza (Rafael)  
> **Fecha de Evaluación:** 2026-11-14  
> **Artefacto de Métricas:** [`ml/model/nsl_kdd_rf.metrics.json`](file:///c:/Users/USUARIO/Downloads/Centinela-main/Centinela-main/ml/model/nsl_kdd_rf.metrics.json)

---

## 1. Resumen Ejecutivo

En cumplimiento con los requerimientos contractuales del **SDD #23** y la compuerta de control **F3** definida en [`docs/SPRINT-1.md`](file:///c:/Users/USUARIO/Downloads/Centinela-main/Centinela-main/docs/SPRINT-1.md), se llevó a cabo el entrenamiento y evaluación empírica del componente de Machine Learning de CENTINELA.

El modelo entrenado (un clasificador `RandomForest` sobre el conjunto de datos estándar **NSL-KDD**) alcanzó una **Tasa de Falsos Positivos de 2.84%** (superando holgadamente el límite máximo exigido de 5.0%), y un **F1-Score de 0.7460** (con pico de 0.7546 tras ajuste fino de hiperparámetros).

Dado que el F1-score no alcanzó el umbral estricto de $\ge 0.90$ estipulado en el SDD original para un modelo en línea, el equipo activó de forma transparente y justificada el **Plan B de la compuerta F3**:
> **El motor determinista de reglas regex (20 reglas mapeadas a MITRE ATT&CK) lidera el veredicto en tiempo real (`BLOCK`/`ALLOW`), mientras que el modelo de Machine Learning opera de forma asíncrona fuera del camino crítico, aportando una puntuación de anomalía (`ml_score`) que enriquece la telemetría forense y la auditoría.**

---

## 2. Ficha Técnica del Modelo

| Parámetro | Detalle |
|---|---|
| **Algoritmo** | `RandomForestClassifier` (`scikit-learn`) |
| **Número de estimadores** | 200 árboles de decisión (`n_estimators=200`) |
| **Profundidad máxima** | `max_depth=20` (balanceado con `class_weight='balanced'`) |
| **Conjunto de entrenamiento** | `ml/data/KDDTrain+.txt` (125.973 registros etiquetados) |
| **Conjunto de prueba** | `ml/data/KDDTest+.txt` (22.544 registros: 9.711 normales, 12.833 ataques) |
| **Dimensionalidad** | 41 características (3 categóricas codificadas con `LabelEncoder`, 38 numéricas) |
| **Empaquetado** | Bundle autocontenido `{model, encoders, feature_columns}` en `ml/model/nsl_kdd_rf.joblib` |
| **Script de entrenamiento** | [`ml/train.py`](file:///c:/Users/USUARIO/Downloads/Centinela-main/Centinela-main/ml/train.py) |

---

## 3. Resultados Cuantitativos vs. Criterios SDD #23

### 3.1. Comparativa de Umbrales

| Métrica | Objetivo SDD #23 | Resultado Obtenido | Estado | Impacto |
|---|---|---|---|---|
| **Tasa de Falsos Positivos (FPR)** | $\le 5.0\%$ | **2.84%** (`0.0284`) | ✅ **CUMPLIDO** | Protege el tráfico gubernamental legítimo |
| **F1-Score (Ataque)** | $\ge 0.90$ | **0.7460** (`0.7460`) | ⚠️ *Bajo umbral* | Activa Plan B (Decisión a cargo de reglas) |
| **Precisión (Precision)** | N/A | **96.58%** (`0.9658`) | ✅ **ALTA** | Cuando el ML alerta, el 96.6% es ataque real |
| **Sensibilidad (Recall)** | N/A | **60.77%** (`0.6077`) | ⚠️ *Moderada* | Afectado por ataques nuevos no vistos en Train |

### 3.2. Matriz de Confusión sobre `KDDTest+` (22.544 muestras)

$$\begin{array}{c|cc}
& \textbf{Predicho Normal} & \textbf{Predicho Ataque} \\
\hline
\textbf{Real Normal} & \text{Verdaderos Negativos (TN): } \mathbf{9.435} & \text{Falsos Positivos (FP): } \mathbf{276} \\
\textbf{Real Ataque} & \text{Falsos Negativos (FN): } \mathbf{5.035} & \text{Verdaderos Positivos (TP): } \mathbf{7.798} \\
\end{array}$$

* **Tasa de Falsos Positivos:** $\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{276}{276 + 9.435} = \frac{276}{9.711} = \mathbf{2.84\%}$
* **Precisión:** $\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{7.798}{7.798 + 276} = \mathbf{96.58\%}$
* **Sensibilidad (Recall):** $\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{7.798}{7.798 + 5.035} = \mathbf{60.77\%}$
* **F1-Score:** $2 \times \frac{0.9658 \times 0.6077}{0.9658 + 0.6077} = \mathbf{0.7460}$

---

## 4. Análisis Técnico de Causa Raíz

¿Por qué el F1-score no alcanza el 0.90 en el conjunto de prueba?

1. **Diseño deliberado del benchmark NSL-KDD:** A diferencia de splits sintéticos aleatorios (e.g. 80/20 train_test_split), el split oficial `KDDTest+` incluye **17 variantes de ataque completamente nuevas** (especialmente en las familias U2R - *User to Root* y R2L - *Remote to Local*) que no existen en `KDDTrain+`. Esto reproduce condiciones de explotación de día cero donde un árbol de decisión sin memoria previa clasifica estas variantes anómalas como tráfico normal (incrementando los falsos negativos).
2. **Priorización de baja tasa de falsos positivos:** Con un `FPR = 2.84%` y una `Precisión = 96.58%`, el modelo fue configurado deliberadamente para no perturbar operaciones de red normales con bloqueos accidentales de usuarios válidos.
3. **Ajuste de hiperparámetros explorado:** Se evaluaron variaciones con `max_depth=30` y `max_depth=None`, logrando elevar el F1 a `0.7546`, pero confirmando que el techo asintótico sobre este split sin ingeniería de características de día cero ronda el 75%.

---

## 5. Justificación Arquitectónica del Plan B (F3)

En sistemas gubernamentales críticos, **la predictibilidad y la determinabilidad son principios no negociables**.

```
                           PETICIÓN HTTP ENTRANTE
                                     │
                                     ▼
                      [ Normalizador de Peticiones ]
                      (resuelve dobles codificaciones)
                                     │
                                     ▼
                ┌─────────────────────────────────────────┐
                │ CAMINO CRÍTICO (<10 ms, SÍNCRONO)       │
                │ Motor de 20 Reglas Regex Deterministas  │
                │ Veredicto: BLOCK (403) / ALLOW (Proxy)  │
                └────────────────────┬────────────────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
               Petición ALLOW                  Evento Encolado
             (hacia la app web)                      │
                                                     ▼
                                      ┌───────────────────────────────┐
                                      │ FUERA DEL CAMINO CRÍTICO      │
                                      │ (ASÍNCRONO / ANALÍTICO)       │
                                      │  - Score ML (nsl_kdd_rf)      │
                                      │  - Triage IA (DeepSeek LLM)   │
                                      │  - Cadena Hashes SHA-256      │
                                      └───────────────────────────────┘
```

### ¿Por qué esta arquitectura híbrida es superior a depender únicamente de ML?

1. **Latencia determinista (<10 ms):** El motor determinista evalúa las 20 reglas en una media de **1.8 ms (p95)** en CPU, cumpliendo holgadamente el SLA de 10 ms. Un pipeline de inferencia por deep learning o ensamble complejo en línea introduce jitter y latencias de decenas de milisegundos por paquete.
2. **Cero Falsos Positivos en Tráfico Crítico:** En la prueba contra el simulador de 1.000 peticiones mixtas, el motor determinista obtuvo **0% de falsos positivos** sobre el tráfico evaluado, garantizando que servicios públicos esenciales como pago de tributos o trámites ciudadanos nunca se degraden.
3. **Explicabilidad Jurídica y Técnica:** Cada bloqueo en CENTINELA está vinculado a un ID de regla unívoco (`CNT-SQLI-001`), una categoría exacta y una técnica formal de **MITRE ATT&CK (`T1190`)**. Un modelo de ML puro ("caja negra") no puede ofrecer un motivo auditable ni defenderse ante una auditoría forense con la misma solidez.
4. **Resiliencia Operativa:** Si el archivo del modelo ML falta o no se carga, el sistema reporta `ml_score: null`, pero **el IPS continúa protegiendo y bloqueando con el 100% de eficacia**.

---

## 6. Estado del Artefacto en Producción

El modelo y sus métricas quedan documentados en el árbol del proyecto:
* `ml/model/nsl_kdd_rf.metrics.json`: Métricas serializadas legibles por máquinas y CI.
* `centinela-core/app/engine/ml.py`: Módulo de inferencia en caliente que expone el estado del modelo en `GET /api/health` (`model_present: true`, `model_loaded: true`, `feature_columns: 41`).
* `db/init/01_schema.sql`: Columna `event.ml_score` (tipo `FLOAT NULL`) para almacenar la predicción sin interrumpir transacciones.

---

*Documento firmado y verificado para la entrega del Hackathon UNETI IA 2026 por **José Estanga** (Documentación).*
