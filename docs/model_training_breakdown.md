# PacketLens — Full Model Training Pipeline Breakdown

## Source Files

| File | Role |
|---|---|
| `scripts/train_model.py` | Main 8-step training pipeline — XGBoost → ONNX |
| `services/inference/core.py` | Production `InferenceEngine` — loads ONNX + runs predictions |
| `services/inference/server.py` | Async gRPC server — wraps InferenceEngine for live traffic |
| `services/inference/model_store/training_metadata.json` | Ground-truth record of the actual training run |

---

## Actual Training Results (from `training_metadata.json`)

| Metric | Value |
|---|---|
| **XGBoost version** | 3.1.2 |
| **Features** | 54 |
| **Classes** | 33 attack types |
| **Best iteration** | 207 / 500 (early stopping fired at round 207+15=222) |
| **Best val mlogloss** | 0.01287 |
| **Macro F1** | **0.8361** (treats all 33 classes equally) |
| **Weighted F1** | **0.9838** (weighted by class frequency) |
| **Early stopping rounds** | 15 |
| **Validation split** | 10% (temporal, last 10% of train set) |

> The gap between Macro F1 (0.836) and Weighted F1 (0.984) is expected — it reveals that the model handles common classes very well but struggles slightly on the rarest attack types. The class weights partially compensate for this.

---

## Step-by-Step Training Pipeline

### Step 1 — Load Preprocessed Data

```
DATA_DIR = data/processed/
```

Loads all artifacts produced by the preprocessing pipeline:

| Artifact | What it is |
|---|---|
| `X_train.parquet` | `(n_train, 54)` float32 — scaled features |
| `X_test.parquet` | `(n_test, 54)` float32 |
| `y_train.parquet` | `(n_train,)` int — encoded labels |
| `y_test.parquet` | `(n_test,)` int |
| `class_weights.json` | `{int_class: float_weight}` per class |
| `label_mapping.json` | `{int: "attack_name"}` for readable output |

Also converts string keys in `class_weights.json` → `int` keys (JSON forces string keys, training needs `int`).

---

### Step 2 — Compute Per-Sample Weights

**Why this step exists:** `class_weights.json` stores one weight **per class** (e.g., class 20 → weight 23679). But XGBoost's `sample_weight` argument needs one weight **per row** of training data.

```python
sample_weights[i] = class_weights[y_train[i]]
```

This means every row whose true label is class 20 gets a gradient contribution of 23679× compared to a weight-1 sample.

**Safety clipping:**
```python
MAX_WEIGHT = 1000.0
sample_weights = np.clip(sample_weights, 1.0, MAX_WEIGHT)
```
Without this, extremely rare classes (weight > 1000) can cause **gradient explosion** — the loss for a handful of samples overwhelms everything else. Capping at 1000 keeps training stable while still heavily emphasizing rare attacks.

**Mathematical effect on loss:**
```
∂L/∂θ = Σ w_i × (p_i - y_i) × x_i
```
Rare classes with high `w_i` dominate the gradient, forcing the model to learn their specific patterns.

> **Why not `scale_pos_weight`?** That XGBoost parameter only works for **binary** classification (one positive class vs. one negative class). With 33 attack types, `sample_weight` is the only correct approach.

---

### Step 3 — Temporal Validation Split (for Early Stopping)

```python
VALIDATION_SPLIT = 0.1
split_idx = int(len(X_train_full) * 0.9)

X_train = X_train_full.iloc[:split_idx]    # First 90%
X_val   = X_train_full.iloc[split_idx:]    # Last 10%
```

**Why temporal (not random)?**  
The data comes from a time-ordered capture. Using the *last* 10% as validation simulates what happens in production — the model trains on earlier traffic and is validated on later traffic. This gives a more realistic early stopping signal than a randomly shuffled validation set.

**Both `X_train` and `X_val` slices also carry their `sample_weights`** — `w_train` and `w_val` — so the weighted loss is consistent across both.

Result after split:
```
X_train:  90% of training rows  (used for gradient updates)
X_val:    10% of training rows  (used for early stopping loss)
X_test:   held-out test set     (used only in evaluation)
```

---

### Step 4 — Train XGBoost (Native API)

#### Why the Native API instead of the sklearn wrapper?

The sklearn wrapper (`XGBClassifier`) has strict label validation that fails when a temporal validation split drops label classes (e.g., if a rare attack appears in `X_train` but not in `X_val`). The native `xgb.train()` API handles this cleanly.

#### Label Re-encoding

```python
label_encoder = LabelEncoder()
label_encoder.fit(np.concatenate([y_train, y_val]))
y_train_encoded = label_encoder.transform(y_train)  # → contiguous [0, n_classes-1]
y_val_encoded   = label_encoder.transform(y_val)
```

XGBoost's native API requires labels in `[0, n_classes-1]`. The original encoded labels from preprocessing may not be contiguous (e.g., if classes 5, 12, 28 are present, XGBoost needs them re-mapped to 0, 1, 2). A `contiguous_to_original` reverse-map is saved to translate predictions back to the original label space.

#### DMatrix Creation

```python
dtrain = xgb.DMatrix(X_train.values, label=y_train_encoded, weight=sample_weights)
dval   = xgb.DMatrix(X_val.values,   label=y_val_encoded)
```

`.values` converts from pandas DataFrame to raw numpy — required for ONNX export (ONNX converter expects numeric feature indices `f0, f1, ...`, not pandas column names).

#### Hyperparameters

| Parameter | Value | Rationale |
|---|---|---|
| `n_estimators` | 500 (max) | Hard cap; early stopping fires at 207 |
| `max_depth` | 8 | Sufficient depth for 54-feature tabular data; >10 risks overfitting |
| `learning_rate` | 0.05 | Conservative — slower but more stable convergence |
| `min_child_weight` | 50 | Min samples in a leaf — strong regularizer against rare class overfitting |
| `subsample` | 0.8 | Row sampling per tree — reduces variance, speeds training |
| `colsample_bytree` | 0.8 | Feature sampling per tree — forces diverse feature usage |
| `gamma` | 0.1 | Minimum loss reduction required to make a split — prunes shallow useless splits |
| `reg_alpha` | 0.01 | L1 regularization — induces sparsity in leaf weights |
| `reg_lambda` | 1.0 | L2 regularization — prevents large leaf weights |
| `objective` | `multi:softprob` | Multi-class with **probability outputs** (not just argmax) |
| `tree_method` | `hist` | Histogram-based — 5-10x faster than exact method on large datasets |
| `eval_metric` | `mlogloss + merror` | Both log-loss and error rate tracked during training |

#### Training Loop

```python
model = xgb.train(
    params, dtrain,
    num_boost_round=500,
    evals=[(dtrain, "train"), (dval, "val")],
    early_stopping_rounds=15,   # Stop if val mlogloss doesn't improve for 15 rounds
    verbose_eval=50,            # Print every 50 rounds
)
```

**Early stopping logic:** If the validation `mlogloss` does not improve for 15 consecutive boosting rounds, training stops and the best iteration is retained. This model stopped at round **207**, saving ~293 unnecessary trees.

**Actual result:**
```
Best iteration: 207
Best val mlogloss: 0.01287
```

---

### Step 5 — Evaluate on Temporal Holdout

```python
dtest = xgb.DMatrix(X_test.values)
y_proba = model.predict(dtest)           # Shape: (n_test, 33)
y_pred_contiguous = np.argmax(y_proba, axis=1)
y_pred = [contiguous_to_original[p] for p in y_pred_contiguous]  # Back to original labels
```

**Why map back?** The model outputs contiguous indices [0–32] but `y_test` uses the original encoding from `label_mapping.json`. Without remapping, the `classification_report` would compare incompatible label spaces.

**Metrics used:**

| Metric | Value | Meaning |
|---|---|---|
| **Macro F1** | 0.8361 | Average F1 across all 33 classes with **equal weight** — critical for NIDS because each attack type matters regardless of frequency |
| **Weighted F1** | 0.9838 | Average F1 weighted by class frequency — dominated by Benign (78%) |

**Why Macro F1 is the primary metric for a NIDS:**  
If the model perfectly classifies Benign and DDoS (the two big classes) but misses SQL Injection entirely, Weighted F1 stays high (0.98) but Macro F1 drops to ~0.64. For a security system, a missed attack class is a critical failure — Macro F1 exposes this.

**Warning condition built in:**
```python
if macro_f1 < 0.5:
    print("[WARNING] Macro F1 < 0.5 — poor performance on rare classes.")
```

---

### Step 6 — Save Native Model (Backup)

```python
model.save_model("services/inference/model_store/model.json")
```

Saves the XGBoost Booster in **XGBoost JSON format** (not pickle). This is human-readable, version-stable, and can be loaded by any XGBoost version ≥ 1.0.

**File size:** 38.8 MB (38 MB for 207 trees × 8 depth levels)

This is a **backup/debug format** — production uses ONNX.

---

### Step 7 — Export to ONNX

```python
initial_type = [("features", OnnxFloatTensorType([None, n_features]))]
onnx_model = convert_xgboost(model, initial_types=initial_type, target_opset=12)
with open("services/inference/model_store/model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
```

**Input spec:** `[None, 54]` — `None` = dynamic batch size, `54` = fixed feature count  
**Target opset:** 12 — broad compatibility across ONNX Runtime versions  
**File size:** 19.6 MB (roughly half the JSON format, due to binary encoding)

**Why ONNX?**

| Property | Native XGBoost | ONNX Runtime |
|---|---|---|
| Inference speed | Baseline | **2–5× faster** |
| Memory footprint | Higher (full XGBoost library) | Lower (runtime-only) |
| Cross-language | Python only | Python, C++, Go, Java, .NET |
| Production dependency | Needs XGBoost installed | Only needs `onnxruntime` |

**Verification after export:**
```python
sess = ort.InferenceSession(str(output_path))
input_name = sess.get_inputs()[0].name      # → "features"
output_names = [o.name for o in sess.get_outputs()]  # → ["label", "probabilities"]
```

**ONNX output tensors:**
- `outputs[0]` = predicted class index (int64), shape `[batch]`
- `outputs[1]` = softmax probabilities (float32), shape `[batch, 33]`

---

### Step 8 — Save Training Metadata

Saves `services/inference/model_store/training_metadata.json`:

```json
{
  "xgboost_version": "3.1.2",
  "best_iteration": 207,
  "best_score": 0.01287,
  "n_features": 54,
  "n_classes": 33,
  "hyperparameters": { ... all params ... },
  "metrics": {
    "macro_f1": 0.8361,
    "weighted_f1": 0.9838
  },
  "early_stopping_rounds": 15,
  "validation_split": 0.1
}
```

Purpose: **Reproducibility** — lets you know exactly what configuration produced the model in the store without re-reading the script.

---

## Saved Artifacts (model_store)

| File | Size | Format | Purpose |
|---|---|---|---|
| `model.onnx` | 19.6 MB | ONNX binary | **Production inference** |
| `model.json` | 38.8 MB | XGBoost JSON | Backup / debug / re-training |
| `training_metadata.json` | 713 B | JSON | Reproducibility record |

---

## The Inference Pipeline (Production)

Once training is done, the ONNX model is served by the `InferenceEngine` class in `core.py`, consumed by `server.py` via gRPC. Here's how a live feature vector travels through the system:

```
Raw packet features (float32 array, n=54)
           │
           ▼
┌─────────────────────────────────────────┐
│  InferenceEngine._apply_preprocessing() │
│                                         │
│  1. Clip negatives on heavy-tail feats  │
│  2. log1p() on 18 power-law features    │
│     (same list as corrected_preprocessing.py)    │
│  3. RobustScaler.transform()            │
│     (loaded from data/processed/scaler.pkl)      │
│  4. Cast to float32                     │
└─────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│  ONNX Runtime session.run()             │
│                                         │
│  Input:  [1, 54] float32               │
│  Output: [labels, probabilities]        │
│          probabilities: [1, 33] float32 │
└─────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│  Post-processing                        │
│                                         │
│  pred_idx  = argmax(probabilities[0])   │
│  confidence = probabilities[0][pred_idx]│
│  label      = label_mapping[pred_idx]   │
│              → "DDoS-HOIC" / "BENIGN"   │
└─────────────────────────────────────────┘
           │
           ▼
   (label, confidence, inference_time_ms)
```

**Critical invariant:** The preprocessing applied in `_apply_preprocessing()` must **exactly mirror** what `corrected_preprocessing.py` did during training. If either changes, the model sees out-of-distribution data and predictions degrade. The `HEAVY_TAIL_FEATURES` frozenset in `core.py` is a copy of the same list from the preprocessing script — kept in sync manually.

---

## InferenceEngine — Startup Validation

When the engine initializes, it runs 4 validation checks before accepting any traffic:

| Check | What fails | Why |
|---|---|---|
| **ONNX model load** | File missing / corrupt | No model = can't run |
| **Feature count** | `feature_map.json` count ≠ ONNX input shape | Preprocessing/model version mismatch |
| **Scaler load** | File missing (graceful warning, not crash) | Running without scaler = degraded accuracy |
| **Scaler feature count** | Scaler `center_` length ≠ ONNX `n_features` | Scaler from different preprocessing run |

The engine handles both `RobustScaler` (`center_`) and `StandardScaler` (`mean_`) for backward compatibility.

---

## gRPC Server Architecture

The `server.py` wraps the `InferenceEngine` in an async gRPC service with **bidirectional streaming**:

```
Go Sniffer                        Python gRPC Server
    │                                     │
    │── stream FeatureVector ──────────►  │  async for request in stream:
    │                                     │      features = np.array(request.features)
    │                                     │      label, conf, time = await to_thread(engine.predict, features)
    │  ◄───────── stream Verdict ─────────│      yield Verdict(label=label, confidence=conf)
    │                                     │
```

**Key architectural decisions:**

| Decision | Mechanism | Why |
|---|---|---|
| **Non-blocking I/O** | `grpc.aio` (AsyncIO) | Handles thousands of concurrent streams without thread pool exhaustion |
| **CPU-bound isolation** | `asyncio.to_thread(engine.predict, ...)` | ONNX `session.run()` blocks — offloading to thread prevents event loop stall |
| **Error isolation** | Per-request try/except → ERROR verdict | One bad packet doesn't kill the entire stream |
| **Session persistence** | ONNX session loaded once at `__init__` | Avoids ~100ms model load overhead per request |
| **Observability** | Prometheus metrics (port 8000) | Tracks latency histogram, verdict counters, throughput gauge, active streams |

**Prometheus metrics exported:**

| Metric | Type | Buckets/Labels |
|---|---|---|
| `packetlens_inference_latency_seconds` | Histogram | 0.5ms, 1ms, 5ms, 10ms, 50ms, 100ms |
| `packetlens_verdict_total` | Counter | `{label, status}` |
| `packetlens_requests_per_second` | Gauge | — |
| `packetlens_requests_total` | Counter | — |
| `packetlens_active_streams` | Gauge | — |

---

## Full Pipeline Summary (Training → Serving)

```
data/processed/ (from corrected_preprocessing.py)
  ├── X_train.parquet          ──┐
  ├── y_train.parquet          ──┤
  ├── class_weights.json       ──┤──► scripts/train_model.py
  ├── label_mapping.json       ──┤
  └── feature_map.json         ──┘
           │
           ▼
     XGBoost training
     (207 trees, 33 classes, Macro F1=0.836)
           │
           ▼
  model_store/
  ├── model.onnx               ──────► InferenceEngine (core.py)
  ├── model.json               ──────► Backup / future fine-tuning
  └── training_metadata.json   ──────► Reproducibility record
           │
           ▼
  data/processed/scaler.pkl   ──────► InferenceEngine._apply_preprocessing()
  data/processed/feature_map.json ──► InferenceEngine validation + log1p mask
           │
           ▼
  services/inference/server.py
  ├── gRPC port 50051  (FeatureVector → Verdict)
  └── Prometheus port 8000 (metrics)
```
