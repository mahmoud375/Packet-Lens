# PacketLens — Full Preprocessing Pipeline Breakdown

## Source Files

| File | Role |
|---|---|
| `Notebooks/01_Data_Preprocessing.ipynb` | Original notebook — first full pass, has some flaws |
| `scripts/corrected_preprocessing.py` | Production-ready corrected pipeline — replaces the notebook |
| `scripts/audit_data_preprocessing.py` | Zero-tolerance validator — run after preprocessing to verify output |
| `Notebooks/experiments.ipynb` | Inference testing only — NOT part of preprocessing |

---

## The Dataset

- **Source file:** `data/raw/cic-collection.parquet` (CIC-IDS family datasets)
- **Nature:** Network flow records with ~80 features + a `label` column (attack type strings)
- **Known characteristic:** Heavy class imbalance (~78% Benign), power-law distributions in flow metrics, and rare extreme outlier values from DDoS attacks

---

## Step-by-Step Pipeline

### Step 1 — Load & Basic Cleaning

**Original notebook (Cell 2–3) and `corrected_preprocessing.py` Step 1**

```python
df = pd.read_parquet("data/raw/cic-collection.parquet")
```

- **Standardize column names:** strip whitespace, lowercase, replace spaces with `_`
- **Drop identity/metadata columns that would leak info:**
  - `flow_id`, `source_ip`, `src_ip`, `source_port`
  - `destination_ip`, `dst_ip`, `timestamp`, `date`
  - `classlabel` (duplicate of `label`)
- **Replace `±inf` → `NaN`, then `dropna()`** to remove rows with infinite or missing values

**Extra step in original notebook only:**  
Memory optimization — downcasts `float64 → float32`, `int64 → int8/16/32` based on actual min/max ranges. This saves ~40–60% RAM. The corrected script skips this in favor of doing it at save time (casting to `float32` when writing Parquet).

---

### Step 2 — Label Encoding

**Original notebook (Cell 4 + Cell 7) and `corrected_preprocessing.py` Step 2**

```python
encoder = LabelEncoder()
df["label_encoded"] = encoder.fit_transform(df["label"])
```

- Maps every attack class string (e.g., `"DDoS"`, `"PortScan"`, `"BENIGN"`) → a stable integer
- Saves **`label_mapping.json`** with both directions:
  ```json
  { "label_to_int": {"BENIGN": 0, "DDoS": 1, ...},
    "int_to_label": {"0": "BENIGN", "1": "DDoS", ...} }
  ```
- Drops the original string `label` column — only `label_encoded` remains

> **Bug in original notebook:** Cell 7 re-saves `label_mapping.json` redundantly after Cell 4 already saved it — harmless duplicate but shows the notebook was iterative.

---

### Step 3 — Feature Engineering

**Original notebook (Cell 5) and `corrected_preprocessing.py` Step 3**

#### A. Remove physically impossible negative values
Columns that must be non-negative (`header`, `duration`, `length`, `iat` in the notebook; `header`, `duration`, `length` in corrected script):
```python
for col in neg_candidates:
    mask &= df[col] >= 0
df = df[mask]
```

#### B. Fix `init_win_bytes = -1`
TCP window size of `-1` is a sentinel for "not captured". Replace with `0`:
```python
df.loc[df[col] == -1, col] = 0
```

#### C. Engineer two rate features
```python
EPSILON = 1e-10
duration = df["flow_duration"].clip(min=EPSILON)
df["bytes_rate"]   = (fwd_bytes + bwd_bytes) / duration
df["packets_rate"] = (fwd_pkts  + bwd_pkts)  / duration
```
Why `EPSILON`? Prevents division by zero for zero-duration flows (single-packet flows).

#### D. Clean any new `±inf` created by division, then `dropna()`

#### E. Remove zero-variance columns (original notebook only)
Columns with `nunique() <= 1` carry no information — dropped.

#### F. Drop known redundant / highly correlated columns
```
subflow_fwd_packets, subflow_bwd_packets  → duplicates of total_*
subflow_fwd_bytes,   subflow_bwd_bytes
fwd_packet_length_mean                    → correlated with avg_fwd_segment_size
```
The original notebook ran this instead of a full correlation matrix to save ~8 GB RAM.

#### G. Save `feature_map.json` (original notebook, Cell 5)
```json
{ "features": ["flow_duration", "total_fwd_packets", ..., "bytes_rate", "packets_rate"] }
```

---

### Step 4 — Log-Transform Heavy-Tailed Features *(CORRECTED ONLY)*

**`corrected_preprocessing.py` Step 4 — NEW, not in original notebook**

18 features that follow **Power-Law (Pareto)** distributions get `log1p` applied:
```python
HEAVY_TAIL_FEATURES = [
    "flow_duration", "flow_bytes/s", "flow_packets/s",
    "fwd_packets/s", "bwd_packets/s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max",
    "bytes_rate", "packets_rate",
]
df[col] = np.log1p(df[col].clip(lower=0))
```

**Why:** These features span 6+ orders of magnitude. `StandardScaler` on raw values compresses 99% of normal traffic to near-zero. `log1p(x) = ln(1+x)` brings the range from `[0, 1e6]` down to `[0, ~14]`, making the distribution log-normal and suitable for IQR-based scaling.

---

### Step 5 — Train / Test Split

**Original notebook (Cell 6) and `corrected_preprocessing.py` Step 5**

Both versions use a **stratified shuffle split** (80/20):
```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, shuffle=True, random_state=42
)
```

**Why stratified?** This is a *Known Attack Classifier* (signature-based NIDS). Every attack class must appear in both train and test sets for fair evaluation. Stratification preserves class proportions across both splits.

> **Debate noted in corrected script:** Comments acknowledge that for detecting *novel* attacks, anomaly detection + temporal split would be more appropriate. For the current scope (known-attack classification), stratified is correct.

---

### Step 6 — Outlier Clipping *(CORRECTED ONLY)*

**`corrected_preprocessing.py` Step 6 — NEW**

```python
CLIP_PERCENTILE = 99.5
for col in X_train.columns:
    upper = X_train[col].quantile(0.995)
    lower = X_train[col].quantile(0.005)
    X_train[col] = X_train[col].clip(lower, upper)
    X_test[col]  = X_test[col].clip(lower, upper)   # Same bounds — no leakage!
```

**Why:** DDoS attacks produce extreme outliers (e.g., 1e6 packets/s) that dominate scaler statistics. Without clipping, gradient magnitudes vary by 6 orders of magnitude → training instability.  
Bounds are computed **only from training data** and applied to test — no data leakage.

---

### Step 7 — Feature Scaling

**Original notebook (Cell 6):** `StandardScaler` (z-score normalization)
```python
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)   # Transform only, no fit!
```

**Corrected script Step 7:** `RobustScaler` (IQR-based)
```python
scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)
```

| | StandardScaler (original) | RobustScaler (corrected) |
|---|---|---|
| Formula | `(x - mean) / std` | `(x - median) / IQR` |
| Outlier sensitivity | High — mean/std explode | Low — median/IQR are robust |
| Suitable for | Gaussian data | Heavy-tailed / power-law data |

Both correctly fit **only on train data** to prevent data leakage.

Scaler saved as **`scaler.pkl`** (via `joblib.dump`).

---

### Step 8 — Class Weights *(CORRECTED ONLY)*

**`corrected_preprocessing.py` Step 8 — NEW**

```python
weights = compute_class_weight("balanced", classes=classes, y=y_train)
# Formula: w_c = n_samples / (n_classes × n_samples_c)
```

Saved as **`class_weights.json`**: `{ "0": 0.64, "1": 4.2, ... }`

**Why:** With 78% Benign traffic, a naive model achieves 78% accuracy by predicting "Benign" for everything — useless for a NIDS. Balanced weights force each class to contribute equally to the loss, making the model learn rare attack patterns.

Used during training as:
- sklearn: `model.fit(X, y, class_weight=weights_dict)`
- XGBoost: `sample_weight` per instance
- PyTorch: `nn.CrossEntropyLoss(weight=weights_tensor)`

---

### Step 9 — Save All Artifacts

**Original notebook (Cell 6) and `corrected_preprocessing.py` Step 9**

All data saved to `data/processed/`:

| Artifact | Shape/Type | Format |
|---|---|---|
| `X_train.parquet` | `(n_train, n_features)` float32 | Parquet |
| `X_test.parquet` | `(n_test, n_features)` float32 | Parquet |
| `y_train.parquet` | `(n_train,)` int | Parquet |
| `y_test.parquet` | `(n_test,)` int | Parquet |
| `scaler.pkl` | Fitted scaler object | joblib pickle |
| `feature_columns.pkl` | List of column names | pickle |
| `feature_map.json` | `{"features": [...]}` | JSON |
| `label_mapping.json` | `{label_to_int, int_to_label}` | JSON |
| `class_weights.json` | `{int_class: float_weight}` | JSON *(corrected only)* |

**Critical fix in corrected script:** `feature_columns.pkl` and `feature_map.json` are now generated **from the same source** (`feature_columns = X.columns.tolist()` before scaling) and verified with an `assert` statement. The original notebook had a potential mismatch between these two artifacts.

---

### Step 10 — Verification

**`corrected_preprocessing.py` Step 10 and `audit_data_preprocessing.py`**

#### In-pipeline verification (corrected script)
- Checks all 9 required files exist
- Verifies scaler type is `RobustScaler`
- Verifies feature count is identical across `feature_columns.pkl`, `feature_map.json`, and `X_train.parquet`

#### External audit script (`audit_data_preprocessing.py`)
A standalone "zero-tolerance" validator with 4 checks:

| Check | What it does |
|---|---|
| **Alignment Check** | `len(X_train) == len(y_train)` and `len(X_test) == len(y_test)` — row count must match exactly |
| **Schema Consistency** | Feature count and feature order in `feature_map.json` must exactly match `X_train` columns; all integer labels in `y` must exist in `label_mapping.json` (ghost class detection) |
| **Data Health** | Zero NaN values, zero `±inf` values, check dtype (float32 preferred), no negative `flow_duration` or packet lengths |
| **Artifact Validity** | `scaler.pkl` is a `StandardScaler` (or `RobustScaler`), is fitted (`mean_` and `scale_` exist), and expects the same number of features as `X_train` |

Returns exit code `0` if all pass, `1` if any fail. The VERDICT line says either **"DATA IS 100% READY FOR MODELING"** or **"DATA HAS ISSUES - DO NOT PROCEED TO MODELING"**.

---

## What `experiments.ipynb` Is

This notebook is **not part of preprocessing**. It's a post-training inference test bench:

- **Experiment A (White-Box):** Loads `model.onnx` directly via `onnxruntime`, runs a dummy `(1, 54)` float32 input, checks prediction + confidence
- **Experiment B (Black-Box):** Connects to the gRPC server at `localhost:50051`, sends a single `FeatureVector` proto, checks `verdict.label` and `verdict.confidence`
- **Experiment C (Stress Test):** Streams 100 requests, collects `inference_time_us` per response, prints latency percentiles (P95, P99) and throughput (req/s) + ASCII histogram

It assumes the preprocessing artifacts (`label_mapping.json`) and the trained model (`model.onnx`) already exist.

---

## Evolution Summary: Notebook → Corrected Script

| Aspect | Original Notebook | Corrected Script |
|---|---|---|
| Scaling | `StandardScaler` | `RobustScaler` (IQR-based) |
| Log transform | ❌ None | ✅ `log1p` on 18 heavy-tail features |
| Outlier clipping | ❌ None | ✅ P99.5 clip (train bounds only) |
| Class weights | ❌ Not computed | ✅ `class_weights.json` saved |
| Artifact sync | ⚠️ Possible mismatch | ✅ `assert` verifies consistency |
| Split | Stratified shuffle | Stratified shuffle (same) |
| Negative row removal | `header|duration|iat|length` | `header|duration|length` only |
| Memory opt | ✅ Full downcast pass | ✅ float32 at Parquet write |
