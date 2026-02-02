#!/usr/bin/env python3
"""
PacketLens Model Training Script
=================================

Trains an XGBoost classifier on preprocessed CIC-IDS data with:
- Class-weighted training for extreme imbalance (78% Benign)
- Early stopping to prevent overfitting
- ONNX export for production inference

Author: PacketLens ML Team
"""

import gc
import json
import sys
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score
import xgboost as xgb

# Optional ONNX conversion (will fail gracefully if not installed)
try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    from onnxmltools.convert import convert_xgboost
    from onnxmltools.convert.common.data_types import FloatTensorType as OnnxFloatTensorType
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    print("[WARNING] onnxmltools/skl2onnx not installed. ONNX export will fail.")

# =============================================================================
# CONFIGURATION
# =============================================================================
DATA_DIR = Path("../data/processed")
MODEL_STORE_DIR = Path("../services/inference/model_store")
MODEL_STORE_DIR.mkdir(parents=True, exist_ok=True)

# XGBoost Hyperparameters (Research-Grade defaults)
XGBOOST_PARAMS = {
    "n_estimators": 500,           # Max trees (early stopping will likely cut this)
    "max_depth": 8,                # Tree depth (6-10 typical for tabular)
    "learning_rate": 0.05,         # Conservative LR for stable convergence
    "min_child_weight": 50,        # Regularization: min samples per leaf
    "subsample": 0.8,              # Row sampling per tree
    "colsample_bytree": 0.8,       # Feature sampling per tree
    "gamma": 0.1,                  # Min loss reduction for split
    "reg_alpha": 0.01,             # L1 regularization
    "reg_lambda": 1.0,             # L2 regularization
    "objective": "multi:softprob", # Multi-class with probability outputs
    "tree_method": "hist",         # Fast histogram-based method
    "random_state": 42,
    "n_jobs": -1,                  # Use all CPUs
}

# Early stopping
EARLY_STOPPING_ROUNDS = 15
VALIDATION_SPLIT = 0.1  # Last 10% of training data for validation


# =============================================================================
# SAMPLE_WEIGHT vs SCALE_POS_WEIGHT EXPLANATION
# =============================================================================
"""
CRITICAL UNDERSTANDING FOR MULTI-CLASS IMBALANCE:

1. `scale_pos_weight` (XGBoost parameter):
   - ONLY works for BINARY classification
   - Sets weight ratio between positive and negative class
   - Useless for multi-class (33 attack types)

2. `sample_weight` (passed to fit()):
   - Works for MULTI-CLASS classification
   - Assigns a weight to EACH INDIVIDUAL SAMPLE
   - If class 20 has weight 23679, every sample of class 20 contributes
     23679x more to the gradient than a weight-1 sample
   - This forces the model to learn rare attack patterns

MATHEMATICAL FORMULATION:
For cross-entropy loss L = -sum(y * log(p)):
With sample_weight w_i, the gradient becomes:
    ∂L/∂θ = sum(w_i * (p_i - y_i) * x_i)

Rare classes with high w_i dominate the gradient, forcing the model
to reduce loss on them specifically.

THIS IS THE CORRECT APPROACH for PacketLens.
"""


# =============================================================================
# STEP 1: DATA LOADING
# =============================================================================
def load_data() -> tuple:
    """Load preprocessed data and class weights."""
    print("=" * 60)
    print("LOADING DATA")
    print("=" * 60)

    # Load feature data
    X_train = pd.read_parquet(DATA_DIR / "X_train.parquet")
    X_test = pd.read_parquet(DATA_DIR / "X_test.parquet")
    y_train = pd.read_parquet(DATA_DIR / "y_train.parquet")["label"].values
    y_test = pd.read_parquet(DATA_DIR / "y_test.parquet")["label"].values

    print(f"  X_train: {X_train.shape}")
    print(f"  X_test:  {X_test.shape}")
    print(f"  y_train: {y_train.shape} | Classes: {np.unique(y_train).shape[0]}")
    print(f"  y_test:  {y_test.shape} | Classes: {np.unique(y_test).shape[0]}")

    # Load class weights
    with open(DATA_DIR / "class_weights.json", "r") as f:
        class_weights = json.load(f)
    # Convert string keys to int
    class_weights = {int(k): v for k, v in class_weights.items()}
    print(f"  Class weights loaded: {len(class_weights)} classes")

    # Load label mapping for interpretable output
    with open(DATA_DIR / "label_mapping.json", "r") as f:
        label_mapping = json.load(f)
    int_to_label = {int(k): v for k, v in label_mapping["int_to_label"].items()}

    return X_train, X_test, y_train, y_test, class_weights, int_to_label


# =============================================================================
# STEP 2: COMPUTE SAMPLE WEIGHTS
# =============================================================================
def compute_sample_weights(y: np.ndarray, class_weights: dict) -> np.ndarray:
    """
    Convert class weights to per-sample weights.

    For each sample i with true label y_i:
        sample_weight[i] = class_weights[y_i]

    This means rare attacks (class 20 with weight 23679) will have
    samples that contribute 23679x more to the loss gradient.
    """
    print("\nComputing per-sample weights...")

    # Map each sample's class to its weight
    sample_weights = np.array([
        class_weights.get(int(label), 1.0)  # Default to 1.0 if class not in weights
        for label in y
    ])

    # Clip extreme weights to prevent numerical instability
    MAX_WEIGHT = 1000.0
    clipped = np.sum(sample_weights > MAX_WEIGHT)
    sample_weights = np.clip(sample_weights, 1.0, MAX_WEIGHT)

    if clipped > 0:
        print(f"  [!] Clipped {clipped:,} samples with weight > {MAX_WEIGHT}")

    print(f"  Sample weights: min={sample_weights.min():.2f}, "
          f"max={sample_weights.max():.2f}, mean={sample_weights.mean():.2f}")

    return sample_weights


# =============================================================================
# STEP 3: VALIDATION SPLIT (TEMPORAL - LAST 10%)
# =============================================================================
def create_validation_split(
    X: pd.DataFrame, y: np.ndarray, sample_weights: np.ndarray, val_ratio: float = 0.1
) -> tuple:
    """
    Create temporal validation split from training data.

    Uses LAST val_ratio% of training data (not random) to maintain
    temporal causality for early stopping signals.
    """
    print(f"\nCreating temporal validation split ({int((1-val_ratio)*100)}/{int(val_ratio*100)})...")

    split_idx = int(len(X) * (1 - val_ratio))

    X_train = X.iloc[:split_idx]
    X_val = X.iloc[split_idx:]
    y_train = y[:split_idx]
    y_val = y[split_idx:]
    w_train = sample_weights[:split_idx]
    w_val = sample_weights[split_idx:]

    print(f"  Train: {X_train.shape}, Val: {X_val.shape}")

    return X_train, X_val, y_train, y_val, w_train, w_val


# =============================================================================
# STEP 4: TRAIN XGBOOST
# =============================================================================
def train_xgboost(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_val: pd.DataFrame,
    y_val: np.ndarray,
    sample_weights: np.ndarray,
    val_weights: np.ndarray,
) -> tuple[xgb.Booster, dict, int]:
    """
    Train XGBoost classifier using NATIVE API (not sklearn wrapper).

    The sklearn wrapper has strict label validation that fails with temporal splits.
    Native API (xgb.train with DMatrix) handles this correctly.

    Returns:
        model: Trained XGBoost Booster
        label_remap: Dict mapping contiguous labels back to original labels
        n_classes: Number of classes
    """
    from sklearn.preprocessing import LabelEncoder

    print("\n" + "=" * 60)
    print("TRAINING XGBOOST CLASSIFIER (Native API)")
    print("=" * 60)

    # Re-encode labels to contiguous [0, n-1] using LabelEncoder
    label_encoder = LabelEncoder()
    all_labels = np.concatenate([y_train, y_val])
    label_encoder.fit(all_labels)
    n_classes = len(label_encoder.classes_)

    print(f"  Original classes: {label_encoder.classes_[:10]}... ({n_classes} total)")
    print(f"  Re-encoding to contiguous [0, {n_classes-1}]")

    y_train_encoded = label_encoder.transform(y_train)
    y_val_encoded = label_encoder.transform(y_val)

    # Create reverse mapping for evaluation
    contiguous_to_original = {i: int(orig) for i, orig in enumerate(label_encoder.classes_)}

    # Create DMatrix objects (native XGBoost format)
    # IMPORTANT: Convert to numpy arrays to avoid feature name issues in ONNX export
    # (ONNX converter expects numeric feature indices like 'f0', 'f1', not column names)
    dtrain = xgb.DMatrix(X_train.values, label=y_train_encoded, weight=sample_weights)
    dval = xgb.DMatrix(X_val.values, label=y_val_encoded)

    # Native XGBoost parameters (slightly different format)
    params = {
        "max_depth": XGBOOST_PARAMS["max_depth"],
        "learning_rate": XGBOOST_PARAMS["learning_rate"],
        "min_child_weight": XGBOOST_PARAMS["min_child_weight"],
        "subsample": XGBOOST_PARAMS["subsample"],
        "colsample_bytree": XGBOOST_PARAMS["colsample_bytree"],
        "gamma": XGBOOST_PARAMS["gamma"],
        "reg_alpha": XGBOOST_PARAMS["reg_alpha"],
        "reg_lambda": XGBOOST_PARAMS["reg_lambda"],
        "objective": "multi:softprob",
        "num_class": n_classes,
        "tree_method": XGBOOST_PARAMS["tree_method"],
        "seed": XGBOOST_PARAMS["random_state"],
        "eval_metric": ["mlogloss", "merror"],
    }

    print(f"  Params: max_depth={params['max_depth']}, lr={params['learning_rate']}, "
          f"n_classes={n_classes}")
    print(f"  Early stopping: {EARLY_STOPPING_ROUNDS} rounds")

    # Train with early stopping
    start_time = perf_counter()
    evals = [(dtrain, "train"), (dval, "val")]

    model = xgb.train(
        params,
        dtrain,
        num_boost_round=XGBOOST_PARAMS["n_estimators"],
        evals=evals,
        early_stopping_rounds=EARLY_STOPPING_ROUNDS,
        verbose_eval=50,
    )
    train_time = perf_counter() - start_time

    print(f"\n  Training completed in {train_time:.1f}s")
    print(f"  Best iteration: {model.best_iteration}")
    print(f"  Best score: {model.best_score:.4f}")

    return model, contiguous_to_original, n_classes


# =============================================================================
# STEP 5: EVALUATE MODEL
# =============================================================================
def evaluate_model(
    model: xgb.Booster,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    int_to_label: dict,
    contiguous_to_original: dict,
) -> dict:
    """
    Evaluate on temporal holdout (the TRUTH).

    This is data the model has NEVER seen, from a FUTURE time period.
    Performance here reflects real-world deployment accuracy.

    Args:
        model: Native XGBoost Booster
        contiguous_to_original: Dict mapping contiguous model output labels
                                back to original label integers
    """
    print("\n" + "=" * 60)
    print("EVALUATION ON TEMPORAL HOLDOUT (X_test)")
    print("=" * 60)

    # Create DMatrix for prediction (use .values for numpy array, consistent with training)
    dtest = xgb.DMatrix(X_test.values)

    # Predict probabilities (native API returns probabilities for softprob)
    y_proba = model.predict(dtest)
    y_pred_contiguous = np.argmax(y_proba, axis=1)

    # Map predictions back to original label space
    y_pred = np.array([contiguous_to_original.get(int(p), p) for p in y_pred_contiguous])

    # Get class labels that exist in test set (original label space)
    test_classes = sorted(np.unique(y_test))
    pred_classes = sorted(np.unique(y_pred))
    all_classes = sorted(set(test_classes) | set(pred_classes))

    # Map to readable names
    target_names = [int_to_label.get(c, f"Class_{c}") for c in all_classes]

    # Classification report
    print("\nClassification Report:")
    print("-" * 60)
    report = classification_report(
        y_test, y_pred,
        labels=all_classes,
        target_names=target_names,
        zero_division=0,
        digits=3,
    )
    print(report)

    # Macro F1 (treats all classes equally - critical for NIDS)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print("-" * 60)
    print(f"  MACRO F1 SCORE:    {macro_f1:.4f}  (treats all classes equally)")
    print(f"  WEIGHTED F1 SCORE: {weighted_f1:.4f}  (weighted by class size)")
    print("-" * 60)

    # Warning for low macro F1
    if macro_f1 < 0.5:
        print("\n  [WARNING] Macro F1 < 0.5 indicates poor performance on rare classes.")
        print("            Consider increasing class weights or using SMOTE.")

    return {
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "n_classes_test": len(test_classes),
        "n_classes_pred": len(pred_classes),
    }


# =============================================================================
# STEP 6: SAVE NATIVE MODEL (BACKUP)
# =============================================================================
def save_native_model(model: xgb.Booster, path: Path) -> None:
    """Save XGBoost Booster in native JSON format."""
    print(f"\nSaving native XGBoost model to {path}...")
    model.save_model(str(path))
    print(f"  Saved: {path.stat().st_size / 1024:.2f} KB")


# =============================================================================
# STEP 7: EXPORT TO ONNX
# =============================================================================
def export_to_onnx(
    model: xgb.Booster,
    n_features: int,
    n_classes: int,
    output_path: Path,
) -> bool:
    """
    Convert XGBoost model to ONNX format for production inference.

    ONNX provides:
    - 2-5x faster inference than native XGBoost
    - Consistent behavior across languages (Python, C++, Go via ONNX Runtime)
    - Smaller memory footprint
    """
    print("\n" + "=" * 60)
    print("EXPORTING TO ONNX FORMAT")
    print("=" * 60)

    if not ONNX_AVAILABLE:
        print("  [ERROR] onnxmltools not installed. Run:")
        print("          pip install onnxmltools skl2onnx")
        return False

    try:
        # Define input tensor shape: [batch_size, n_features]
        # batch_size = None means dynamic batching
        initial_type = [("features", OnnxFloatTensorType([None, n_features]))]

        print(f"  Input shape: [batch, {n_features}] (float32)")
        print(f"  Output: probabilities for each class")

        # Convert
        onnx_model = convert_xgboost(
            model,
            initial_types=initial_type,
            target_opset=12,  # Broad compatibility
        )

        # Save
        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        print(f"\n  ONNX model saved: {output_path}")
        print(f"  Size: {output_path.stat().st_size / 1024:.2f} KB")

        # Verify it can be loaded
        import onnxruntime as ort
        sess = ort.InferenceSession(str(output_path))
        input_name = sess.get_inputs()[0].name
        output_names = [o.name for o in sess.get_outputs()]
        print(f"  Verified: input='{input_name}', outputs={output_names}")

        return True

    except Exception as e:
        print(f"  [ERROR] ONNX conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# STEP 8: SAVE TRAINING METADATA
# =============================================================================
def save_training_metadata(
    metrics: dict,
    model: xgb.Booster,
    n_features: int,
    n_classes: int,
    output_path: Path,
) -> None:
    """Save training metadata for reproducibility."""
    metadata = {
        "xgboost_version": xgb.__version__,
        "best_iteration": model.best_iteration,
        "best_score": float(model.best_score),
        "n_features": n_features,
        "n_classes": n_classes,
        "hyperparameters": XGBOOST_PARAMS,
        "metrics": {
            "macro_f1": float(metrics["macro_f1"]),
            "weighted_f1": float(metrics["weighted_f1"]),
        },
        "early_stopping_rounds": EARLY_STOPPING_ROUNDS,
        "validation_split": VALIDATION_SPLIT,
    }

    with open(output_path, "w") as f:
        json.dump(metadata, f, indent=4)

    print(f"\nTraining metadata saved to {output_path}")


# =============================================================================
# MAIN PIPELINE
# =============================================================================
def main() -> int:
    """Execute the complete training pipeline."""
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + "  PACKETLENS - MODEL TRAINING PIPELINE".center(68) + "║")
    print("║" + "  XGBoost + Class Weights + ONNX Export".center(68) + "║")
    print("╚" + "═" * 68 + "╝\n")

    # Step 1: Load data
    X_train_full, X_test, y_train_full, y_test, class_weights, int_to_label = load_data()

    # Step 2: Compute per-sample weights
    sample_weights_full = compute_sample_weights(y_train_full, class_weights)

    # Step 3: Create validation split (for early stopping)
    X_train, X_val, y_train, y_val, w_train, w_val = create_validation_split(
        X_train_full, y_train_full, sample_weights_full, VALIDATION_SPLIT
    )

    # Free memory
    del X_train_full, y_train_full, sample_weights_full
    gc.collect()

    # Step 4: Train XGBoost (returns model + label remapping + n_classes)
    model, contiguous_to_original, n_classes = train_xgboost(
        X_train, y_train, X_val, y_val, w_train, w_val
    )

    # Step 5: Evaluate on temporal holdout (map predictions back to original labels)
    metrics = evaluate_model(model, X_test, y_test, int_to_label, contiguous_to_original)

    # Step 6: Save native model (backup)
    native_path = MODEL_STORE_DIR / "model.json"
    save_native_model(model, native_path)

    # Step 7: Export to ONNX (production format)
    onnx_path = MODEL_STORE_DIR / "model.onnx"
    n_features = X_train.shape[1]
    onnx_success = export_to_onnx(model, n_features, n_classes, onnx_path)

    # Step 8: Save metadata
    metadata_path = MODEL_STORE_DIR / "training_metadata.json"
    save_training_metadata(metrics, model, n_features, n_classes, metadata_path)

    # Final summary
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Model:       {native_path}")
    print(f"  ONNX:        {onnx_path} ({'OK' if onnx_success else 'FAILED'})")
    print(f"  Metadata:    {metadata_path}")
    print(f"  Macro F1:    {metrics['macro_f1']:.4f}")
    print("=" * 60)

    return 0 if onnx_success else 1


if __name__ == "__main__":
    sys.exit(main())
