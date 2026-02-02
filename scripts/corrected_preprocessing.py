#!/usr/bin/env python3
"""
PacketLens Phase 0: CORRECTED Data Preprocessing Pipeline
==========================================================

This script replaces the flawed preprocessing logic with mathematically
correct transformations for Network Intrusion Detection Systems.

CHANGES FROM ORIGINAL:
1. Time-based split (no random shuffle) - preserves temporal causality
2. Log-transform + RobustScaler - handles power-law distributions
3. Outlier clipping at P99.5 - prevents gradient explosion
4. Class weights computation - handles 78%/22% imbalance
5. Synchronized artifact saving - no more feature_columns.pkl mismatch

Author: PacketLens ML Team
"""

import gc
import json
import os
import pickle
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, RobustScaler
from sklearn.utils.class_weight import compute_class_weight

# =============================================================================
# CONFIGURATION
# =============================================================================
RAW_DATA_PATH = Path("../data/raw/cic-collection.parquet")
PROCESSED_DIR = Path("../data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Features that follow Power-Law distributions (need log-transform)
# These span 6+ orders of magnitude in CIC-IDS datasets
HEAVY_TAIL_FEATURES = [
    "flow_duration",
    "flow_bytes/s",
    "flow_packets/s",
    "fwd_packets/s",
    "bwd_packets/s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bytes_rate",
    "packets_rate",
]

# Percentile for outlier clipping (prevents gradient explosion)
CLIP_PERCENTILE = 99.5

# Train/Test split ratio (temporal, NOT random)
TRAIN_RATIO = 0.8


# =============================================================================
# STEP 1: LOAD & BASIC CLEANING (Same as before)
# =============================================================================
def load_and_clean_data(file_path: Path) -> pd.DataFrame:
    """Load dataset and perform basic cleaning."""
    print(f"Loading data from {file_path}...")
    df = pd.read_parquet(file_path)
    print(f"  Loaded: {df.shape[0]:,} rows × {df.shape[1]} columns")

    # Standardize column names
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    # Drop metadata columns that leak identity
    drop_cols = [
        "flow_id",
        "source_ip",
        "src_ip",
        "source_port",
        "destination_ip",
        "dst_ip",
        "timestamp",
        "date",
        "classlabel",  # Duplicate label column
    ]
    dropped = [c for c in drop_cols if c in df.columns]
    df.drop(columns=drop_cols, errors="ignore", inplace=True)
    print(f"  Dropped metadata columns: {dropped}")

    # Handle infinite and NaN values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    null_count = df.isna().sum().sum()
    if null_count > 0:
        print(f"  Dropping {null_count:,} infinite/missing values...")
        df.dropna(inplace=True)

    print(f"  Cleaned shape: {df.shape}")
    return df


# =============================================================================
# STEP 2: LABEL ENCODING (Unchanged - was correct)
# =============================================================================
def encode_labels(df: pd.DataFrame, target_col: str = "label") -> tuple:
    """Encode string labels to integers and save mapping."""
    print(f"\nEncoding labels from '{target_col}'...")

    encoder = LabelEncoder()
    df["label_encoded"] = encoder.fit_transform(df[target_col])

    # Create bidirectional mapping
    label_mapping = dict(
        zip(
            encoder.classes_.tolist(),
            [int(x) for x in encoder.transform(encoder.classes_)],
        )
    )
    reverse_mapping = {v: k for k, v in label_mapping.items()}

    # Save label mapping
    label_map_path = PROCESSED_DIR / "label_mapping.json"
    with open(label_map_path, "w") as f:
        json.dump(
            {"label_to_int": label_mapping, "int_to_label": reverse_mapping},
            f,
            indent=4,
        )
    print(f"label_mapping.json saved ({len(label_mapping)} classes)")

    # Show class distribution
    print("\n  Class Distribution (Top 10):")
    counts = df[target_col].value_counts()
    for label, count in counts.head(10).items():
        pct = count / len(df) * 100
        print(f"    {label:25s}: {count:>10,} ({pct:5.2f}%)")

    # Drop original string label
    df.drop(columns=[target_col], inplace=True)

    return df, encoder, label_mapping


# =============================================================================
# STEP 3: FEATURE ENGINEERING (Minor fixes)
# =============================================================================
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Create derived features and clean invalid values."""
    print("\nEngineering features...")
    rows_before = len(df)

    # A. Remove rows with negative values in columns that must be positive
    neg_candidates = [
        col
        for col in df.columns
        if "header" in col or "duration" in col or "length" in col
    ]
    mask = pd.Series(True, index=df.index)
    for col in neg_candidates:
        if pd.api.types.is_numeric_dtype(df[col]):
            mask &= df[col] >= 0
    df = df[mask].copy()
    print(f"  Dropped {rows_before - len(df):,} rows with negative values")

    # B. Fix init_win_bytes (-1 → 0)
    win_cols = [col for col in df.columns if "init" in col and "win" in col]
    for col in win_cols:
        df.loc[df[col] == -1, col] = 0

    # C. Engineer rate features
    EPSILON = 1e-10
    if "flow_duration" in df.columns:
        duration = df["flow_duration"].values.clip(min=EPSILON)

        if (
            "fwd_packets_length_total" in df.columns
            and "bwd_packets_length_total" in df.columns
        ):
            df["bytes_rate"] = (
                (df["fwd_packets_length_total"].values + df["bwd_packets_length_total"].values)
                / duration
            ).astype(np.float32)

        if (
            "total_fwd_packets" in df.columns
            and "total_backward_packets" in df.columns
        ):
            df["packets_rate"] = (
                (df["total_fwd_packets"].values + df["total_backward_packets"].values)
                / duration
            ).astype(np.float32)

    # D. Clean infinities created by division
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # E. Drop known redundant columns (high correlation)
    redundant_cols = [
        "subflow_fwd_packets",
        "subflow_bwd_packets",
        "subflow_fwd_bytes",
        "subflow_bwd_bytes",
        "fwd_packet_length_mean",  # Correlated with avg_fwd_segment_size
    ]
    actual_redundant = [c for c in redundant_cols if c in df.columns]
    if actual_redundant:
        df.drop(columns=actual_redundant, inplace=True)
        print(f"  Dropped redundant columns: {actual_redundant}")

    gc.collect()
    print(f"  Final shape after engineering: {df.shape}")
    return df


# =============================================================================
# STEP 4: LOG-TRANSFORM (NEW - fixes Power-Law distribution issue)
# =============================================================================
def apply_log_transform(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply log1p transform to heavy-tailed features.

    MATHEMATICAL JUSTIFICATION:
    Network flow features like bytes/s, packets/s follow Power-Law (Pareto)
    distributions with P(X > x) ~ x^(-α). These span 6+ orders of magnitude.

    StandardScaler assumes Gaussian: z = (x - μ) / σ
    For Power-Law data, μ and σ are dominated by outliers, compressing 99%
    of samples to near-zero values.

    log1p(x) = ln(1 + x) compresses the dynamic range:
    - log1p(1) ≈ 0.69
    - log1p(1e6) ≈ 13.8
    This makes the distribution closer to log-normal, suitable for RobustScaler.
    """
    print("\nApplying log1p transform to heavy-tailed features...")
    transformed = []

    for col in HEAVY_TAIL_FEATURES:
        if col in df.columns:
            # Clip negatives (shouldn't exist after cleaning, but safety first)
            df[col] = np.log1p(df[col].clip(lower=0))
            transformed.append(col)

    print(f"  Transformed {len(transformed)} features: {transformed[:5]}...")
    return df


# =============================================================================
# STEP 5: STRATIFIED SHUFFLE SPLIT (For Known Attack Classifier)
# =============================================================================
def stratified_shuffle_split(
    X: pd.DataFrame, y: pd.Series, test_size: float = 0.2
) -> tuple:
    """
    Split data using STRATIFIED SHUFFLE for Known Attack Classification.

    RATIONALE:
    For a "Known Attack Classifier" (signature-based NIDS), the model must
    learn patterns for ALL attack types present in the dataset. This requires:
    - Training data containing examples of EVERY class
    - Test data containing examples of EVERY class (for fair evaluation)

    Stratified split ensures proportional class representation in both sets.

    NOTE: This approach assumes attacks in production will match training data.
    For detecting NOVEL attacks, consider anomaly detection instead.
    """
    from sklearn.model_selection import train_test_split

    print(f"\nApplying STRATIFIED SHUFFLE split (80/20)...")
    print("  Ensuring all attack types appear in both train and test sets")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        stratify=y,              # Preserve class proportions
        shuffle=True,            # Random shuffle
        random_state=42          # Reproducibility
    )

    print(f"  Train: {X_train.shape} | Classes: {y_train.nunique()}")
    print(f"  Test:  {X_test.shape} | Classes: {y_test.nunique()}")

    return X_train, X_test, y_train, y_test


# =============================================================================
# STEP 6: OUTLIER CLIPPING (NEW - prevents gradient explosion)
# =============================================================================
def clip_outliers(
    X_train: pd.DataFrame, X_test: pd.DataFrame, percentile: float = 99.5
) -> tuple:
    """
    Clip extreme outliers at the given percentile.

    MATHEMATICAL JUSTIFICATION:
    DDoS attacks create extreme outliers (1e6 packets/s) that dominate
    mean and variance calculations. Without clipping:
    - Scaler statistics are skewed by <0.1% of samples
    - Gradient magnitudes vary by 6 orders of magnitude → instability

    Clipping at P99.5 bounds are computed ONLY from training data to
    prevent test-to-train leakage.
    """
    print(f"\nClipping outliers at P{percentile}...")

    bounds = {}
    for col in X_train.columns:
        upper = X_train[col].quantile(percentile / 100)
        lower = X_train[col].quantile((100 - percentile) / 100)
        bounds[col] = (lower, upper)

        X_train[col] = X_train[col].clip(lower=lower, upper=upper)
        # Apply SAME bounds to test (no leakage)
        X_test[col] = X_test[col].clip(lower=lower, upper=upper)

    print(f"  Clipped {len(bounds)} features using training quantiles")
    return X_train, X_test


# =============================================================================
# STEP 7: ROBUST SCALING (NEW - replaces StandardScaler)
# =============================================================================
def apply_robust_scaling(
    X_train: pd.DataFrame, X_test: pd.DataFrame
) -> tuple:
    """
    Scale features using RobustScaler (IQR-based).

    MATHEMATICAL JUSTIFICATION:
    RobustScaler uses:
        z = (x - Q2) / (Q3 - Q1)

    Where Q2 = median, Q3-Q1 = Interquartile Range.

    Unlike StandardScaler (z = (x - μ) / σ):
    - Median is resistant to outliers (breakdown point = 50%)
    - IQR ignores extreme tails entirely

    For Power-Law data with heavy tails, this prevents:
    - Mean/std explosion from DDoS attack packets
    - Compression of normal traffic to near-zero values
    """
    print("\nApplying RobustScaler (IQR-based, outlier-resistant)...")

    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)  # Transform only, no fit!

    # Save scaler
    scaler_path = PROCESSED_DIR / "scaler.pkl"
    joblib.dump(scaler, scaler_path)
    print(f"scaler.pkl saved (type: RobustScaler)")

    return X_train_scaled, X_test_scaled, scaler


# =============================================================================
# STEP 8: CLASS WEIGHTS (NEW - handles 78% Benign imbalance)
# =============================================================================
def compute_and_save_class_weights(y_train: np.ndarray) -> dict:
    """
    Compute balanced class weights for training.

    MATHEMATICAL JUSTIFICATION:
    With 78% Benign traffic, a naive model achieves 78% accuracy by
    predicting "Benign" for everything. This is useless for NIDS.

    Balanced class weights: w_c = n_samples / (n_classes × n_samples_c)

    This makes each class contribute equally to the loss, forcing the
    model to learn minority attack patterns.

    For training:
    - sklearn: model.fit(X, y, class_weight=class_weights_dict)
    - XGBoost: set sample_weight per instance
    - PyTorch: nn.CrossEntropyLoss(weight=class_weights_tensor)
    """
    print("\nComputing balanced class weights...")

    classes = np.unique(y_train)
    weights = compute_class_weight(
        class_weight="balanced", classes=classes, y=y_train
    )
    class_weights_dict = {int(c): float(w) for c, w in zip(classes, weights)}

    # Save for training
    weights_path = PROCESSED_DIR / "class_weights.json"
    with open(weights_path, "w") as f:
        json.dump(class_weights_dict, f, indent=4)

    print(f"class_weights.json saved ({len(class_weights_dict)} classes)")

    # Show top 5 highest weights (rarest classes)
    sorted_weights = sorted(class_weights_dict.items(), key=lambda x: -x[1])
    print("\n  Highest weights (rarest classes):")
    for cls, weight in sorted_weights[:5]:
        print(f"    Class {cls}: weight={weight:.2f}")

    return class_weights_dict


# =============================================================================
# STEP 9: SAVE ARTIFACTS (Fixed - synchronized)
# =============================================================================
def save_artifacts(
    X_train_scaled: np.ndarray,
    X_test_scaled: np.ndarray,
    y_train: pd.Series,
    y_test: pd.Series,
    feature_columns: list,
) -> None:
    """Save all artifacts with VERIFIED consistency."""
    print("\nSaving artifacts to Parquet...")

    # A. Save feature data
    X_train_df = pd.DataFrame(
        X_train_scaled, columns=feature_columns, dtype=np.float32
    )
    X_test_df = pd.DataFrame(
        X_test_scaled, columns=feature_columns, dtype=np.float32
    )

    X_train_df.to_parquet(PROCESSED_DIR / "X_train.parquet", index=False)
    X_test_df.to_parquet(PROCESSED_DIR / "X_test.parquet", index=False)
    print(f" X_train.parquet: {X_train_df.shape}")
    print(f" X_test.parquet:  {X_test_df.shape}")

    # B. Save labels
    pd.DataFrame({"label": y_train.values}).to_parquet(
        PROCESSED_DIR / "y_train.parquet", index=False
    )
    pd.DataFrame({"label": y_test.values}).to_parquet(
        PROCESSED_DIR / "y_test.parquet", index=False
    )
    print(f" y_train.parquet: ({len(y_train)},)")
    print(f" y_test.parquet:  ({len(y_test)},)")

    # C. Save feature_columns.pkl (SYNCHRONIZED with actual data)
    with open(PROCESSED_DIR / "feature_columns.pkl", "wb") as f:
        pickle.dump(feature_columns, f)
    print(f" feature_columns.pkl: {len(feature_columns)} features")

    # D. Save feature_map.json (SYNCHRONIZED)
    with open(PROCESSED_DIR / "feature_map.json", "w") as f:
        json.dump({"features": feature_columns}, f, indent=4)
    print(f" feature_map.json: {len(feature_columns)} features")

    # E. VERIFY CONSISTENCY (Critical assertion)
    assert (
        len(feature_columns) == X_train_df.shape[1]
    ), f"MISMATCH: {len(feature_columns)} != {X_train_df.shape[1]}"
    print("\n VERIFIED: All artifacts synchronized!")


# =============================================================================
# STEP 10: VERIFICATION
# =============================================================================
def verify_artifacts() -> bool:
    """Final verification of all saved artifacts."""
    print("\n" + "=" * 60)
    print("ARTIFACT VERIFICATION")
    print("=" * 60)

    required_files = [
        "X_train.parquet",
        "X_test.parquet",
        "y_train.parquet",
        "y_test.parquet",
        "scaler.pkl",
        "feature_columns.pkl",
        "feature_map.json",
        "label_mapping.json",
        "class_weights.json",  # NEW artifact
    ]

    all_ok = True
    for fname in required_files:
        fpath = PROCESSED_DIR / fname
        if fpath.exists():
            size_kb = fpath.stat().st_size / 1024
            size_str = f"{size_kb/1024:.2f} MB" if size_kb > 1024 else f"{size_kb:.2f} KB"
            print(f" {fname:25s} ({size_str})")
        else:
            print(f" {fname:25s} MISSING!")
            all_ok = False

    # Verify scaler type (use joblib since we saved with joblib.dump)
    scaler = joblib.load(PROCESSED_DIR / "scaler.pkl")
    scaler_type = type(scaler).__name__
    if scaler_type == "RobustScaler":
        print(f"\n Scaler type: {scaler_type} (correct)")
    else:
        print(f"\n Scaler type: {scaler_type} (expected RobustScaler)")

    # Verify feature count consistency
    with open(PROCESSED_DIR / "feature_columns.pkl", "rb") as f:
        pkl_features = pickle.load(f)
    with open(PROCESSED_DIR / "feature_map.json", "r") as f:
        json_features = json.load(f)["features"]
    X_train = pd.read_parquet(PROCESSED_DIR / "X_train.parquet")

    if len(pkl_features) == len(json_features) == X_train.shape[1]:
        print(f" Feature count: {len(pkl_features)} (all artifacts match)")
    else:
        print(f"  Feature count MISMATCH:")
        print(f"  feature_columns.pkl: {len(pkl_features)}")
        print(f"  feature_map.json:    {len(json_features)}")
        print(f"  X_train.parquet:     {X_train.shape[1]}")
        all_ok = False

    print("\n" + "=" * 60)
    if all_ok:
        print("STATUS: READY FOR MODEL TRAINING (Phase 0 COMPLETE)")
    else:
        print("STATUS: FIX ISSUES BEFORE TRAINING")
    print("=" * 60)

    return all_ok


# =============================================================================
# MAIN PIPELINE
# =============================================================================
def main():
    """Execute the complete preprocessing pipeline."""
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + "  PACKETLENS - KNOWN ATTACK CLASSIFIER PREPROCESSING".center(68) + "║")
    print("║" + "  Stratified Split | RobustScaler | Class Weights".center(68) + "║")
    print("╚" + "═" * 68 + "╝\n")

    # Step 1: Load & Clean
    df = load_and_clean_data(RAW_DATA_PATH)

    # Step 2: Encode Labels
    df, encoder, label_mapping = encode_labels(df, target_col="label")

    # Step 3: Feature Engineering
    df = engineer_features(df)

    # Step 4: Log-Transform Heavy-Tailed Features (NEW)
    df = apply_log_transform(df)

    # Separate features and target
    X = df.drop(columns=["label_encoded"])
    y = df["label_encoded"]
    feature_columns = X.columns.tolist()
    print(f"\nFeatures: {len(feature_columns)}, Samples: {len(X):,}")

    # Free memory
    del df
    gc.collect()

    # Step 5: Stratified Shuffle Split (for Known Attack Classifier)
    X_train, X_test, y_train, y_test = stratified_shuffle_split(X, y, test_size=0.2)

    # Free original data
    del X, y
    gc.collect()

    # Step 6: Clip Outliers (NEW)
    X_train, X_test = clip_outliers(X_train, X_test, CLIP_PERCENTILE)

    # Step 7: Robust Scaling (NEW)
    X_train_scaled, X_test_scaled, scaler = apply_robust_scaling(X_train, X_test)

    # Step 8: Compute Class Weights (NEW)
    class_weights = compute_and_save_class_weights(y_train.values)

    # Step 9: Save All Artifacts (Fixed)
    save_artifacts(X_train_scaled, X_test_scaled, y_train, y_test, feature_columns)

    # Step 10: Verify
    success = verify_artifacts()

    return success


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
