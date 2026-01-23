#!/usr/bin/env python3
"""
Zero-Tolerance Deep Audit Script for PacketLens Data Preprocessing
===================================================================
This script performs comprehensive validation of all data artifacts.
"""

import json
import pickle
import sys
from pathlib import Path
import pandas as pd
import numpy as np

# ============================================================================
# CONFIGURATION
# ============================================================================
PROCESSED_DIR = Path(__file__).parent / "data" / "processed"

RESULTS = {
    "alignment_check": {"status": None, "details": {}},
    "schema_consistency": {"status": None, "details": {}},
    "data_health": {"status": None, "details": {}},
    "artifact_validity": {"status": None, "details": {}},
    "critical_issues": [],
    "stats": {}
}

def print_header(title: str):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def print_result(check_name: str, status: bool, message: str = ""):
    icon = "PASS" if status else "FAIL"
    print(f"  [{icon}] {check_name}")
    if message:
        print(f"         └─ {message}")

# ============================================================================
# 1. ALIGNMENT CHECK (Row-Match Test)
# ============================================================================
def alignment_check():
    print_header("1. ALIGNMENT CHECK (Row-Match Test)")
    
    try:
        X_train = pd.read_parquet(PROCESSED_DIR / "X_train.parquet")
        y_train = pd.read_parquet(PROCESSED_DIR / "y_train.parquet")
        X_test = pd.read_parquet(PROCESSED_DIR / "X_test.parquet")
        y_test = pd.read_parquet(PROCESSED_DIR / "y_test.parquet")
    except Exception as e:
        RESULTS["alignment_check"]["status"] = False
        RESULTS["critical_issues"].append(f"Failed to load parquet files: {e}")
        print_result("Load parquet files", False, str(e))
        return
    
    # Train set alignment
    train_aligned = len(X_train) == len(y_train)
    train_msg = f"X_train: {len(X_train):,} rows | y_train: {len(y_train):,} rows"
    print_result("Train set row alignment", train_aligned, train_msg)
    
    # Test set alignment
    test_aligned = len(X_test) == len(y_test)
    test_msg = f"X_test: {len(X_test):,} rows | y_test: {len(y_test):,} rows"
    print_result("Test set row alignment", test_aligned, test_msg)
    
    RESULTS["alignment_check"]["status"] = train_aligned and test_aligned
    RESULTS["alignment_check"]["details"] = {
        "X_train_shape": X_train.shape,
        "y_train_shape": y_train.shape,
        "X_test_shape": X_test.shape,
        "y_test_shape": y_test.shape,
        "train_aligned": train_aligned,
        "test_aligned": test_aligned
    }
    RESULTS["stats"]["X_train_rows"] = len(X_train)
    RESULTS["stats"]["X_train_cols"] = X_train.shape[1]
    RESULTS["stats"]["X_test_rows"] = len(X_test)
    RESULTS["stats"]["X_test_cols"] = X_test.shape[1]
    
    if not train_aligned:
        RESULTS["critical_issues"].append(f"Train set MISALIGNED: X_train={len(X_train)}, y_train={len(y_train)}")
    if not test_aligned:
        RESULTS["critical_issues"].append(f"Test set MISALIGNED: X_test={len(X_test)}, y_test={len(y_test)}")
    
    return X_train, y_train, X_test, y_test

# ============================================================================
# 2. SCHEMA CONSISTENCY (Contract Test)
# ============================================================================
def schema_consistency_check(X_train, y_train, y_test):
    print_header("2. SCHEMA CONSISTENCY (Contract Test)")
    
    # Load feature_map.json
    try:
        with open(PROCESSED_DIR / "feature_map.json", "r") as f:
            feature_map = json.load(f)
        features_in_map = feature_map.get("features", [])
    except Exception as e:
        RESULTS["schema_consistency"]["status"] = False
        RESULTS["critical_issues"].append(f"Failed to load feature_map.json: {e}")
        print_result("Load feature_map.json", False, str(e))
        return
    
    # Load label_mapping.json
    try:
        with open(PROCESSED_DIR / "label_mapping.json", "r") as f:
            label_mapping = json.load(f)
        label_to_int = label_mapping.get("label_to_int", {})
        int_to_label = label_mapping.get("int_to_label", {})
    except Exception as e:
        RESULTS["critical_issues"].append(f"Failed to load label_mapping.json: {e}")
        print_result("Load label_mapping.json", False, str(e))
        return
    
    # Feature count check
    n_features_map = len(features_in_map)
    n_features_data = X_train.shape[1]
    feature_count_match = n_features_map == n_features_data
    print_result("Feature count match", feature_count_match, 
                 f"feature_map: {n_features_map} | X_train columns: {n_features_data}")
    
    # Feature order check
    data_columns = list(X_train.columns)
    feature_order_match = features_in_map == data_columns
    if not feature_order_match:
        missing_in_data = set(features_in_map) - set(data_columns)
        missing_in_map = set(data_columns) - set(features_in_map)
        msg = ""
        if missing_in_data:
            msg += f"Missing in data: {missing_in_data}. "
        if missing_in_map:
            msg += f"Missing in map: {missing_in_map}."
        print_result("Feature order match", False, msg or "Order mismatch")
    else:
        print_result("Feature order match", True, "Exact match in order and content")
    
    # Label mapping check
    # Get unique labels from y_train and y_test
    y_train_col = y_train.columns[0] if len(y_train.columns) > 0 else None
    y_test_col = y_test.columns[0] if len(y_test.columns) > 0 else None
    
    if y_train_col:
        unique_train = set(y_train[y_train_col].unique())
    else:
        unique_train = set(y_train.iloc[:, 0].unique())
    
    if y_test_col:
        unique_test = set(y_test[y_test_col].unique())
    else:
        unique_test = set(y_test.iloc[:, 0].unique())
    
    all_unique_labels = unique_train.union(unique_test)
    
    # Check if labels are integers (encoded) or strings
    sample_label = next(iter(all_unique_labels))
    if isinstance(sample_label, (int, np.integer)):
        # Labels are encoded as integers
        valid_ints = set(int(k) for k in int_to_label.keys())
        ghost_classes = all_unique_labels - valid_ints
        label_check = len(ghost_classes) == 0
        print_result("Labels in mapping (int)", label_check, 
                     f"Unique labels in data: {sorted(all_unique_labels)}")
    else:
        # Labels are strings
        valid_labels = set(label_to_int.keys())
        ghost_classes = all_unique_labels - valid_labels
        label_check = len(ghost_classes) == 0
        print_result("Labels in mapping (str)", label_check, 
                     f"Unique labels in data: {len(all_unique_labels)}")
    
    if ghost_classes:
        print_result("Ghost Class Detection", False, f"GHOST CLASSES FOUND: {ghost_classes}")
        RESULTS["critical_issues"].append(f"Ghost classes in data not in mapping: {ghost_classes}")
    else:
        print_result("Ghost Class Detection", True, "No ghost classes found")
    
    RESULTS["schema_consistency"]["status"] = feature_count_match and feature_order_match and label_check
    RESULTS["schema_consistency"]["details"] = {
        "n_features_map": n_features_map,
        "n_features_data": n_features_data,
        "feature_count_match": feature_count_match,
        "feature_order_match": feature_order_match,
        "n_classes": len(label_to_int),
        "ghost_classes": list(ghost_classes) if ghost_classes else []
    }
    RESULTS["stats"]["n_features"] = n_features_data
    RESULTS["stats"]["n_classes"] = len(label_to_int)
    
    if not feature_count_match:
        RESULTS["critical_issues"].append(f"Feature count mismatch: map={n_features_map}, data={n_features_data}")
    if not feature_order_match:
        RESULTS["critical_issues"].append("Feature order/content mismatch between feature_map.json and X_train")

# ============================================================================
# 3. DATA HEALTH (Cleanliness Test)
# ============================================================================
def data_health_check(X_train, X_test):
    print_header("3. DATA HEALTH (Cleanliness Test)")
    
    # NaN check
    nan_train = X_train.isna().sum().sum()
    nan_test = X_test.isna().sum().sum()
    nan_free = nan_train == 0 and nan_test == 0
    print_result("NaN values check", nan_free, 
                 f"X_train NaN: {nan_train:,} | X_test NaN: {nan_test:,}")
    
    # Inf check
    inf_train = np.isinf(X_train.select_dtypes(include=[np.number])).sum().sum()
    inf_test = np.isinf(X_test.select_dtypes(include=[np.number])).sum().sum()
    inf_free = inf_train == 0 and inf_test == 0
    print_result("Inf/-Inf values check", inf_free, 
                 f"X_train Inf: {inf_train:,} | X_test Inf: {inf_test:,}")
    
    # Data type check
    dtypes_train = X_train.dtypes.unique()
    dtypes_test = X_test.dtypes.unique()
    print(f"\n  [INFO] X_train dtypes: {list(dtypes_train)}")
    print(f"  [INFO] X_test dtypes: {list(dtypes_test)}")
    
    using_float32 = all('float32' in str(dt) for dt in dtypes_train)
    using_float64 = all('float64' in str(dt) for dt in dtypes_train)
    
    if using_float32:
        print_result("Memory efficiency (float32)", True, "Using float32 (optimal)")
    elif using_float64:
        print_result("Memory efficiency (float64)", False, 
                     "Using float64 - Consider converting to float32 for memory savings")
    else:
        print_result("Data types", True, "Mixed types detected")
    
    # Sanity checks for specific columns
    sanity_passed = True
    sanity_issues = []
    
    # Check for negative flow_duration
    if 'flow_duration' in X_train.columns:
        neg_duration_train = (X_train['flow_duration'] < 0).sum()
        neg_duration_test = (X_test['flow_duration'] < 0).sum()
        if neg_duration_train > 0 or neg_duration_test > 0:
            sanity_passed = False
            sanity_issues.append(f"Negative flow_duration: train={neg_duration_train}, test={neg_duration_test}")
        print_result("flow_duration >= 0", neg_duration_train == 0 and neg_duration_test == 0,
                     f"Negative values: train={neg_duration_train:,}, test={neg_duration_test:,}")
    
    # Check for negative packet lengths
    length_cols = [c for c in X_train.columns if 'length' in c.lower()]
    for col in length_cols[:3]:  # Check first 3 length columns
        neg_train = (X_train[col] < 0).sum()
        neg_test = (X_test[col] < 0).sum()
        if neg_train > 0 or neg_test > 0:
            sanity_passed = False
            sanity_issues.append(f"Negative {col}: train={neg_train}, test={neg_test}")
    
    if length_cols:
        print_result("Packet length columns >= 0", 
                     all((X_train[c] >= 0).all() and (X_test[c] >= 0).all() for c in length_cols[:3]),
                     f"Checked: {length_cols[:3]}")
    
    RESULTS["data_health"]["status"] = nan_free and inf_free and sanity_passed
    RESULTS["data_health"]["details"] = {
        "nan_train": nan_train,
        "nan_test": nan_test,
        "inf_train": inf_train,
        "inf_test": inf_test,
        "dtypes": [str(dt) for dt in dtypes_train],
        "sanity_issues": sanity_issues
    }
    
    if not nan_free:
        RESULTS["critical_issues"].append(f"NaN values found: train={nan_train}, test={nan_test}")
    if not inf_free:
        RESULTS["critical_issues"].append(f"Inf values found: train={inf_train}, test={inf_test}")
    for issue in sanity_issues:
        RESULTS["critical_issues"].append(issue)

# ============================================================================
# 4. ARTIFACT VALIDITY (Scaler Check)
# ============================================================================
def artifact_validity_check(X_train):
    print_header("4. ARTIFACT VALIDITY (Scaler Check)")
    
    try:
        with open(PROCESSED_DIR / "scaler.pkl", "rb") as f:
            scaler = pickle.load(f)
    except Exception as e:
        RESULTS["artifact_validity"]["status"] = False
        RESULTS["critical_issues"].append(f"Failed to load scaler.pkl: {e}")
        print_result("Load scaler.pkl", False, str(e))
        return
    
    # Check scaler type
    scaler_type = type(scaler).__name__
    is_standard_scaler = scaler_type == "StandardScaler"
    print_result("Scaler type check", is_standard_scaler, f"Type: {scaler_type}")
    
    # Check if fitted
    has_mean = hasattr(scaler, 'mean_') and scaler.mean_ is not None
    has_scale = hasattr(scaler, 'scale_') and scaler.scale_ is not None
    is_fitted = has_mean and has_scale
    print_result("Scaler is fitted", is_fitted, 
                 f"has mean_: {has_mean} | has scale_: {has_scale}")
    
    # Check feature count match
    if is_fitted:
        scaler_n_features = len(scaler.mean_)
        data_n_features = X_train.shape[1]
        features_match = scaler_n_features == data_n_features
        print_result("Scaler feature count match", features_match,
                     f"Scaler expects: {scaler_n_features} | X_train has: {data_n_features}")
        
        if not features_match:
            RESULTS["critical_issues"].append(
                f"Scaler feature mismatch: scaler={scaler_n_features}, data={data_n_features}")
    else:
        features_match = False
        print_result("Scaler feature count match", False, "Cannot check - scaler not fitted")
        RESULTS["critical_issues"].append("Scaler is not properly fitted (missing mean_ or scale_)")
    
    RESULTS["artifact_validity"]["status"] = is_standard_scaler and is_fitted and features_match
    RESULTS["artifact_validity"]["details"] = {
        "scaler_type": scaler_type,
        "is_fitted": is_fitted,
        "n_features_scaler": len(scaler.mean_) if is_fitted else None,
        "n_features_data": X_train.shape[1]
    }

# ============================================================================
# FINAL SUMMARY
# ============================================================================
def print_summary():
    print_header("FINAL AUDIT SUMMARY")
    
    checks = [
        ("Alignment Check", RESULTS["alignment_check"]["status"]),
        ("Schema Consistency", RESULTS["schema_consistency"]["status"]),
        ("Data Health", RESULTS["data_health"]["status"]),
        ("Artifact Validity", RESULTS["artifact_validity"]["status"]),
    ]
    
    all_passed = all(status for _, status in checks if status is not None)
    
    print("\n  CHECK RESULTS:")
    for name, status in checks:
        icon = "[PASS]" if status else "[FAIL]" if status is False else "[WARN]"
        print(f"    {icon} {name}")
    
    print("\n  STATISTICS:")
    print(f"    • Training Rows:  {RESULTS['stats'].get('X_train_rows', 'N/A'):,}")
    print(f"    • Test Rows:      {RESULTS['stats'].get('X_test_rows', 'N/A'):,}")
    print(f"    • Features:       {RESULTS['stats'].get('n_features', 'N/A')}")
    print(f"    • Classes:        {RESULTS['stats'].get('n_classes', 'N/A')}")
    
    if RESULTS["critical_issues"]:
        print("\n  CRITICAL ISSUES:")
        for issue in RESULTS["critical_issues"]:
            print(f"    • {issue}")
    
    print("\n" + "="*70)
    if all_passed and not RESULTS["critical_issues"]:
        print("  VERDICT: DATA IS 100% READY FOR MODELING")
    else:
        print("  VERDICT: DATA HAS ISSUES - DO NOT PROCEED TO MODELING")
    print("="*70 + "\n")
    
    return all_passed and not RESULTS["critical_issues"]

# ============================================================================
# MAIN
# ============================================================================
def main():
    print("\n")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║     PACKETLENS - ZERO-TOLERANCE DATA PREPROCESSING AUDIT             ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(f"\n  Artifacts Directory: {PROCESSED_DIR}")
    print(f"  Artifacts Found: {list(PROCESSED_DIR.glob('*'))}")
    
    # Run all checks
    result = alignment_check()
    if result:
        X_train, y_train, X_test, y_test = result
        schema_consistency_check(X_train, y_train, y_test)
        data_health_check(X_train, X_test)
        artifact_validity_check(X_train)
    
    # Print summary
    success = print_summary()
    
    # Return results as JSON for programmatic access
    return RESULTS, success

if __name__ == "__main__":
    results, success = main()
    sys.exit(0 if success else 1)
