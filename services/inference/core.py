"""
PacketLens Inference Engine - Core Module
==========================================

This module implements the ONNX-based inference engine for network
intrusion detection. It is designed for high-throughput, low-latency
prediction in a production gRPC service.

Architecture Decisions:
-----------------------
1. ONNX Runtime: Provides 2-5x faster inference than native XGBoost
   and enables deployment without XGBoost dependencies.

2. Session Persistence: The ONNX session is loaded ONCE at init and
   reused for all predictions. This avoids the ~100ms model load
   overhead per request.

3. NumPy-Only Interface: The predict() method accepts raw numpy arrays,
   avoiding pandas overhead in the hot path (~10µs per DataFrame creation).

4. Thread Safety: ONNX Runtime sessions are thread-safe for inference.
   Multiple concurrent calls to predict() are safe.

5. Feature Alignment: Production inference applies the SAME transforms
   as training (log1p on heavy-tail features + RobustScaler) to ensure
   the model sees data from the correct distribution.

Author: PacketLens ML Team
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import onnxruntime as ort

# Configure module logger
logger = logging.getLogger(__name__)

# =========================================================================
# HEAVY-TAIL FEATURES (must match corrected_preprocessing.py exactly)
# =========================================================================
# These features follow Power-Law distributions and were log1p-transformed
# during training. We must apply the same transform at inference time.
HEAVY_TAIL_FEATURES = frozenset([
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
])


class InferenceEngine:
    """
    High-performance ONNX inference engine for network intrusion detection.
    
    This class manages the ONNX session and model artifacts, providing
    a simple predict() interface for the gRPC service layer.
    
    Attributes:
        session: ONNX Runtime InferenceSession (loaded once, reused)
        label_mapping: Dict mapping class indices to human-readable labels
        feature_map: List of expected feature names (for validation)
        input_name: Name of the ONNX model's input tensor
        n_features: Expected number of input features
        n_classes: Number of output classes
        scaler: RobustScaler loaded from training artifacts (or None)
        _log1p_indices: Numpy array of feature indices requiring log1p
    """
    
    # Default paths (relative to project root)
    DEFAULT_MODEL_PATH = Path("services/inference/model_store/model.onnx")
    DEFAULT_LABEL_MAPPING_PATH = Path("data/processed/label_mapping.json")
    DEFAULT_FEATURE_MAP_PATH = Path("data/processed/feature_map.json")
    DEFAULT_SCALER_PATH = Path("data/processed/scaler.pkl")
    
    def __init__(
        self,
        model_path: Path | None = None,
        label_mapping_path: Path | None = None,
        feature_map_path: Path | None = None,
        scaler_path: Path | None = None,
    ) -> None:
        """
        Initialize the inference engine by loading model and artifacts.
        
        Args:
            model_path: Path to ONNX model file
            label_mapping_path: Path to label_mapping.json
            feature_map_path: Path to feature_map.json
            scaler_path: Path to scaler.pkl (optional, graceful fallback)
            
        Raises:
            FileNotFoundError: If any required file is missing
            ValueError: If feature count doesn't match ONNX input shape
        """
        # Use defaults if not provided
        model_path = model_path or self.DEFAULT_MODEL_PATH
        label_mapping_path = label_mapping_path or self.DEFAULT_LABEL_MAPPING_PATH
        feature_map_path = feature_map_path or self.DEFAULT_FEATURE_MAP_PATH
        scaler_path = scaler_path or self.DEFAULT_SCALER_PATH
        
        logger.info(f"Initializing InferenceEngine...")
        logger.info(f"  Model: {model_path}")
        logger.info(f"  Labels: {label_mapping_path}")
        logger.info(f"  Features: {feature_map_path}")
        logger.info(f"  Scaler: {scaler_path}")
        
        # =====================================================================
        # STEP 1: Load ONNX Model
        # =====================================================================
        # Session options for production performance
        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        sess_options.intra_op_num_threads = 4  # Parallel ops within a single inference
        sess_options.inter_op_num_threads = 1  # Sequential between ops (simpler)
        
        # Prefer CPU execution provider (most portable)
        # Can add CUDAExecutionProvider for GPU if available
        providers = ["CPUExecutionProvider"]
        
        self.session = ort.InferenceSession(
            str(model_path),
            sess_options=sess_options,
            providers=providers,
        )
        
        # Extract input/output metadata
        self.input_name = self.session.get_inputs()[0].name
        input_shape = self.session.get_inputs()[0].shape
        self.n_features = input_shape[1]  # [batch, features]
        
        output_shape = self.session.get_outputs()[1].shape  # probabilities output
        self.n_classes = output_shape[1] if len(output_shape) > 1 else 33
        
        logger.info(f"  ONNX loaded: input={self.input_name}, shape={input_shape}")
        
        # =====================================================================
        # STEP 2: Load Label Mapping
        # =====================================================================
        with open(label_mapping_path, "r") as f:
            label_data = json.load(f)
        
        # The mapping is stored as {index: label_name}
        # Handle both string and int keys
        int_to_label = label_data.get("int_to_label", {})
        self.label_mapping: dict[int, str] = {
            int(k): v for k, v in int_to_label.items()
        }
        
        logger.info(f"  Labels: {len(self.label_mapping)} classes")
        
        # =====================================================================
        # STEP 3: Load Feature Map
        # =====================================================================
        with open(feature_map_path, "r") as f:
            feature_data = json.load(f)
        
        self.feature_map: list[str] = feature_data.get("features", [])
        
        # =====================================================================
        # STEP 4: Validate Feature Count
        # =====================================================================
        # CRITICAL: Ensure feature count matches ONNX input shape
        # This catches preprocessing/model version mismatches at startup
        if len(self.feature_map) != self.n_features:
            raise ValueError(
                f"Feature count mismatch! "
                f"feature_map.json has {len(self.feature_map)} features, "
                f"but ONNX model expects {self.n_features}. "
                f"Regenerate artifacts or retrain model."
            )
        
        logger.info(f"  Features: {len(self.feature_map)} (validated against ONNX)")
        
        # =====================================================================
        # STEP 5: Build Log1p Index Mask (from feature_map + HEAVY_TAIL list)
        # =====================================================================
        # Pre-compute which feature indices need log1p at inference time.
        # This avoids string lookups on every predict() call.
        self._log1p_indices = np.array([
            i for i, name in enumerate(self.feature_map)
            if name in HEAVY_TAIL_FEATURES
        ], dtype=np.intp)
        
        logger.info(
            f"  Log1p mask: {len(self._log1p_indices)} of "
            f"{len(self.feature_map)} features"
        )
        
        # =====================================================================
        # STEP 6: Load Scaler (Graceful Fallback)
        # =====================================================================
        # The scaler is critical for correct predictions but we allow
        # running without it for local dev / debugging convenience.
        self.scaler = None
        try:
            self.scaler = joblib.load(scaler_path)
            scaler_type = type(self.scaler).__name__
            logger.info(f"  Scaler loaded: {scaler_type} ✓")
            
            # Validate scaler feature count
            # RobustScaler stores center_ (median) with shape (n_features,)
            if hasattr(self.scaler, "center_"):
                scaler_n = len(self.scaler.center_)
            elif hasattr(self.scaler, "mean_"):
                scaler_n = len(self.scaler.mean_)
            else:
                scaler_n = -1
            
            if scaler_n != -1 and scaler_n != self.n_features:
                logger.error(
                    f"  Scaler feature mismatch: scaler has {scaler_n}, "
                    f"model expects {self.n_features}. Disabling scaler."
                )
                self.scaler = None
        except FileNotFoundError:
            logger.warning(
                f"  Scaler not found at {scaler_path}. "
                f"Running WITHOUT preprocessing transforms. "
                f"Predictions may be inaccurate!"
            )
        except Exception as e:
            logger.warning(
                f"  Failed to load scaler: {e}. "
                f"Running WITHOUT preprocessing transforms."
            )
        
        logger.info("InferenceEngine initialized successfully ✓")
    
    def _apply_preprocessing(self, features: np.ndarray) -> np.ndarray:
        """
        Apply the same transforms used during training.
        
        Pipeline (must match corrected_preprocessing.py):
            1. Clip negatives to 0 for heavy-tail features
            2. log1p() on heavy-tail features
            3. RobustScaler.transform()
        
        Args:
            features: Raw float32 array of shape (1, n_features)
            
        Returns:
            Transformed float32 array of shape (1, n_features)
        """
        # Work on a copy to avoid mutating the caller's data
        features = features.copy()
        
        # Step 1 & 2: log1p on heavy-tail features (clip negatives first)
        if len(self._log1p_indices) > 0:
            features[:, self._log1p_indices] = np.log1p(
                np.clip(features[:, self._log1p_indices], 0, None)
            )
        
        # Step 3: RobustScaler
        if self.scaler is not None:
            features = self.scaler.transform(features)
        
        # Ensure float32 after transform (scaler may output float64)
        return features.astype(np.float32)
    
    def predict(self, features: np.ndarray) -> Tuple[str, float, float]:
        """
        Run inference on a single feature vector.
        
        This method is designed for maximum throughput:
        - No DataFrame creation (numpy only)
        - No model reloading
        - Minimal memory allocation
        
        Args:
            features: Float32 numpy array of shape (n_features,) or (1, n_features)
            
        Returns:
            Tuple of:
                - label: Human-readable class name (e.g., "DDoS-HOIC")
                - confidence: Softmax probability [0.0, 1.0]
                - inference_time_ms: Time spent in ONNX inference
                
        Raises:
            ValueError: If feature count doesn't match expected
        """
        start_time = time.perf_counter()
        
        # =====================================================================
        # INPUT VALIDATION & RESHAPING
        # =====================================================================
        # Ensure correct shape: [1, n_features] for single sample batch
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Validate feature count
        if features.shape[1] != self.n_features:
            raise ValueError(
                f"Feature count mismatch: got {features.shape[1]}, "
                f"expected {self.n_features}"
            )
        
        # Ensure float32 (ONNX requirement)
        if features.dtype != np.float32:
            features = features.astype(np.float32)
        
        # =====================================================================
        # PREPROCESSING (match training pipeline)
        # =====================================================================
        features = self._apply_preprocessing(features)
        
        # =====================================================================
        # ONNX INFERENCE
        # =====================================================================
        # Run inference - returns [labels, probabilities]
        outputs = self.session.run(None, {self.input_name: features})
        
        # outputs[0] = labels (int64), outputs[1] = probabilities (float32)
        # For softprob objective, probabilities has shape [batch, n_classes]
        probabilities = outputs[1][0]  # First (only) sample
        
        # Get predicted class and confidence
        pred_idx = int(np.argmax(probabilities))
        confidence = float(probabilities[pred_idx])
        
        # Map index to human-readable label
        label = self.label_mapping.get(pred_idx, f"UNKNOWN_{pred_idx}")
        
        # Calculate inference time
        inference_time_ms = (time.perf_counter() - start_time) * 1000
        
        return label, confidence, inference_time_ms
    
    def predict_batch(
        self, features: np.ndarray
    ) -> list[Tuple[str, float]]:
        """
        Run inference on a batch of feature vectors.
        
        More efficient than calling predict() in a loop due to
        ONNX Runtime's internal batching optimizations.
        
        Args:
            features: Float32 numpy array of shape (batch_size, n_features)
            
        Returns:
            List of (label, confidence) tuples
        """
        # Ensure correct dtype
        if features.dtype != np.float32:
            features = features.astype(np.float32)
        
        # Apply preprocessing (same transforms as training)
        features = self._apply_preprocessing(features)
        
        # Run batched inference
        outputs = self.session.run(None, {self.input_name: features})
        probabilities = outputs[1]  # Shape: [batch, n_classes]
        
        # Process each sample
        results = []
        for probs in probabilities:
            pred_idx = int(np.argmax(probs))
            confidence = float(probs[pred_idx])
            label = self.label_mapping.get(pred_idx, f"UNKNOWN_{pred_idx}")
            results.append((label, confidence))
        
        return results
    
    @property
    def expected_features(self) -> int:
        """Number of features expected by the model."""
        return self.n_features
    
    @property
    def class_labels(self) -> list[str]:
        """List of all class labels in order."""
        return [
            self.label_mapping.get(i, f"UNKNOWN_{i}")
            for i in range(self.n_classes)
        ]
