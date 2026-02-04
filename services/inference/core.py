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

Author: PacketLens ML Team
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Tuple

import numpy as np
import onnxruntime as ort

# Configure module logger
logger = logging.getLogger(__name__)


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
    """
    
    # Default paths (relative to project root)
    DEFAULT_MODEL_PATH = Path("services/inference/model_store/model.onnx")
    DEFAULT_LABEL_MAPPING_PATH = Path("data/processed/label_mapping.json")
    DEFAULT_FEATURE_MAP_PATH = Path("data/processed/feature_map.json")
    
    def __init__(
        self,
        model_path: Path | None = None,
        label_mapping_path: Path | None = None,
        feature_map_path: Path | None = None,
    ) -> None:
        """
        Initialize the inference engine by loading model and artifacts.
        
        Args:
            model_path: Path to ONNX model file
            label_mapping_path: Path to label_mapping.json
            feature_map_path: Path to feature_map.json
            
        Raises:
            FileNotFoundError: If any required file is missing
            ValueError: If feature count doesn't match ONNX input shape
        """
        # Use defaults if not provided
        model_path = model_path or self.DEFAULT_MODEL_PATH
        label_mapping_path = label_mapping_path or self.DEFAULT_LABEL_MAPPING_PATH
        feature_map_path = feature_map_path or self.DEFAULT_FEATURE_MAP_PATH
        
        logger.info(f"Initializing InferenceEngine...")
        logger.info(f"  Model: {model_path}")
        logger.info(f"  Labels: {label_mapping_path}")
        logger.info(f"  Features: {feature_map_path}")
        
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
        logger.info("InferenceEngine initialized successfully ✓")
    
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
