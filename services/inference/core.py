"""
PacketLens Model Engine
=======================

Core inference engine that loads artifacts and performs predictions.
Follows tech-stack.md rules: NumPy arrays only, no pandas in inference loop.
"""

import json
import logging
import pickle
import time
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


class ModelEngine:
    """
    High-performance inference engine for network intrusion detection.
    
    Loads artifacts from data/processed/ at startup:
    - scaler.pkl: StandardScaler for feature normalization
    - feature_map.json: Feature name → index mapping
    - label_mapping.json: Model output index → attack label
    - model.onnx: ONNX model for inference
    
    Supports Mock Mode when model.onnx is missing for connectivity testing.
    """
    
    def __init__(self, data_dir: Path, mock_mode: bool = False):
        """
        Initialize the ModelEngine.
        
        Args:
            data_dir: Path to data/processed/ directory
            mock_mode: If True, use dummy predictor when model is missing
        """
        self.data_dir = data_dir
        self.mock_mode = mock_mode
        self._onnx_session: Optional[object] = None
        self._scaler: Optional[object] = None
        self._feature_map: dict = {}
        self._label_mapping: dict = {}
        self._is_mock: bool = False
        
    def load(self) -> None:
        """
        Load all artifacts. Must be called before predict().
        
        Raises:
            FileNotFoundError: If required artifacts are missing (non-mock mode)
            RuntimeError: If artifacts are corrupted
        """
        logger.info(f"Loading artifacts from {self.data_dir}")
        
        # 1. Load scaler (required)
        scaler_path = self.data_dir / "scaler.pkl"
        if scaler_path.exists():
            try:
                with open(scaler_path, "rb") as f:
                    self._scaler = pickle.load(f)
                logger.info("✓ Loaded scaler.pkl")
            except Exception as e:
                if not self.mock_mode:
                    raise RuntimeError(f"Failed to load scaler.pkl: {e}")
                logger.warning(f"⚠ scaler.pkl corrupted ({e}) - using identity transform")
                self._scaler = None
        else:
            if not self.mock_mode:
                raise FileNotFoundError(f"Required artifact missing: {scaler_path}")
            logger.warning("⚠ scaler.pkl not found - using identity transform")
            self._scaler = None
        
        # 2. Load feature map (required)
        feature_map_path = self.data_dir / "feature_map.json"
        if feature_map_path.exists():
            with open(feature_map_path, "r") as f:
                self._feature_map = json.load(f)
            logger.info(f"✓ Loaded feature_map.json ({len(self._feature_map)} features)")
        else:
            if not self.mock_mode:
                raise FileNotFoundError(f"Required artifact missing: {feature_map_path}")
            logger.warning("⚠ feature_map.json not found - using empty map")
            self._feature_map = {}
        
        # 3. Load label mapping (required)
        label_map_path = self.data_dir / "label_mapping.json"
        if label_map_path.exists():
            with open(label_map_path, "r") as f:
                self._label_mapping = json.load(f)
            logger.info(f"✓ Loaded label_mapping.json ({len(self._label_mapping)} labels)")
        else:
            if not self.mock_mode:
                raise FileNotFoundError(f"Required artifact missing: {label_map_path}")
            logger.warning("⚠ label_mapping.json not found - using default labels")
            self._label_mapping = {"0": "BENIGN", "1": "ATTACK"}
        
        # 4. Load ONNX model (optional in mock mode)
        model_path = self.data_dir / "model.onnx"
        if model_path.exists():
            import onnxruntime as ort
            self._onnx_session = ort.InferenceSession(
                str(model_path),
                providers=["CPUExecutionProvider"]
            )
            logger.info("✓ Loaded model.onnx")
            self._is_mock = False
        else:
            if not self.mock_mode:
                raise FileNotFoundError(f"Required artifact missing: {model_path}")
            logger.warning("⚠ model.onnx not found - RUNNING IN MOCK MODE")
            self._is_mock = True
        
        logger.info(f"ModelEngine ready (mock={self._is_mock})")
    
    @property
    def expected_feature_count(self) -> int:
        """Number of features expected by the model."""
        return len(self._feature_map) if self._feature_map else 78  # Default CIC-IDS2017
    
    @property
    def is_mock(self) -> bool:
        """True if running in mock mode with dummy predictor."""
        return self._is_mock
    
    def predict(self, features: np.ndarray) -> tuple[str, float, int]:
        """
        Perform inference on a feature vector.
        
        Args:
            features: 1D numpy array of float32 features
            
        Returns:
            Tuple of (label, confidence, inference_time_us)
            
        Note:
            Uses NumPy arrays directly - no pandas DataFrames per tech-stack.md
        """
        start_us = time.perf_counter_ns() // 1000
        
        # Ensure correct shape and type
        if features.ndim == 1:
            features = features.reshape(1, -1)
        features = features.astype(np.float32)
        
        # Apply scaler if available
        if self._scaler is not None:
            features = self._scaler.transform(features)
        
        if self._is_mock:
            # Mock prediction for connectivity testing
            label = "BENIGN"
            confidence = 0.95
        else:
            # Real ONNX inference
            input_name = self._onnx_session.get_inputs()[0].name
            outputs = self._onnx_session.run(None, {input_name: features})
            
            # Get prediction and confidence
            logits = outputs[0][0]
            pred_idx = int(np.argmax(logits))
            confidence = float(np.max(self._softmax(logits)))
            label = self._label_mapping.get(str(pred_idx), f"UNKNOWN_{pred_idx}")
        
        end_us = time.perf_counter_ns() // 1000
        inference_time_us = end_us - start_us
        
        return label, confidence, inference_time_us
    
    @staticmethod
    def _softmax(x: np.ndarray) -> np.ndarray:
        """Compute softmax probabilities."""
        exp_x = np.exp(x - np.max(x))
        return exp_x / exp_x.sum()
