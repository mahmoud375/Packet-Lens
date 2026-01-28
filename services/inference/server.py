"""
PacketLens gRPC Inference Server
================================

Implements InferenceService with bidirectional streaming.
Receives FeatureVector messages, returns Verdict messages.
"""

import logging
import time
from pathlib import Path
from typing import Iterator

import grpc
import numpy as np

from .proto import (
    FeatureVector,
    Verdict,
    InferenceServiceServicer,
    add_InferenceServiceServicer_to_server,
)
from .core import ModelEngine

logger = logging.getLogger(__name__)


class InferenceServiceImpl(InferenceServiceServicer):
    """
    gRPC service implementation for real-time network intrusion detection.
    
    Uses bidirectional streaming for high-throughput, low-latency inference.
    Each incoming FeatureVector is processed and a Verdict is returned.
    """
    
    def __init__(self, engine: ModelEngine):
        """
        Initialize the service with a loaded ModelEngine.
        
        Args:
            engine: Pre-loaded ModelEngine instance
        """
        self._engine = engine
        self._request_count = 0
        self._start_time = time.time()
    
    def Classify(
        self,
        request_iterator: Iterator[FeatureVector],
        context: grpc.ServicerContext
    ) -> Iterator[Verdict]:
        """
        Bidirectional streaming RPC for classification.
        
        Receives a stream of FeatureVector messages and yields Verdict messages.
        Each feature vector is processed independently with minimal latency.
        
        Args:
            request_iterator: Stream of FeatureVector messages from Go sniffer
            context: gRPC context for the call
            
        Yields:
            Verdict messages with classification results
        """
        peer = context.peer() or "unknown"
        logger.info(f"New Classify stream from {peer}")
        
        for feature_vector in request_iterator:
            self._request_count += 1
            
            try:
                # Convert protobuf repeated float to numpy array
                features = np.array(feature_vector.features, dtype=np.float32)
                
                # Validate feature count
                expected = self._engine.expected_feature_count
                if len(features) != expected and expected > 0:
                    logger.warning(
                        f"Feature count mismatch: got {len(features)}, "
                        f"expected {expected} for flow {feature_vector.flow_id}"
                    )
                
                # Run inference (NumPy only - no pandas per tech-stack.md)
                label, confidence, inference_time_us = self._engine.predict(features)
                
                # Build and yield verdict
                verdict = Verdict(
                    flow_id=feature_vector.flow_id,
                    label=label,
                    confidence=confidence,
                    inference_time_us=inference_time_us,
                )
                
                if self._request_count % 1000 == 0:
                    logger.info(
                        f"Processed {self._request_count} requests | "
                        f"Last: {label} ({confidence:.2%}) in {inference_time_us}µs"
                    )
                
                yield verdict
                
            except Exception as e:
                logger.error(f"Inference error for flow {feature_vector.flow_id}: {e}")
                # Return error verdict instead of breaking stream
                yield Verdict(
                    flow_id=feature_vector.flow_id,
                    label="ERROR",
                    confidence=0.0,
                    inference_time_us=0,
                )
        
        logger.info(f"Classify stream from {peer} ended. Total: {self._request_count}")
    
    def get_stats(self) -> dict:
        """Return service statistics."""
        uptime = time.time() - self._start_time
        return {
            "request_count": self._request_count,
            "uptime_seconds": uptime,
            "requests_per_second": self._request_count / uptime if uptime > 0 else 0,
            "mock_mode": self._engine.is_mock,
        }


def create_server(
    engine: ModelEngine,
    port: int = 50051,
    max_workers: int = 10,
) -> grpc.Server:
    """
    Create and configure the gRPC server.
    
    Args:
        engine: Loaded ModelEngine instance
        port: Port to listen on (default: 50051)
        max_workers: Thread pool size for handling requests
        
    Returns:
        Configured grpc.Server (not started)
    """
    from concurrent import futures
    
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=[
            ("grpc.max_receive_message_length", 10 * 1024 * 1024),  # 10MB
            ("grpc.max_send_message_length", 10 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 10000),
            ("grpc.keepalive_timeout_ms", 5000),
            ("grpc.keepalive_permit_without_calls", True),
        ]
    )
    
    service = InferenceServiceImpl(engine)
    add_InferenceServiceServicer_to_server(service, server)
    
    server.add_insecure_port(f"[::]:{port}")
    
    return server
