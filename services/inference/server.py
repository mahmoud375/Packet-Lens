"""
PacketLens Inference Server - gRPC Handler Module
===================================================

This module implements the async gRPC service handler for the
network intrusion detection inference service.

Architecture Decisions:
-----------------------
1. grpc.aio (AsyncIO): We use gRPC's native async implementation
   instead of the synchronous threading model. This enables:
   - True non-blocking I/O for thousands of concurrent streams
   - Cooperative multitasking without thread pool exhaustion
   - Lower memory footprint (~8KB per coroutine vs ~1MB per thread)

2. asyncio.to_thread for Inference: Although ONNX inference is fast
   (~1-5ms), it's a CPU-bound operation that blocks the event loop.
   We offload it to a thread pool to prevent blocking other streams.
   For sub-millisecond inference, this could be removed.

3. Bidirectional Streaming: The Classify RPC uses bidirectional
   streaming (stream FeatureVector → stream Verdict). This:
   - Amortizes connection overhead across many predictions
   - Enables real-time packet-by-packet classification
   - Maintains flow context within a single stream

4. Error Isolation: Individual prediction failures yield ERROR verdicts
   instead of terminating the stream. This ensures one bad packet
   doesn't kill an entire session.

Author: PacketLens ML Team
"""

from __future__ import annotations

import asyncio
import logging
import time
import traceback
from typing import AsyncIterator

import grpc
import numpy as np
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    start_http_server,
)

# Import proto stubs (generated from packetlens.proto)
from .proto import packetlens_pb2, packetlens_pb2_grpc

# Import inference engine
from .core import InferenceEngine

# Configure module logger
logger = logging.getLogger(__name__)

# =============================================================================
# PROMETHEUS METRICS
# =============================================================================
# These are module-level singletons, initialized once when the module loads.

# Histogram for inference latency (in seconds)
# Buckets: 0.5ms, 1ms, 5ms, 10ms, 50ms, 100ms
INFERENCE_LATENCY = Histogram(
    "packetlens_inference_latency_seconds",
    "Inference latency in seconds",
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)

# Counter for verdicts by label and status
VERDICT_COUNTER = Counter(
    "packetlens_verdict_total",
    "Total verdicts by label and status",
    ["label", "status"],
)

# Gauge for current throughput (requests per second)
THROUGHPUT_GAUGE = Gauge(
    "packetlens_requests_per_second",
    "Current inference throughput (requests/second)",
)

# Counter for total requests processed
REQUESTS_TOTAL = Counter(
    "packetlens_requests_total",
    "Total inference requests processed",
)

# Gauge for active streams
ACTIVE_STREAMS = Gauge(
    "packetlens_active_streams",
    "Number of active gRPC streams",
)


class InferenceService(packetlens_pb2_grpc.InferenceServiceServicer):
    """
    Async gRPC servicer for network intrusion detection inference.
    
    This class handles incoming classification requests via bidirectional
    streaming, delegating actual inference to the InferenceEngine.
    
    Thread Safety:
        This servicer is designed for concurrent access. The underlying
        InferenceEngine.predict() is thread-safe, and asyncio.to_thread
        ensures proper isolation.
    
    Attributes:
        engine: The ONNX inference engine instance
        request_count: Running count of processed requests (for logging)
    """
    
    def __init__(self, engine: InferenceEngine) -> None:
        """
        Initialize the service with a pre-loaded inference engine.
        
        Args:
            engine: Initialized InferenceEngine instance
        """
        self.engine = engine
        self.request_count: int = 0
        logger.info(f"InferenceService initialized with {engine.n_classes} classes")
    
    async def Classify(
        self,
        request_iterator: AsyncIterator[packetlens_pb2.FeatureVector],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[packetlens_pb2.Verdict]:
        """
        Bidirectional streaming RPC for real-time classification.
        
        This method receives a stream of FeatureVectors (one per network flow)
        and yields a stream of Verdicts (classification results).
        
        Architecture Notes:
        -------------------
        - We use `async for` to consume the request stream without blocking.
          Each iteration yields to the event loop, allowing other streams
          to be processed concurrently.
        
        - Inference is offloaded to a thread via asyncio.to_thread() because
          ONNX Runtime's session.run() is a CPU-bound blocking call. Without
          this, a slow inference would freeze ALL concurrent streams.
        
        - Error handling is per-request: a malformed feature vector yields
          an ERROR verdict instead of terminating the entire stream.
        
        Args:
            request_iterator: Async iterator of FeatureVector messages
            context: gRPC context with metadata, deadline, etc.
            
        Yields:
            Verdict messages with classification results
        """
        # Log connection info
        peer = context.peer() or "unknown"
        logger.info(f"New Classify stream opened from {peer}")
        
        stream_request_count = 0
        stream_error_count = 0
        stream_start_time = time.time()
        
        # Track active stream count for metrics
        ACTIVE_STREAMS.inc()
        
        try:
            # ================================================================
            # MAIN STREAMING LOOP
            # ================================================================
            # async for: Non-blocking iteration over incoming requests.
            # This yields control to the event loop between messages,
            # enabling true concurrency across multiple streams.
            async for request in request_iterator:
                self.request_count += 1
                stream_request_count += 1
                
                try:
                    # ========================================================
                    # STEP 1: Extract and Validate Features
                    # ========================================================
                    # Convert protobuf RepeatedScalarContainer to numpy array
                    features = np.array(request.features, dtype=np.float32)
                    
                    # Validate feature count
                    expected = self.engine.expected_features
                    if len(features) != expected:
                        logger.warning(
                            f"Feature count mismatch for flow {request.flow_id}: "
                            f"got {len(features)}, expected {expected}"
                        )
                        # Yield error verdict and continue
                        VERDICT_COUNTER.labels(label="ERROR", status="validation_error").inc()
                        yield packetlens_pb2.Verdict(
                            flow_id=request.flow_id,
                            label="ERROR",
                            confidence=0.0,
                            inference_time_us=0,
                        )
                        stream_error_count += 1
                        continue
                    
                    # ========================================================
                    # STEP 2: Run Inference (Offloaded to Thread Pool)
                    # ========================================================
                    # asyncio.to_thread: Runs the blocking predict() call in
                    # a separate thread, preventing event loop starvation.
                    # This is CRITICAL for maintaining responsiveness under
                    # load with CPU-bound ONNX inference.
                    inference_start = time.perf_counter()
                    label, confidence, inference_time_ms = await asyncio.to_thread(
                        self.engine.predict, features
                    )
                    inference_elapsed = time.perf_counter() - inference_start
                    
                    # Record metrics
                    INFERENCE_LATENCY.observe(inference_elapsed)
                    REQUESTS_TOTAL.inc()
                    VERDICT_COUNTER.labels(label=label, status="success").inc()
                    
                    # Convert ms to µs for proto
                    inference_time_us = int(inference_time_ms * 1000)
                    
                    # ========================================================
                    # STEP 3: Yield Verdict
                    # ========================================================
                    verdict = packetlens_pb2.Verdict(
                        flow_id=request.flow_id,
                        label=label,
                        confidence=confidence,
                        inference_time_us=inference_time_us,
                    )
                    
                    # Periodic logging (every 1000 requests)
                    if self.request_count % 1000 == 0:
                        logger.info(
                            f"Processed {self.request_count:,} total requests | "
                            f"Last: {label} ({confidence:.2%}) in {inference_time_us}µs"
                        )
                    
                    yield verdict
                    
                except Exception as e:
                    # ========================================================
                    # ERROR HANDLING: Isolate failures
                    # ========================================================
                    # Log the full traceback for debugging
                    logger.error(
                        f"Inference error for flow {request.flow_id}: {e}\n"
                        f"{traceback.format_exc()}"
                    )
                    
                    # Yield error verdict instead of crashing the stream
                    VERDICT_COUNTER.labels(label="ERROR", status="exception").inc()
                    yield packetlens_pb2.Verdict(
                        flow_id=request.flow_id,
                        label="ERROR",
                        confidence=0.0,
                        inference_time_us=0,
                    )
                    stream_error_count += 1
        
        except asyncio.CancelledError:
            # Client cancelled the stream (e.g., timeout, disconnect)
            logger.info(f"Stream from {peer} cancelled")
            raise
        
        except Exception as e:
            # Unexpected error in stream handling
            logger.error(f"Stream error from {peer}: {e}\n{traceback.format_exc()}")
            raise
        
        finally:
            # Decrement active streams
            ACTIVE_STREAMS.dec()
            
            # Update throughput gauge
            stream_duration = time.time() - stream_start_time
            if stream_duration > 0:
                THROUGHPUT_GAUGE.set(stream_request_count / stream_duration)
            
            # Always log stream completion
            logger.info(
                f"Classify stream from {peer} closed | "
                f"Requests: {stream_request_count}, Errors: {stream_error_count}"
            )
    
    async def HealthCheck(
        self,
        request: packetlens_pb2.HealthRequest,
        context: grpc.aio.ServicerContext,
    ) -> packetlens_pb2.HealthResponse:
        """
        Simple health check endpoint for load balancers and monitoring.
        
        Returns:
            HealthResponse with status "SERVING" if engine is ready
        """
        return packetlens_pb2.HealthResponse(
            status="SERVING",
            model_loaded=True,
            n_classes=self.engine.n_classes,
            n_features=self.engine.n_features,
        )


async def serve(
    engine: InferenceEngine,
    port: int = 50051,
    max_workers: int = 10,
) -> None:
    """
    Start the async gRPC server.
    
    This function creates and runs the gRPC server with the InferenceService.
    It's designed to be called from main.py.
    
    Args:
        engine: Pre-initialized InferenceEngine
        port: Port to listen on (default: 50051)
        max_workers: Max concurrent workers (for thread pool)
    """
    # =========================================================================
    # START PROMETHEUS METRICS SERVER
    # =========================================================================
    # start_http_server runs in a background daemon thread, so it won't block
    # the asyncio event loop. Port 8000 is standard for Prometheus metrics.
    metrics_port = 8000
    try:
        start_http_server(metrics_port)
        logger.info(f"📊 Prometheus metrics server started on port {metrics_port}")
    except Exception as e:
        logger.warning(f"Failed to start metrics server on port {metrics_port}: {e}")
    
    # Create async server
    server = grpc.aio.server(
        options=[
            # Message size limits (10MB max for batched requests)
            ("grpc.max_receive_message_length", 10 * 1024 * 1024),
            ("grpc.max_send_message_length", 10 * 1024 * 1024),
            # Keepalive settings for long-running streams
            ("grpc.keepalive_time_ms", 10000),
            ("grpc.keepalive_timeout_ms", 5000),
            ("grpc.keepalive_permit_without_calls", True),
            # HTTP/2 settings
            ("grpc.http2.max_pings_without_data", 0),
            ("grpc.http2.min_ping_interval_without_data_ms", 5000),
        ]
    )
    
    # Register service
    service = InferenceService(engine)
    packetlens_pb2_grpc.add_InferenceServiceServicer_to_server(service, server)
    
    # Enable gRPC reflection for debugging with tools like grpcurl
    try:
        from grpc_reflection.v1alpha import reflection
        SERVICE_NAMES = (
            packetlens_pb2.DESCRIPTOR.services_by_name["InferenceService"].full_name,
            reflection.SERVICE_NAME,
        )
        reflection.enable_server_reflection(SERVICE_NAMES, server)
        logger.info("gRPC reflection enabled")
    except ImportError:
        logger.warning("grpc-reflection not installed, reflection disabled")
    
    # Bind to port
    listen_addr = f"[::]:{port}"
    server.add_insecure_port(listen_addr)
    
    logger.info(f"Starting gRPC server on {listen_addr}")
    
    # Start server
    await server.start()
    logger.info(f"🚀 Server listening on {listen_addr}")
    
    # Wait for termination
    await server.wait_for_termination()
