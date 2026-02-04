#!/usr/bin/env python3
"""
PacketLens gRPC Server Test Script
===================================

Validates the inference server by streaming dummy packets and measuring performance.

Usage:
    python scripts/test_grpc_server.py
    python scripts/test_grpc_server.py --host localhost --port 50051 --count 1000
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Generator, Iterator

import grpc
import numpy as np

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.inference.proto import packetlens_pb2, packetlens_pb2_grpc


def generate_dummy_packets(
    count: int,
    n_features: int = 54,
    seed: int = 42,
) -> Generator[tuple[str, np.ndarray], None, None]:
    """
    Generate dummy feature vectors for testing.
    
    Args:
        count: Number of packets to generate
        n_features: Number of features per packet (must match model)
        seed: Random seed for reproducibility
        
    Yields:
        Tuple of (flow_id, features array)
    """
    rng = np.random.default_rng(seed)
    
    for i in range(count):
        flow_id = f"test_flow_{i:06d}"
        # Generate random features in [0, 1] range
        # In production, these would be scaled network flow statistics
        features = rng.random(n_features).astype(np.float32)
        yield flow_id, features


def create_request_stream(
    packets: list[tuple[str, np.ndarray]],
) -> Iterator[packetlens_pb2.FeatureVector]:
    """
    Convert packets to a stream of FeatureVector protobuf messages.
    
    Args:
        packets: List of (flow_id, features) tuples
        
    Yields:
        FeatureVector protobuf messages
    """
    for flow_id, features in packets:
        yield packetlens_pb2.FeatureVector(
            flow_id=flow_id,
            features=features.tolist(),
        )


def run_benchmark(
    host: str,
    port: int,
    count: int,
    verbose: bool = True,
) -> dict:
    """
    Run the gRPC benchmark test.
    
    Args:
        host: Server hostname
        port: Server port
        count: Number of requests to send
        verbose: Print individual results
        
    Returns:
        Dict with benchmark results
    """
    print("=" * 60)
    print("PacketLens gRPC Server Benchmark")
    print("=" * 60)
    print(f"  Target: {host}:{port}")
    print(f"  Requests: {count:,}")
    print("=" * 60)
    
    # Generate dummy packets
    print("\n[1/4] Generating dummy packets...")
    packets = list(generate_dummy_packets(count))
    print(f"      Generated {len(packets):,} packets with {len(packets[0][1])} features each")
    
    # Connect to server
    print(f"\n[2/4] Connecting to {host}:{port}...")
    try:
        channel = grpc.insecure_channel(
            f"{host}:{port}",
            options=[
                ("grpc.max_receive_message_length", 10 * 1024 * 1024),
                ("grpc.max_send_message_length", 10 * 1024 * 1024),
            ],
        )
        stub = packetlens_pb2_grpc.InferenceServiceStub(channel)
        
        # Quick connectivity check
        grpc.channel_ready_future(channel).result(timeout=5)
        print("      Connected successfully ✓")
        
    except grpc.FutureTimeoutError:
        print("      ERROR: Connection timed out")
        print("      Is the server running? Try: python -m services.inference.main")
        return {"error": "timeout"}
    except grpc.RpcError as e:
        print(f"      ERROR: {e.code().name} - {e.details()}")
        return {"error": str(e)}
    
    # Stream requests and collect results
    print("\n[3/4] Streaming requests...")
    
    latencies = []
    results = []
    label_counts = {}
    error_count = 0
    
    start_time = time.perf_counter()
    
    try:
        # Create request stream
        request_stream = create_request_stream(packets)
        
        # Call bidirectional streaming RPC
        response_stream = stub.Classify(request_stream)
        
        # Collect responses with timing
        for i, verdict in enumerate(response_stream):
            recv_time = time.perf_counter()
            
            # Calculate per-request latency (approximate)
            # Note: For streaming, this measures response receipt time
            if i == 0:
                first_response_time = recv_time
            
            # Track results
            results.append(verdict)
            
            if verdict.label == "ERROR":
                error_count += 1
            else:
                label_counts[verdict.label] = label_counts.get(verdict.label, 0) + 1
            
            # Record inference time from server
            latencies.append(verdict.inference_time_us / 1000)  # Convert to ms
            
            # Print first few results
            if verbose and i < 5:
                print(f"      [{i+1:4d}] {verdict.flow_id}: {verdict.label} "
                      f"({verdict.confidence:.2%}) [{verdict.inference_time_us}µs]")
            elif verbose and i == 5:
                print(f"      ... ({count - 5} more)")
    
    except grpc.RpcError as e:
        print(f"      ERROR during streaming: {e.code().name} - {e.details()}")
        return {"error": str(e)}
    
    end_time = time.perf_counter()
    total_time = end_time - start_time
    
    # Calculate metrics
    print("\n[4/4] Calculating metrics...")
    
    avg_latency = np.mean(latencies) if latencies else 0
    p50_latency = np.percentile(latencies, 50) if latencies else 0
    p95_latency = np.percentile(latencies, 95) if latencies else 0
    p99_latency = np.percentile(latencies, 99) if latencies else 0
    throughput = len(results) / total_time if total_time > 0 else 0
    
    # Print summary
    print("\n" + "=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    
    print("\nRequest Statistics:")
    print(f"   Total Requests:     {len(results):,}")
    print(f"   Successful:         {len(results) - error_count:,}")
    print(f"   Errors:             {error_count:,}")
    print(f"   Total Time:         {total_time:.2f}s")
    
    print("\nLatency (server-side inference):")
    print(f"   Average:            {avg_latency:.3f} ms")
    print(f"   P50 (median):       {p50_latency:.3f} ms")
    print(f"   P95:                {p95_latency:.3f} ms")
    print(f"   P99:                {p99_latency:.3f} ms")
    
    print("\nThroughput:")
    print(f"   Requests/second:    {throughput:,.1f}")
    
    print("\nLabel Distribution:")
    sorted_labels = sorted(label_counts.items(), key=lambda x: -x[1])
    for label, count in sorted_labels[:10]:
        pct = count / len(results) * 100
        print(f"   {label:25s}: {count:,} ({pct:.1f}%)")
    if len(sorted_labels) > 10:
        print(f"   ... and {len(sorted_labels) - 10} more labels")
    
    print("\n" + "=" * 60)
    print("Benchmark complete")
    print("=" * 60)
    
    # Return results dict
    return {
        "total_requests": len(results),
        "successful": len(results) - error_count,
        "errors": error_count,
        "total_time_s": total_time,
        "avg_latency_ms": avg_latency,
        "p50_latency_ms": p50_latency,
        "p95_latency_ms": p95_latency,
        "p99_latency_ms": p99_latency,
        "throughput_rps": throughput,
        "label_distribution": label_counts,
    }


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test PacketLens gRPC Inference Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="Server hostname",
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=50051,
        help="Server port",
    )
    
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of test requests",
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress individual result output",
    )
    
    args = parser.parse_args()
    
    try:
        results = run_benchmark(
            host=args.host,
            port=args.port,
            count=args.count,
            verbose=not args.quiet,
        )
        
        if "error" in results:
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nBenchmark cancelled by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
