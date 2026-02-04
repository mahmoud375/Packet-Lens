#!/usr/bin/env python3
"""
PacketLens Inference Service - Main Entry Point
=================================================

This module provides the entry point for the gRPC inference service.
It handles configuration, logging setup, and graceful server lifecycle.

Usage:
------
    # From project root:
    python -m services.inference.main
    
    # With custom port:
    python -m services.inference.main --port 50052
    
    # With debug logging:
    python -m services.inference.main --debug

Architecture Decisions:
-----------------------
1. Module Execution: Run as `python -m services.inference.main` to ensure
   correct relative imports and working directory.

2. Signal Handling: We catch SIGINT/SIGTERM for graceful shutdown, allowing
   in-flight requests to complete before terminating.

3. Lazy Engine Init: The InferenceEngine is initialized before the server
   starts. Any startup errors (missing model, invalid artifacts) are caught
   early with clear error messages.

Author: PacketLens ML Team
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

# Configure root logger FIRST before any imports that might log
def setup_logging(debug: bool = False) -> None:
    """Configure logging with a consistent format."""
    level = logging.DEBUG if debug else logging.INFO
    
    # Format: timestamp - level - module - message
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger("grpc").setLevel(logging.WARNING)
    logging.getLogger("onnxruntime").setLevel(logging.WARNING)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PacketLens Network Intrusion Detection Inference Service",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=50051,
        help="gRPC server port",
    )
    
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("services/inference/model_store/model.onnx"),
        help="Path to ONNX model file",
    )
    
    parser.add_argument(
        "--labels",
        type=Path,
        default=Path("data/processed/label_mapping.json"),
        help="Path to label mapping JSON",
    )
    
    parser.add_argument(
        "--features",
        type=Path,
        default=Path("data/processed/feature_map.json"),
        help="Path to feature map JSON",
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    
    return parser.parse_args()


async def main() -> int:
    """
    Main entry point for the inference service.
    
    This function:
    1. Parses arguments and configures logging
    2. Initializes the InferenceEngine (loads ONNX model)
    3. Starts the async gRPC server
    4. Handles graceful shutdown on signals
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    # Parse arguments
    args = parse_args()
    
    # Setup logging
    setup_logging(debug=args.debug)
    logger = logging.getLogger(__name__)
    
    # Print banner
    logger.info("=" * 60)
    logger.info("PacketLens Inference Service")
    logger.info("=" * 60)
    logger.info(f"Port:     {args.port}")
    logger.info(f"Model:    {args.model}")
    logger.info(f"Labels:   {args.labels}")
    logger.info(f"Features: {args.features}")
    logger.info(f"Debug:    {args.debug}")
    logger.info("=" * 60)
    
    # =========================================================================
    # STEP 1: Initialize Inference Engine
    # =========================================================================
    # Import here to ensure logging is configured first
    from .core import InferenceEngine
    from .server import serve
    
    try:
        engine = InferenceEngine(
            model_path=args.model,
            label_mapping_path=args.labels,
            feature_map_path=args.features,
        )
    except FileNotFoundError as e:
        logger.error(f"Missing required file: {e}")
        logger.error("Ensure you're running from the project root directory")
        logger.error("Usage: python -m services.inference.main")
        return 1
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Failed to initialize engine: {e}")
        logger.exception("Full traceback:")
        return 1
    
    # =========================================================================
    # STEP 2: Setup Graceful Shutdown
    # =========================================================================
    shutdown_event = asyncio.Event()
    
    def signal_handler(signum: int, frame) -> None:
        """Handle shutdown signals gracefully."""
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}, initiating graceful shutdown...")
        shutdown_event.set()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # =========================================================================
    # STEP 3: Start Server
    # =========================================================================
    try:
        # Create server task
        server_task = asyncio.create_task(serve(engine, port=args.port))
        
        # Wait for either server completion or shutdown signal
        done, pending = await asyncio.wait(
            [server_task, asyncio.create_task(shutdown_event.wait())],
            return_when=asyncio.FIRST_COMPLETED,
        )
        
        # If shutdown was requested, cancel server
        if shutdown_event.is_set():
            logger.info("Shutting down server...")
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Server stopped")
        return 0
        
    except Exception as e:
        logger.error(f"Server error: {e}")
        logger.exception("Full traceback:")
        return 1


def run() -> None:
    """
    Synchronous entry point for running the async main function.
    
    This allows the service to be run with:
        python -m services.inference.main
    """
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        # Clean exit on Ctrl+C
        sys.exit(0)


if __name__ == "__main__":
    run()
