#!/usr/bin/env python3
"""
PacketLens Inference Service Entry Point
=========================================

Starts the gRPC inference server on port 50051.
Supports mock mode for testing when model.onnx is not available.

Usage:
    python -m services.inference.main
    python -m services.inference.main --mock  # For testing without model
"""

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from services.inference.core import ModelEngine
from services.inference.server import create_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("packetlens.inference")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PacketLens Inference Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("INFERENCE_PORT", 50051)),
        help="gRPC server port (default: 50051)",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("DATA_DIR", "data/processed")),
        help="Path to processed data artifacts (default: data/processed)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=os.environ.get("MOCK_MODE", "").lower() == "true",
        help="Run in mock mode without model (for testing)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("MAX_WORKERS", 10)),
        help="Number of worker threads (default: 10)",
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    
    logger.info("=" * 60)
    logger.info("PacketLens Inference Service")
    logger.info("=" * 60)
    logger.info(f"Port: {args.port}")
    logger.info(f"Data dir: {args.data_dir.absolute()}")
    logger.info(f"Mock mode: {args.mock}")
    logger.info(f"Workers: {args.workers}")
    logger.info("=" * 60)
    
    # Initialize model engine
    engine = ModelEngine(data_dir=args.data_dir, mock_mode=args.mock)
    
    try:
        engine.load()
    except FileNotFoundError as e:
        logger.error(f"Failed to load artifacts: {e}")
        logger.error("Use --mock flag to run without model for testing")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error loading artifacts: {e}")
        return 1
    
    # Create and start server
    server = create_server(
        engine=engine,
        port=args.port,
        max_workers=args.workers,
    )
    
    # Setup graceful shutdown
    shutdown_event = False
    
    def handle_signal(signum, frame):
        nonlocal shutdown_event
        if not shutdown_event:
            shutdown_event = True
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            server.stop(grace=5)
    
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Start server
    server.start()
    logger.info(f"🚀 Server listening on [::]:{args.port}")
    
    if engine.is_mock:
        logger.warning("⚠️  RUNNING IN MOCK MODE - predictions are simulated")
    
    # Wait for shutdown
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt, stopping...")
        server.stop(grace=5)
    
    logger.info("Server stopped. Goodbye!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
