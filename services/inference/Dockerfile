# ==============================================================================
# PacketLens Inference Service — Dockerfile
# ==============================================================================
# Runs the Python gRPC inference server with ONNX Runtime.
#
# Build context: project root (../..)
# Usage: docker compose up --build
# ==============================================================================

FROM python:3.10-slim

# Install build-essential for compiling grpcio C extension
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python dependencies first (layer caching)
COPY services/inference/requirements.txt services/inference/requirements.txt
RUN pip install --no-cache-dir -r services/inference/requirements.txt

# Copy the entire project context (needed for `python -m services.inference.main`)
COPY . .

# Expose gRPC port and Prometheus metrics port
EXPOSE 50051 8000

CMD ["python", "-m", "services.inference.main"]
