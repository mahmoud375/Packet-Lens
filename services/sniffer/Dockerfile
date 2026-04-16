# ==============================================================================
# PacketLens Sniffer Service — Multi-Stage Dockerfile
# ==============================================================================
# Stage 1: Compile Go binary with libpcap (CGO required)
# Stage 2: Minimal Debian runtime with libpcap shared library only
#
# Build context: project root (../..)
# Usage: docker compose up --build
# ==============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

# libpcap-dev provides the headers and static libs for CGO compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy dependency files first (layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Build the sniffer binary
# CGO_ENABLED=1 is required for gopacket/pcap (uses libpcap via CGO)
RUN CGO_ENABLED=1 go build -o /packetlens-sniffer ./services/sniffer/cmd

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# libpcap0.8 provides the shared library needed at runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /packetlens-sniffer .

# Expose Prometheus metrics port
EXPOSE 9091

# Use shell form to enable ${INTERFACE} env-var expansion
CMD ./packetlens-sniffer -iface ${INTERFACE:-wlp2s0} -server localhost:50051
