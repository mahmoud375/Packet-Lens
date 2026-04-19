# ==============================================================================
# PacketLens API Service — Multi-Stage Dockerfile
# ==============================================================================
# Stage 1: Compile Go binary (no CGO needed — pure Go)
# Stage 2: Minimal Debian runtime
# ==============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

WORKDIR /src

# Copy dependency files first (layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Build the API binary — CGO_ENABLED=0 for static binary (no libpcap needed)
RUN CGO_ENABLED=0 go build -o /packetlens-api ./services/api/cmd

# ---------------------------------------------------------------------------
# Stage 2: Runtime (minimal scratch-like image with CA certs)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /packetlens-api .

# Expose API port
EXPOSE 8080

CMD ["./packetlens-api"]
