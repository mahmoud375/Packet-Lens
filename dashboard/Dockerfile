# ==============================================================================
# PacketLens Dashboard — Multi-Stage Dockerfile (Next.js Standalone)
# ==============================================================================
#
# Optimized production build using Next.js "standalone" output mode.
# Final image is ~120MB instead of ~1GB (no node_modules shipped).
#
# Build context: dashboard/ (set via docker-compose.yml)
# Usage: docker compose up --build -d
#
# ==============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Install dependencies
# ---------------------------------------------------------------------------
FROM node:20-alpine AS deps

# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine
# to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY package.json package-lock.json ./

# Clean install (ci) for reproducible builds
RUN npm ci

# ---------------------------------------------------------------------------
# Stage 2: Build the application
# ---------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# NEXT_PUBLIC_* env vars must be available at BUILD time (baked into JS bundle).
# docker-compose passes these as build args.
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

# Disable Next.js telemetry during build
ENV NEXT_TELEMETRY_DISABLED=1

# Build the standalone output
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 3: Production runtime (minimal)
# ---------------------------------------------------------------------------
FROM node:20-alpine AS runner

WORKDIR /app

# Run as non-root for security
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Disable telemetry at runtime
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

# Copy only what the standalone server needs:
# 1. public/ — static assets (favicon, images)
# 2. .next/standalone — self-contained Node.js server
# 3. .next/static — compiled JS/CSS chunks
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

# The port the standalone server listens on.
# Overridable via DASHBOARD_PORT in docker-compose.
ENV PORT=3001
EXPOSE 3001

# The standalone output produces a server.js at the root
CMD ["node", "server.js"]
