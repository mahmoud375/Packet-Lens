<div align="center">

# 🔬 PacketLens

### High-Performance Real-Time Network Intrusion Detection System

[![Go](https://img.shields.io/badge/Go-1.23-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![ONNX](https://img.shields.io/badge/ONNX-Runtime-7B64FF?style=for-the-badge&logo=onnx&logoColor=white)](https://onnxruntime.ai)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**A polyglot NIDS that captures live network traffic at the kernel level, extracts 54 statistical flow features using numerically stable algorithms, and classifies threats in <2ms using an XGBoost model compiled to ONNX — all orchestrated through bidirectional gRPC streaming with full Prometheus/Grafana observability.**

[Architecture](#-architecture) · [Features](#-key-features) · [Quick Start](#-quick-start) · [Tech Stack](#-tech-stack) · [Project Structure](#-project-structure)

</div>

---

## 🏗 Architecture

<p align="center">
  <img src="docs/architecture.png" alt="PacketLens System Architecture" width="850">
</p>

**Data Path:** `Network Interface → pcap (BPF filter) → gopacket decode → 5-tuple flow keying → Welford's online stats → 54-element float32 vector → gRPC bidirectional stream → log1p + RobustScaler → ONNX session.run() → Verdict (label + confidence) → Prometheus → Grafana`

---

## ✨ Key Features

### 🧮 Mathematically Stable Statistics
The edge engine implements **Welford's Online Algorithm** (1962) for computing running mean, variance, and standard deviation. Unlike naive `sum(x²)/n - mean²` which suffers from [catastrophic cancellation](https://en.wikipedia.org/wiki/Catastrophic_cancellation) at large scales, Welford's maintains numerical stability across 6+ orders of magnitude — critical when `flow_bytes/s` ranges from 0 to 10⁹.

```go
// Two-pass delta: the key insight for numerical stability
delta := x - s.mean
s.mean += delta / float64(s.n)
delta2 := x - s.mean
s.m2 += delta * delta2   // Bessel-corrected sample variance
```

### 🛡 DDoS Resilience (Load Shedding)
A spoofed-IP DDoS attack can generate millions of unique 5-tuples per second. Without protection, each creates a new flow entry → OOM in seconds. PacketLens implements **lock-free load shedding** using `atomic.Int64`:

- **`MaxActiveFlows = 100,000`** → ~40 MB memory ceiling
- Atomic counter — zero mutex contention on the capture hot path
- Graceful degradation: excess flows are dropped with metrics, not crashes

### ⚡ Sub-Millisecond Inference
The XGBoost model (207 trees, depth 8) is compiled to **ONNX format**, providing:
- **~1-2ms** end-to-end inference latency (feature extraction → verdict)
- `asyncio.to_thread()` offloads CPU-bound ONNX calls — the event loop **never blocks**
- Thread-safe ONNX sessions enable concurrent stream processing

### 🎯 Production-Grade Preprocessing
The inference pipeline applies the **exact same transforms** as training — solving the critical train/serve skew problem:
1. `np.log1p()` on 18 heavy-tail features (compresses power-law distributions)
2. `RobustScaler` (resistant to outliers, breakdown point = 50%)
3. Feature indices pre-computed at init from `feature_map.json` — zero per-request string lookups

### 📡 Bidirectional gRPC Streaming
Single persistent connection between Go and Python. Flows stream in, verdicts stream back — no per-request connection overhead. Error isolation ensures individual prediction failures don't kill the stream.

### 📊 Zero-Touch Observability
Grafana dashboards are **auto-provisioned** on first boot. No manual setup. Clone → `docker compose up` → open `localhost:3000` → see live threat detection.

---

## 🛠 Tech Stack

| Layer | Technology | Role |
|---|---|---|
| **Packet Capture** | Go 1.23 + gopacket/libpcap | Raw socket capture, BPF filtering |
| **Flow Aggregation** | sync.Map + atomic.Int64 | Concurrent flow tracking, load shedding |
| **Statistics** | Welford's Algorithm | O(1) per-packet mean/var/std computation |
| **Transport** | gRPC + Protocol Buffers | Bidirectional streaming, schema enforcement |
| **Inference** | ONNX Runtime 1.17+ | Compiled XGBoost model, sub-ms latency |
| **ML Framework** | XGBoost (training only) | 33-class classifier, 207 estimators |
| **Preprocessing** | NumPy + joblib | log1p + RobustScaler (matches training) |
| **Async Server** | grpc.aio + asyncio | Non-blocking concurrent stream handling |
| **Metrics** | Prometheus client (Go + Python) | Latency histograms, verdict counters, flow gauges |
| **Visualization** | Grafana 10+ | Auto-provisioned dashboards |
| **Containerization** | Docker Compose | Multi-stage builds, zero-touch deployment |
| **Dataset** | CIC-IDS-2017 | 54 features, 33 attack classes, ~2.8M flows |

---

## 🚀 Quick Start

### Prerequisites
- **Docker** & **Docker Compose** (v2+)
- **Linux** with a network interface (e.g., `wlp2s0`, `eth0`)
- `sudo` access (required for raw packet capture)

### 🐧 Linux (One Command)

```bash
# Clone the repository
git clone https://github.com/mahmoud375/Packet-Lens.git
cd Packet-Lens/deploy

# Launch the entire NIDS stack
INTERFACE=wlp2s0 sudo docker compose up --build -d
```

> [!TIP]
> Replace `wlp2s0` with your network interface name. Find it with `ip link show`.

**That's it.** Open your browser:

| Service | URL | Description |
|---|---|---|
| **Grafana Dashboard** | [localhost:3000](http://localhost:3000) | Live threat detection dashboard (auto-provisioned) |
| **Prometheus** | [localhost:9090](http://localhost:9090) | Raw metrics explorer |
| **Inference Metrics** | [localhost:8000/metrics](http://localhost:8000/metrics) | Python service health |
| **Sniffer Metrics** | [localhost:9091/metrics](http://localhost:9091/metrics) | Go capture engine health |

### 🪟 Windows

> [!WARNING]
> Docker Desktop on Windows does **not** support `network_mode: host`. The sniffer will capture traffic from the Docker VM's virtual interface, not your host Wi-Fi. For full host-level capture, use **WSL2** with a Linux distro or run natively on Linux.

```powershell
git clone https://github.com/mahmoud375/Packet-Lens.git
cd Packet-Lens\deploy

# Use the Docker VM's default interface
set INTERFACE=eth0
docker compose up --build -d
```

The Grafana dashboard will still load and display metrics, but traffic visibility is limited to the Docker VM network.

### 🛑 Stopping

```bash
cd deploy && sudo docker compose down
```

To also clear persistent data (Prometheus TSDB, Grafana state):
```bash
sudo docker compose down -v
```

---

## 📈 Usage

### Viewing the Dashboard

Navigate to **[localhost:3000](http://localhost:3000)** — the **"PacketLens Ultimate"** dashboard loads automatically with 5 panels:

| Panel | Metric | What It Shows |
|---|---|---|
| **Threat Level** | `rate(verdict_total{label!="Benign"}[1m])` | Attacks per second (green = secure, red = active threats) |
| **Live Traffic** | Benign vs. Malicious rate | Real-time traffic classification over time |
| **Active Flows** | `packetlens_active_flows` | Memory pressure indicator (cap: 100K) |
| **Attack Distribution** | `sum by (label) (verdict_total)` | Donut chart of all detected attack types |
| **System Latency** | `inference_latency_seconds` | Average inference speed (target: <2ms) |

### Testing with Network Traffic

Generate some traffic to see the system in action:

```bash
# Browse the web — the sniffer sees everything
curl -s https://example.com > /dev/null

# Generate bulk traffic
wget -q https://speed.hetzner.de/100MB.bin -O /dev/null

# Watch verdicts in real-time
sudo docker compose logs -f sniffer
```

---

## ⚡ Performance

| Metric | Value | Condition |
|---|---|---|
| **Inference Latency** | **< 2 ms** | End-to-end (feature extraction → ONNX → verdict) |
| **Model Size** | 19 MB | ONNX format (207 trees × depth 8) |
| **Flow Memory Cap** | ~40 MB | 100K concurrent flows × ~400 bytes each |
| **Weighted F1** | 0.984 | On CIC-IDS-2017 temporal holdout |
| **Macro F1** | 0.836 | Across all 33 attack classes |
| **Max Active Flows** | 100,000 | Before load-shedding activates |
| **Feature Extraction** | O(1) per packet | Welford's algorithm, no packet history stored |

---

## 📁 Project Structure

```
PacketLens/
├── services/
│   ├── sniffer/                    # 🛡 Edge Engine (Go)
│   │   ├── cmd/main.go             #    Entrypoint, flags, graceful shutdown
│   │   ├── internal/
│   │   │   ├── capture/engine.go   #    gopacket/pcap wrapper
│   │   │   ├── flow/
│   │   │   │   ├── manager.go      #    Flow aggregation, load shedding
│   │   │   │   └── stats_welford.go#    Welford's online algorithm
│   │   │   ├── transport/grpc.go   #    gRPC client, reconnection logic
│   │   │   └── metrics/metrics.go  #    Prometheus instrumentation
│   │   └── Dockerfile              #    Multi-stage (golang → debian-slim)
│   │
│   └── inference/                  # 🧠 Inference Core (Python)
│       ├── main.py                 #    Entrypoint, signal handling
│       ├── server.py               #    Async gRPC server (grpc.aio)
│       ├── core.py                 #    ONNX engine + preprocessing pipeline
│       ├── model_store/model.onnx  #    Compiled XGBoost model
│       ├── requirements.txt        #    Pinned dependencies
│       └── Dockerfile              #    python:3.10-slim
│
├── proto/packetlens.proto          # ⚡ gRPC schema (FeatureVector ↔ Verdict)
├── data/processed/                 # 📊 Training artifacts
│   ├── feature_map.json            #    54 feature names (CIC-IDS order)
│   ├── label_mapping.json          #    33 class labels
│   └── scaler.pkl                  #    RobustScaler (fitted on training data)
│
├── deploy/                         # 🐳 Docker Orchestration
│   ├── docker-compose.yml          #    4-service stack
│   ├── prometheus.yml              #    Scrape config
│   └── grafana/                    #    Auto-provisioned dashboards
│
├── scripts/                        # 🔧 Training & Audit Scripts
│   ├── corrected_preprocessing.py  #    Data pipeline (log1p + RobustScaler)
│   └── train_model.py              #    XGBoost training → ONNX export
│
└── Makefile                        #    Protobuf compilation
```

---

## 🔬 Research Context

PacketLens is trained on the **[CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html)** dataset — a benchmark containing realistic network traffic with 33 labeled attack types including DDoS, Port Scan, Brute Force, Web Attacks, and Infiltration.

**Key methodological choices:**
- **Temporal train/test split** (not random) to simulate real-world deployment
- **RobustScaler** over StandardScaler for outlier resistance (DDoS flows are extreme outliers)
- **`sample_weight`** for class imbalance (not `scale_pos_weight`, which only works for binary classification)
- **log1p transform** on 18 power-law features to compress 6+ orders of magnitude

---

## 👤 Author

**Mahmoud Elgendy**

---

<div align="center">

*Built with precision. Deployed with confidence.*

</div>
