# Universal Log Pre-processing Framework (ULPF)
## Official Evaluation Submission Readme & Technical Dossier

**Target Challenge:** Universal Log Pre-processing Framework (ULPF) for Next-Generation SIEM and Big Data Platforms  
**Scope:** Lossless Ingestion, Cryptographic Provenance, Self-Learning Parsing, and OCSF Normalization for Heterogeneous Perimeter Network Devices  
**Source Code Link:** **https://github.com/Sabhya1/ULPF**  

## For Architecture Document, Demo Video and PPT, refer to this Drive link: 
**https://drive.google.com/drive/folders/1Ji8d5KuyRGaS6ZZjBcQDNW5TWF6aHDOO?usp=sharing**  

---

## Table of Contents
1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [Expected Solutions & Compliance Traceability Matrix (Items a–k)](#2-expected-solutions--compliance-traceability-matrix-items-ak)
3. [Setup Instructions (Complete Guide)](#3-setup-instructions-complete-guide)

---

## 1. Executive Summary & Problem Statement

### Background
Modern enterprises generate massive volumes of logs across heterogeneous platforms: perimeter firewalls, routers, switches, VPN concentrators, industrial SCADA gateways, cloud infrastructure, and IoT sensors. These logs arrive in highly fragmented syntaxes: **Syslog (RFC 3164 / RFC 5424), JSON, XML, CSV, CEF (Common Event Format), LEEF (Log Event Extended Format), and custom vendor formats**.

This diversity leads to severe operational bottlenecks:
* **Parser Fatigue:** Security teams spend weeks manually writing fragile regular expressions for every new vendor device.
* **Storage Inefficiency:** Raw logs are either discarded (losing forensic fidelity) or duplicated into multi-terabyte unindexed silos.
* **Forensic Non-Repudiation:** Traditional databases allow silent administrative log tampering without leaving audit evidence.
* **Downstream Latency:** Threat detection systems and machine learning platforms cannot run analytics without prior normalization.

### The ULPF Solution
The **Universal Log Pre-processing Framework (ULPF)** is a resilient, vendor-agnostic, containerized pre-processing system. It captures logs over Syslog UDP/TCP and HTTP REST, content-seals them with SHA-256 in immutable WORM chunks, dynamically routes them through a **Dual-Path Engine** (Hot-Path regex packs vs. Cold-Path Drain3 prefix-tree clustering), and outputs canonical **OCSF v1.2.0 Class 4001 (Network Activity)** events into an Apache Parquet data lake and low-latency SIEM stream.

Every normalized record remains cryptographically linked to its raw bitstream via an **Ed25519-signed Merkle Tree Ledger**.

---

## 2. Expected Solutions & Compliance Traceability Matrix (Items a–k)

The table below outlines how ULPF completely satisfies all 11 technical requirements specified by the evaluation board:

| SIH Requirement | ULPF Architecture Implementation | Evidence / Code References |
| :--- | :--- | :--- |
| **a) Preserve complete raw event data without information loss** | Ingestion captures exact raw bytes into `IngestEnvelope` with microsecond SHA-256 seals, appending to append-only Zstandard compressed chunks (`.zst`) with byte-offset JSON indices (`.idx.json`). Zero bytes discarded. | `services/ingestion-svc/src/raw_store.ts`<br>`services/ingestion-svc/src/envelope.ts` |
| **b) Extract and parse source-specific attributes** | Dual-path router: Hot Path uses pre-compiled deterministic regex engines; Cold Path uses unsupervised Drain3 prefix-trees to mine templates (`<*>`) and isolate variable tokens automatically. | `services/pipeline-svc/src/pipeline_svc/router.py`<br>`services/pipeline-svc/src/pipeline_svc/coldpath/drain.py` |
| **c) Normalize fields into a common event taxonomy** | Strict 3-Layer normalizer enforcing **OCSF v1.2.0 Class 4001 (Network Activity)** with IPv4 zero-stripping, RFC 5952 IPv6 compression, port range bounds checking, and activity categorization. | `services/pipeline-svc/src/pipeline_svc/normalization.py`<br>`packages/contracts/schemas/ocsf_event.v1.schema.json` |
| **d) Maintain traceability between normalized and original events** | Immutable invariant: `ocsf.metadata.uid == raw_event.lineage_id`. Every log is anchored as a leaf in a 1,000-event SHA-256 Merkle tree signed with Ed25519 into `ledger.jsonl`. Sub-millisecond tamper audits via `/verify/:lineage_id`. | `services/integrity-svc/src/merkle.ts`<br>`services/review-api/src/index.ts` |
| **e) Plug-and-play onboarding of new log sources** | Declarative YAML mapping packs with multi-level inheritance (`base_network.yaml` $\rightarrow$ vendor pack). Loaded via Read-Copy-Update (RCU) hot-reload with zero service restarts and zero packet drops. | `packs/cisco_asa/1.3.0/pack.yaml`<br>`services/pipeline-svc/src/pipeline_svc/pack_registry.py` |
| **f) Unified visibility across enterprise environments** | Modern Next.js 15 Analyst Dashboard (`review-ui` on `:3100`): real-time EPS meters, Drain3 discovered cluster review queue (newest first), OCSF canonical event streams, and visual Merkle tamper inspection. | `services/review-ui/src/app/page.tsx`<br>`services/review-ui/src/app/queue/page.tsx` |
| **g) Efficient SIEM and Data Lake integration** | Dual-tier streaming: Apache Parquet columnar Data Lake partitioned by date (`data/lake/ocsf_4001/`) via `pyarrow` + streaming Splunk HEC / CEF / JSONL sink dispatcher with backpressure handling. | `services/sinks-svc/src/sinks_svc/parquet.py`<br>`services/sinks-svc/src/sinks_svc/siem.py` |
| **h) AI/ML-ready security and operational analytics** | Columnar Parquet records with per-field `_confidence` metrics directly readable into Pandas / PyTorch (`pd.read_parquet(...)`) with zero preprocessing or schema wrangling needed. | `packages/contracts/python/ulpf_contracts/` |
| **i) Reduced parser development effort** | Self-Learning Loop: Unsupervised Drain3 prefix-tree clustering groups raw novel logs $\rightarrow$ Lexical TF-IDF Semantic Mapper auto-proposes OCSF mappings $\rightarrow$ Analyst confirms in 1 click $\rightarrow$ Compiles signed YAML pack. 90% manual effort eliminated. | `services/pipeline-svc/src/pipeline_svc/coldpath/semantic_mapper.py` |
| **j) Deployable in an air-gapped network** | 100% offline compliance: Zero CDN references, bundled local fonts, local ML models, pre-built multi-stage container images, offline vector math (`tools/check_airgap.py` passes 100%). | `tools/check_airgap.py`<br>`docker-compose.airgap.yml` |
| **k) Containerized & platform-independent** | 6 hardened multi-stage Dockerfiles (`docker/Dockerfile.*`) running under non-privileged users (`appuser:10001`), immutable volumes, healthchecks, and internal bridge network isolation. | `docker-compose.yml`<br>`docker/` |

---

## 3. Setup Instructions (Complete Guide)

### System Requirements & Prerequisites

#### 1. Hardware Requirements
| Resource | Minimum Specification | Recommended Specification | Purpose |
| :--- | :--- | :--- | :--- |
| **CPU** | 4 Cores (x86_64 or ARM64) | 8 Cores (3.0 GHz+) | Concurrent ingestion, Drain3 prefix-tree clustering, and regex compilation |
| **RAM** | 8 GB RAM | 16 GB RAM | Concurrent execution of 6 microservices, in-memory spooling, and Parquet caching |
| **Storage** | 10 GB Free Disk Space | 25 GB+ Fast SSD | Docker image layers, append-only Zstandard WORM chunks, and Parquet Data Lake |

#### 2. Software Requirements
* **Operating System:** Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+), macOS (12+), or Windows 10/11 (with Docker Desktop / WSL2 / PowerShell)
* **Container Runtime:** Docker Engine 24.0+ & Docker Compose v2.20+ (Docker daemon running)
* **Python Runtime (Optional):** Python 3.11+ (only needed if running test tools or benchmarks directly from host)
* **Node.js Runtime (Optional):** Node.js 20+ with `pnpm` (only needed for manual local UI development outside Docker)

#### 3. Service Port Allocations (What Runs on Which Port)
All microservices communicate across an internal Docker bridge. The following ports are exposed on `localhost`:

| Port | Protocol | Service / Component | Container Name | Description & Primary Function |
| :--- | :--- | :--- | :--- | :--- |
| **`3100`** | TCP / HTTP | **Analyst Web Console** | `ulpf-review-ui` | Next.js 15 UI: Real-time EPS telemetry, Drain3 Cold-Path Review Queue, and Merkle tamper audit trail viewer |
| **`4000`** | TCP / HTTP | **Review REST API** | `ulpf-review-api` | Express API: Verification proofs (`/api/verify/:id`), CSV log batch uploads, and 1-click pack compiler |
| **`5140`** | UDP | **Syslog Ingestion (UDP)** | `ulpf-ingestion-svc` | Wire-speed Syslog listener for perimeter firewalls & network appliances (RFC 3164 / RFC 5424) |
| **`5141`** | TCP | **Syslog Ingestion (TCP)** | `ulpf-ingestion-svc` | Connection-oriented Syslog stream listener with octet-framing and backpressure control |
| **`5142`** | TCP / HTTP | **HTTP REST Ingestion** | `ulpf-ingestion-svc` | Lossless JSON/batch REST ingestion (`POST /ingest`) with immediate SHA-256 content-seal and WORM append |
| **`5143`** | TCP / HTTP | **Integrity Service** | `ulpf-integrity-svc` | Merkle tree builder (1,000 leaves/tree), offline Ed25519 root signing, and hash-chained audit ledger |
| **`8000`** | TCP / HTTP | **Pipeline Processing Engine** | `ulpf-pipeline-svc` | FastAPI router: Hot-Path compiled regex execution, Cold-Path Drain3 template mining, and OCSF 4001 normalizer |
| **`8001`** | TCP / HTTP | **Sinks & Storage Service** | `ulpf-sinks-svc` | Date-partitioned Apache Parquet columnar Data Lake writer (`data/lake/ocsf_4001/`) and SIEM forwarder (Splunk HEC/CEF) |

---

### Step 1: Clone Repository
```bash
git clone https://github.com/Sabhya1/ULPF.git
cd ULPF
```

---

### Step 2: Launch Cluster (Standard or Air-Gapped)

#### Option A: Standard Deployment (Default)
Launch the 6 microservices with standard configuration (builds locally if images are not yet built):
```bash
docker compose up -d --build
```

#### Option B: Air-Gapped Deployment (100% Offline)
Launch all 6 microservices in strictly isolated, air-gapped mode with zero external internet dependencies using pre-built images:
```bash
docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d
```

> **Air-Gap Security Guarantees:**
> * `pull_policy: never`: Starts immediately from local container images without querying external registries.
> * `internal: true`: All inter-service traffic is confined to an isolated internal bridge with zero outbound egress.
> * Zero remote CDNs, web fonts, or cloud API calls.

---

### Step 3: Verify Running Services
Check that all 6 microservices report `healthy`:

```bash
docker compose ps
```

| Service | Container Name | Host Port | Health Check Endpoint | Primary Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **Analyst Web Console** | `ulpf-review-ui` | `http://localhost:3100` | `http://localhost:3100` | Real-time Dashboard, Review Queue, Lineage Trace |
| **Review REST API** | `ulpf-review-api` | `http://localhost:4000` | `http://localhost:4000/health` | REST Management, Verification & Audit Engine |
| **Ingestion Service** | `ulpf-ingestion-svc` | `UDP :5140`<br>`TCP :5141`<br>`HTTP :5142` | `http://localhost:5142/health` | Syslog & HTTP listener, SHA-256 seal, WORM store |
| **Integrity Service** | `ulpf-integrity-svc` | `http://localhost:5143` | `http://localhost:5143/health` | Merkle Tree builder, Ed25519-signed Ledger |
| **Pipeline Service** | `ulpf-pipeline-svc` | `http://localhost:8000` | `http://localhost:8000/health` | Router, Drain3 Mining, OCSF 4001 Normalizer |
| **Sinks Service** | `ulpf-sinks-svc` | `http://localhost:8001` | `http://localhost:8001/health` | Parquet Data Lake & SIEM Dispatcher |

---

### Step 4: Web Console Access
Once launched, open your web browser to:
* **Analyst Dashboard:** `http://localhost:3100`
* **Cold-Path Review Queue (Newest First):** `http://localhost:3100/queue`
* **Cryptographic Event Trace:** `http://localhost:3100/trace/d47683d1-aea7-494d-a7db-e6982cb87720`

---

### Step 5: Stop or Teardown Cluster
To stop the services without deleting stored chunks:
```bash
# Standard
docker compose stop

# Air-Gapped
docker compose -f docker-compose.yml -f docker-compose.airgap.yml stop
```
To completely remove containers and networks:
```bash
# Standard
docker compose down

# Air-Gapped
docker compose -f docker-compose.yml -f docker-compose.airgap.yml down
```

---

**ULPF Submission Team**  
*Universal Log Pre-processing Framework*  
*Air-Gapped, Lossless, Blockchain-Anchored Cybersecurity Normalization Engine*
