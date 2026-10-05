# ULPF — Product Requirements Document (PRD)

**Scope of this document:** the full MVP project (all phases M0–M8), not just the current phase. For live build status, see `context.md`. For how this gets built in order, see `phases.md`.

---

## 1. Problem Statement

SOC teams operating perimeter devices (firewalls, IPS/IDS, VPN gateways, routers) from multiple vendors face three compounding problems: (1) raw logs are not tamper-evident once written, (2) every new vendor/format needs a hand-written parser before it's usable, and (3) normalized output isn't uniformly queryable or ML-ready across vendors. ULPF exists to remove all three.

## 2. Users / Personas

| Persona | Needs |
|---|---|
| **SOC Analyst** | Confirm or correct auto-proposed field mappings for new log formats, quickly, in bulk (one action per cluster, not per field) |
| **Security/Compliance Auditor** | Prove a given SIEM alert traces back to unaltered raw bytes, on demand |
| **Platform/DevOps Engineer** | Deploy and operate the stack fully air-gapped, with no external dependencies at runtime |
| **Pack Maintainer** | Author, sign, and ship new vendor mapping packs, including offline via physical media |
| **Data/ML Engineer (downstream)** | Consume normalized events from the data lake with zero preprocessing |

## 3. Goals

- Zero raw-log loss or silent mutation, ever.
- Every event cryptographically traceable from raw bytes to final OCSF record and back.
- New/unknown vendor formats become queryable without a developer writing a parser — an analyst confirms a proposed mapping once, and it becomes permanent.
- One unified OCSF namespace regardless of source vendor.
- Runs with zero network calls at runtime (air-gapped).
- SIEM and data lake outputs never block or degrade each other, or ingestion.

## 4. Non-Goals (explicitly out of scope, MVP and beyond unless stated)

- Parsing anything other than perimeter network device logs (no endpoint/EDR, no cloud logs) in v1.
- Supporting OCSF classes beyond Network Activity (4001) in the MVP.
- Multi-tenant/multi-org deployments (single-org, single air-gapped instance assumed).
- Public/permissionless blockchain — the ledger is always permissioned and internal.
- Real-time analyst chat/collaboration features in the review UI.

## 5. Feature List (mapped to the original FRD clauses)

| Req | Feature | MVP behavior | Full-spec behavior (post-MVP) |
|---|---|---|---|
| **FR-A — Raw Preservation** | Byte-exact capture, lineage ID, sha256 seal, context metadata, zstd batching, Merkle+blockchain anchoring | Local filesystem raw store, SQLite metadata, hash-chained signed ledger file | MinIO raw store, PostgreSQL, permissioned PoA Ethereum/Fabric node |
| **FR-B — Source Extraction** | Deterministic hot path for known formats; Drain-based clustering + transfer learning for unknown formats | Regex-based extraction; `drain3` clustering with token-overlap seeding | VRL execution engine; same clustering logic, tuned at scale |
| **FR-C — Normalization** | IP/timestamp/port/enum canonicalization, semantic field mapping with confidence gating, OCSF assembly & validation | Lexical (TF-IDF) embedder + heuristic type matching for semantic mapping | ONNX MiniLM embeddings + FAISS ANN search |
| **FR-D — Traceability** | Forward trace (lineage_id → everything) and backward trace (OCSF uid → raw bytes), append-only history | Full forward/backward trace against SQLite | Same, against Postgres at scale |
| **FR-E — Plug-and-Play Onboarding** | Signed mapping packs, mandatory Ed25519 verification, quarantine of unsigned/invalid packs, atomic hot-reload with zero dropped events, offline signed bundle import | All of the above, dev signing key co-located for now (flagged as a deviation) | Offline/HSM-held signing key, full offline `.tar.zst` bundle importer |
| **FR-F — Unified Visibility** | Single OCSF namespace; vendor-neutral queries | Enforced structurally — C5-equivalent is sole writer to normalized output | Same, at production scale |
| **FR-G — SIEM & Data Lake Integration** | Independent, backpressure-isolated delivery to SIEM and data lake | JSONL/syslog-CEF stand-in SIEM sink + local Parquet writer, independent consumer offsets | Splunk HEC/OpenSearch Bulk translators, Kafka/Redpanda consumer groups at scale |
| **FR-H — AI/ML-Ready Analytics** | Typed, queryable Parquet output with per-field confidence as structured columns | Same, via `pyarrow`, local filesystem lake | Same, on MinIO with compaction |
| **FR-I — Reduced Parser Effort** | Grouped-by-cluster analyst review, one-action confirmation, auto-generated regression fixtures, on-chain provenance for every pack decision | CLI-first review tool (web UI optional, later phase) | Full Next.js review UI from day one |
| **FR-J — Air-Gapped Deployment** | Zero external dependencies at runtime; local NTP only | Enforced from M0 onward; CI gate with `--network none` | Same, validated across the full multi-service topology |
| **FR-K — Containerized / Platform-Independent** | Multi-stage Docker builds, mounted volumes, OS-independent | Single/few-service Docker Compose | Full per-container split matching the original 8-container topology |

## 6. Success Metrics

| Metric | MVP target |
|---|---|
| Byte-for-byte raw fidelity | 100% (zero tolerance) |
| Tamper detection | 100% of single-byte alterations detected and isolated |
| Hot-path coverage | ≥ 1 shipped vendor pack (Cisco ASA) fully round-trips to valid OCSF |
| Auto-onboarding loop | An unknown format goes from "first seen" to "hot-path parsed" with exactly one analyst confirmation action |
| Backpressure isolation | Killing the SIEM sink causes zero measurable slowdown in ingestion or the data lake writer |
| Air-gap compliance | Zero outbound connection attempts under `--network none` |
| Review efficiency | One analyst action confirms an entire cluster (not per-field) |

## 7. Assumptions & Constraints

- Single-org, air-gapped deployment; no multi-region, no cloud dependency.
- Team is comfortable with a mixed Python / Node-TypeScript / Next.js stack (see `architecture.md`).
- Contracts (event schemas, OCSF shape, pack YAML, DB tables) are frozen at the start of each phase and changed only through the process in `agent.md`.

## 8. Open Questions (track and resolve during M0–M1; update this section as they close)

- Confidence auto-accept threshold (default 0.85) needs calibration against real sample logs — owner: ML team.
- Whether cold-path low-confidence events pass through to output flagged, or are held until resolved — MVP default is pass-through (see `architecture.md`).
- Final choice of language for `integrity-svc` (Node vs. Python) — owner: blockchain developer, decide by end of M0.
