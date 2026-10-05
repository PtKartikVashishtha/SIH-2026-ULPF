# ULPF — Architecture Document

**Scope of this document:** the full MVP project's target architecture (all phases). This is the single source of truth for service boundaries, data flow, database schema, payload contracts, and naming conventions. **Any change to anything in this file requires a note in the Decisions Log (Section 9) and sign-off from the tech lead** — see `agent.md` for the exact process.

---

## 1. System Overview

```
Device logs ──► [ingestion-svc]  ──► bus: raw.ingest ──► [pipeline-svc: router]
                  │ lineage_id                                  │ known format?
                  │ sha256, zstd                                ├─ YES → hot path (regex, confidence 1.0)
                  │ raw store write                             └─ NO  → cold path (pipeline-svc/coldpath)
                  ▼                                                        │ Drain cluster + semantic mapping
             bus: merkle.leaf ──► [integrity-svc] ──► ledger                confidence-gated
                                                                            ▼
                                        [Common Intermediate Extraction Envelope]
                                                                            ▼
                                        [pipeline-svc: normalize → OCSF 4001, validate]
                                                                            ▼
                                        bus: ocsf.events ──► [sinks-svc]
                                                                ├─ SIEM stand-in (JSONL / syslog-CEF)
                                                                └─ Data lake (Parquet, partitioned)

Low-confidence clusters ──► [review-api] ──► [review-ui] ──► analyst confirms
        ──► pack signed ──► anchored in ledger (via integrity-svc) ──► hot-reloaded into pipeline-svc
        ──► future logs of that format take the hot path
```

Invariant: **`lineage_id` (UUIDv4) is the single join key** from raw byte to OCSF output. `metadata.uid == _lineage_id == lineage_id`, always.

## 2. Services

| Service | Owns (from spec) | Language | Talks to |
|---|---|---|---|
| `ingestion-svc` | C1 — listeners, envelope generation, batching, raw store writer | Node.js/TypeScript | Raw store (fs/MinIO), Index DB, bus (`raw.ingest`, `merkle.leaf`) |
| `integrity-svc` | C2 — Merkle batching, ledger, anchoring, verification | Node.js/TypeScript (or Python — owner's choice) | Bus (`merkle.leaf`, `pack.lifecycle`), Index DB, ledger store |
| `pipeline-svc` | C3 (router/hot path), C5 (normalization), C6 (pack registry) | Python | Bus (all pipeline topics), Index DB, pack filesystem |
| `pipeline-svc/coldpath` | C4 — Drain mining, embeddings, semantic mapping, confidence gate | Python | In-process call from router; Index DB (`review_queue`) |
| `sinks-svc` | C8 — SIEM adapter, Parquet writer | Python | Bus (`ocsf.events`), SIEM stand-in target, data lake filesystem |
| `review-api` | C7 backend — REST API, review queue view | Node.js/TypeScript (NestJS) | Index DB (`review_queue`), `pipeline-svc`'s pack registry HTTP API |
| `review-ui` | C7 frontend — analyst review interface | Next.js/React | `review-api` only, via REST |

No service reaches into another service's internal storage or code. All cross-service communication is either the message bus (contracts in Section 5) or a documented REST API (Section 6).

## 3. Data Stores (MVP → full-spec upgrade path)

| Store | MVP implementation | Full-spec implementation | Owned by |
|---|---|---|---|
| Index/Lookup DB (D1) | SQLite (WAL mode), accessed via SQLAlchemy (Python services) / Prisma or Knex (Node services) | PostgreSQL 15+ | Shared — schema in Section 4 is authoritative regardless of engine |
| Raw Object Store (D2) | Local filesystem, chunked zstd frames + offset index | MinIO (S3-compatible) | `ingestion-svc` |
| Data Lake Store (D3) | Local filesystem, partitioned Parquet | MinIO, separate bucket from D2 | `sinks-svc` |
| Blockchain Ledger (D4) | Hash-chained, node-signed JSONL file | Permissioned PoA Ethereum or Hyperledger Fabric | `integrity-svc` |
| Event Bus (D5) | In-process/lightweight local bus (e.g. NATS core, single node) with independent consumer-group offsets | Kafka / Redpanda / NATS JetStream | Shared infra |

**Rule:** every store is accessed through an interface (`RawStore`, `IndexDB`/repository layer, `Ledger`, `Bus`). No service hardcodes SQLite-only or filesystem-only assumptions into business logic — swapping the implementation must never require touching `pipeline-svc`'s parsing/normalization code, `integrity-svc`'s Merkle/verify algorithms, etc.

## 4. Database Schema (D1 — authoritative, do not redefine elsewhere)

### `raw_events`
One row per ingested raw event. Written once by `ingestion-svc`; only `chunk_id`/`merkle_leaf_index` are backfilled later.

| Column | Type | Notes |
|---|---|---|
| `lineage_id` | UUID, PK | Generated at ingestion, never reused |
| `sha256_hash` | CHAR(64), indexed | Content seal of raw bytes |
| `ingestion_timestamp` | TIMESTAMPTZ(6) | UTC, microsecond |
| `source_ip` | INET | |
| `source_port` | INTEGER | |
| `transport_protocol` | VARCHAR(8), CHECK IN (UDP,TCP,TLS,HTTP) | |
| `char_encoding` | VARCHAR(16) | Detected, metadata only — never used to transform stored bytes |
| `raw_size_bytes` | INTEGER | |
| `storage_pointer` | TEXT | `raw_store://chunk_<id>/offset_<n>` |
| `chunk_id` | VARCHAR(64), nullable, indexed | Populated post-batching |
| `merkle_leaf_index` | INTEGER, nullable | Position within the chunk's Merkle tree |
| `created_at` | TIMESTAMPTZ(6) | |

### `merkle_chunks`
One row per Merkle batch.

| Column | Type | Notes |
|---|---|---|
| `chunk_id` | VARCHAR(64), PK | e.g. `chunk_20260925_01` |
| `event_count` | INTEGER | |
| `merkle_root_hash` | CHAR(64) | |
| `batch_opened_at` / `batch_closed_at` | TIMESTAMPTZ(6) | |
| `chain_tx_hash` / `chain_block_id` | VARCHAR(128), nullable | |
| `anchor_status` | VARCHAR(16), CHECK IN (pending,anchored,failed) | |
| `anchored_at` | TIMESTAMPTZ(6), nullable | |

### `extraction_history` (append-only)
| Column | Type | Notes |
|---|---|---|
| `extraction_id` | BIGSERIAL, PK | |
| `lineage_id` | UUID, FK → raw_events | |
| `path_taken` | VARCHAR(8), CHECK IN (HOT,COLD) | |
| `source_type` | VARCHAR(64) | e.g. `cisco_asa`, `unknown_v1` |
| `parser_version` | VARCHAR(32) | |
| `extracted_fields` | JSONB | |
| `confidence_scores` | JSONB | |
| `processed_at` | TIMESTAMPTZ(6) | |

### `normalization_history` (append-only)
| Column | Type | Notes |
|---|---|---|
| `normalization_id` | BIGSERIAL, PK | |
| `lineage_id` | UUID, FK → raw_events | |
| `extraction_id` | BIGINT, FK → extraction_history | |
| `ocsf_class_uid` | INTEGER | e.g. 4001 |
| `ocsf_event_json` | JSONB | |
| `schema_valid` | BOOLEAN | |
| `validation_errors` | JSONB, nullable | |
| `published_to_bus` | BOOLEAN | |
| `normalized_at` | TIMESTAMPTZ(6) | |

### `review_queue`
| Column | Type | Notes |
|---|---|---|
| `review_id` | BIGSERIAL, PK | |
| `lineage_id` | UUID, indexed | |
| `extraction_id` | BIGINT, FK → extraction_history | |
| `candidate_mapping` | JSONB | Field → OCSF candidate(s) + similarity scores |
| `cluster_id` | VARCHAR(64), indexed | Drain cluster, for grouped review |
| `status` | VARCHAR(16), CHECK IN (pending,in_review,confirmed,rejected) | |
| `assigned_analyst` | VARCHAR(128), nullable | |
| `confirmed_mapping` | JSONB, nullable | |
| `created_at` / `resolved_at` | TIMESTAMPTZ(6) | |

### `mapping_packs`
| Column | Type | Notes |
|---|---|---|
| `pack_id` | VARCHAR(64), PK | e.g. `cisco_asa_v1.3.0` |
| `source_type` | VARCHAR(64) | |
| `version` | VARCHAR(32) | Semver |
| `pack_yaml_hash` | CHAR(64) | |
| `signature` | TEXT | Ed25519 |
| `signer_key_id` | VARCHAR(64) | |
| `status` | VARCHAR(16), CHECK IN (draft,staged,quarantined,active,deprecated) | |
| `parent_pack_id` | VARCHAR(64), nullable, FK → mapping_packs | Inheritance |
| `chain_provenance_tx` | VARCHAR(128), nullable | |
| `created_at` / `promoted_at` | TIMESTAMPTZ(6) | |

### `pack_lifecycle_events` (append-only)
| Column | Type | Notes |
|---|---|---|
| `event_id` | BIGSERIAL, PK | |
| `pack_id` | VARCHAR(64), FK → mapping_packs | |
| `event_type` | VARCHAR(24), CHECK IN (pack_created,pack_confirmed,pack_updated,pack_rolled_back,pack_quarantined) | |
| `actor` | VARCHAR(128) | Never anonymous |
| `event_hash` | CHAR(64) | Anchored on-chain |
| `chain_tx_hash` | VARCHAR(128), nullable | |
| `occurred_at` | TIMESTAMPTZ(6) | |

### `test_fixtures`
| Column | Type | Notes |
|---|---|---|
| `fixture_id` | BIGSERIAL, PK | |
| `pack_id` | VARCHAR(64), FK → mapping_packs | |
| `sample_raw_pointer` | TEXT | |
| `expected_ocsf_json` | JSONB | |
| `created_at` | TIMESTAMPTZ(6) | |

**MVP note:** SQLite type mapping — `UUID`/`INET`/`TIMESTAMPTZ` → `TEXT` (ISO-8601 UTC, microseconds); `JSONB` → `JSON`; `BIGSERIAL` → `INTEGER PRIMARY KEY AUTOINCREMENT`. CHECK constraints kept as-is. History tables (`extraction_history`, `normalization_history`, `pack_lifecycle_events`) expose only insert operations at the repository layer — no code path may `UPDATE`/`DELETE` them.

## 5. Message Bus Contracts (D5)

All topics are versioned (`.v1`); a breaking change ships as `.v2` consumed in parallel during migration.

| Topic | Producer | Consumer(s) |
|---|---|---|
| `ulpf.raw.ingest.v1` | `ingestion-svc` | `pipeline-svc` (router) |
| `ulpf.merkle.leaf.v1` | `ingestion-svc` | `integrity-svc` |
| `ulpf.review.queue.v1` | `pipeline-svc/coldpath` | `review-api` |
| `ulpf.pack.lifecycle.v1` | `pipeline-svc` (pack registry) | `integrity-svc`, audit subscribers |
| `ulpf.ocsf.events.v1` | `pipeline-svc` (normalization) | `sinks-svc` (consumer groups `siem-streaming`, `lake-batch`, independent offsets) |

### `ulpf.raw.ingest.v1`
```json
{
  "lineage_id": "uuid-v4",
  "raw_bytes_b64": "base64 — omitted above bus.max_inline_bytes, use storage_pointer instead",
  "storage_pointer": "raw_store://chunk_20260925_01/offset_42",
  "sha256_hash": "hex64",
  "ingestion_timestamp": "2026-09-25T09:12:44.123456Z",
  "source_ip": "203.0.113.5",
  "source_port": 51422,
  "transport_protocol": "UDP",
  "char_encoding": "UTF-8"
}
```

### `ulpf.merkle.leaf.v1`
```json
{ "lineage_id": "uuid-v4", "sha256_hash": "hex64", "ingestion_timestamp": "2026-09-25T09:12:44.123456Z" }
```

### Common Intermediate Extraction Envelope
Emitted by both hot and cold path — the contract that lets normalization treat both identically.
```json
{
  "lineage_id": "uuid-v4",
  "path_taken": "HOT | COLD",
  "source_type": "cisco_asa",
  "extracted_fields": { "src_ip": "10.1.1.1", "dst_ip": "8.8.8.8", "action": "Deny" },
  "confidence_scores": { "src_ip": 1.0, "dst_ip": 1.0, "action": 0.95 },
  "parser_version": "1.3.0"
}
```
Hot-path scores are always `1.0`. Normalization logic must never branch on `path_taken` beyond reading this field.

### `ulpf.review.queue.v1`
```json
{
  "review_id": null,
  "lineage_id": "uuid-v4",
  "extraction_id": 0,
  "cluster_id": "drain-cluster-0042",
  "candidate_mapping": {
    "field_raw_token_3": {
      "candidate_ocsf_attribute": "dst_endpoint.hostname",
      "similarity_score": 0.71,
      "alternate_candidates": [{ "attribute": "src_endpoint.hostname", "similarity_score": 0.68 }]
    }
  },
  "sample_raw_pointer": "raw_store://chunk_20260925_01/offset_42"
}
```

### `ulpf.pack.lifecycle.v1`
```json
{
  "pack_id": "cisco_asa_v1.3.0",
  "event_type": "pack_created | pack_confirmed | pack_updated | pack_rolled_back | pack_quarantined",
  "actor": "analyst:jdoe | system:auto-onboarding",
  "event_hash": "hex64",
  "occurred_at": "2026-09-25T09:12:44Z"
}
```

### `ulpf.ocsf.events.v1` (OCSF Class 4001 + ULPF extensions)
```json
{
  "activity_id": 5, "activity_name": "Refuse",
  "category_uid": 4, "class_uid": 4001, "class_name": "Network Activity",
  "severity_id": 4,
  "time": 1790328764123,
  "src_endpoint": { "ip": "10.1.1.50", "port": 49823 },
  "dst_endpoint": { "ip": "8.8.8.8", "port": 443 },
  "connection_info": { "protocol_num": 6, "protocol_name": "tcp" },
  "metadata": { "version": "1.2.0", "uid": "<lineage_id>", "product": { "vendor_name": "Cisco", "name": "ASA Firewall" } },
  "raw_data": "raw_store://chunk_20260925_01/offset_42",
  "_confidence": { "src_endpoint.ip": 1.0, "activity_id": 0.95 },
  "_lineage_id": "<lineage_id>"
}
```
`metadata.uid` and `_lineage_id` are always identical. `time` (epoch ms) is a documented addition to the original spec example — OCSF requires it (see Decisions Log).

## 6. Internal REST API (`review-api` ↔ `pipeline-svc` pack registry, and ↔ `review-ui`)

| Endpoint | Method | Purpose |
|---|---|---|
| `/internal/packs/drafts` | GET | List `draft`/`staged` packs, grouped by cluster |
| `/internal/packs/{pack_id}` | GET | Full pack detail, candidate mappings |
| `/internal/packs/{pack_id}/confirm` | POST | Analyst confirms/corrects a draft; triggers signing, fixture generation, anchoring, hot-reload |
| `/internal/packs/{pack_id}/reject` | POST | Marks a draft rejected |
| `/internal/packs/{pack_id}/rollback` | POST | Reverts an active pack to its previous signed version |
| `/health` | GET | Liveness |
| `/ready` | GET | Readiness — `200` only when DB, bus, and (for `pipeline-svc`) the pack registry snapshot are all confirmed ready; `503` otherwise. Orchestration/health checks must use `/ready`, never `/health` |
| `/trace/{lineage_id}` | GET | Full forward trace |
| `/verify/{lineage_id}` | GET | Merkle proof verification result |

Optimistic concurrency: `/confirm` rejects a second concurrent submission on the same cluster with `409 Conflict` — never silently overwritten.

## 7. Naming Conventions

- **Files/branches:** `kebab-case` (`review-api`, `pipeline-svc`).
- **Python:** `snake_case` for modules/functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants.
- **TypeScript:** `camelCase` for functions/variables, `PascalCase` for types/classes/React components, `UPPER_SNAKE` for constants.
- **DB tables/columns:** `snake_case`, always matching Section 4 exactly — no service may invent its own column or table name.
- **Bus topics:** `ulpf.<domain>.<noun>.v<major>` (e.g. `ulpf.ocsf.events.v1`) — versioned in the name always.
- **Pack IDs:** `{source_type}_v{semver}` (e.g. `cisco_asa_v1.3.0`).
- **Chunk IDs:** `chunk_<yyyyMMdd>_<sequence>`.
- **Cluster IDs:** `drain-cluster-<zero-padded-int>`.
- **`lineage_id`:** UUIDv4, generated once at ingestion, never regenerated, never reused as a lookup key for anything except itself.
- **Config keys:** `snake_case`, dot-namespaced by owning module (e.g. `batch.max_event_count`, `confidence.auto_accept_threshold`) — mirrors the original spec's config tables so nothing needs renaming when upgrading.

## 8. Non-Functional Requirements Carried Into the MVP

- No runtime network calls outside the local Docker network (air-gap principle) — verified in CI with `--network none`.
- History tables append-only, enforced at the repository layer.
- Every dropped/failed item logged with its `lineage_id`; nothing fails silently.
- Every heavy dependency (DB, bus, ledger, embedder) sits behind an interface — swapping the implementation must never require touching business logic in another service.

## 9. Decisions Log (deviations from the original 14-doc spec)

| Date | Decision | Reason | Upgrade impact |
|---|---|---|---|
| — | Mixed Python/Node/Next.js stack instead of pure Python | Matches team's existing MERN/Next.js skills across 8 people | Contracts shared via generated JSON Schema → Pydantic + TS types |
| — | SQLite instead of PostgreSQL for the MVP | Faster local setup, zero external service to run | Swap DB URL + engine per Phase table in `phases.md`; schema unchanged |
| — | Local filesystem instead of MinIO | Simpler for MVP | `storage_pointer` format is store-agnostic already |
| — | Hash-chained signed JSONL file instead of a real blockchain node | No blockchain infra needed to prove the ledger contract works | `integrity-svc`'s `Ledger` interface is the only thing that changes |
| — | `time` (epoch ms) added to the OCSF event example | OCSF Class 4001 requires it; original spec example omitted it | None — additive, non-breaking |
| — | Cold-path semantic mapping uses lexical (TF-IDF) similarity instead of ONNX MiniLM + FAISS | No model/index needed to validate the confidence-gating and pack-generation logic | `Embedder`/`VectorIndex` interfaces swap; thresholds need recalibration |
| 2026-09-26 | M7 Throughput & Latency Calibration Benchmarks | Establishes verified MVP performance baseline (Ingestion seal: 550k eps @ 1.6µs p50; Regex Router: 61.5k eps @ 15.3µs p50; OCSF 4001 Normalizer: 50.0k eps @ 17.9µs p50; Merkle Builder: 1.32M leaves/sec @ 71.8µs p50) | All core stages exceed the 10,000 eps production throughput SLA by 4x to 50x; verified offline under air-gap constraints. |

*(Keep this table current — every architectural deviation from `docs/spec/` gets a row here before it ships.)*
