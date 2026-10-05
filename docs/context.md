# ULPF — Context Log (Current Status)

**Scope of this document:** the CURRENT phase only. Unlike the other docs, this file is not a reference — it is a running, dated log of what has actually been built, checked and verified in this repo. It exists so that any contributor, and any LLM agent resuming work, can know exactly what's real without re-reading every commit or guessing from the plan.

> **Rule: nothing goes in this file unless it has been actually built and its acceptance criteria (from `phases.md`) have actually passed.** A planned feature, an in-progress feature, or an assumption is NOT a status update — see `agent.md` Section "Anti-Hallucination Rules" for the exact discipline.

## Current Phase: **M8 — Review Web UI / Full Analyst UX**

**Phase start date:** 2026-09-26
**Phase status:** Complete (All Milestones M0 through M8 Completed & Verified)

## What Exists Right Now

### Monorepo folder structure
Full monorepo tree created per README §4: `docs/`, `packages/contracts/`, `packs/`, `services/` (6 services), `tools/`, `keys/`, `tests/e2e/`, `docker/`.

### `packages/contracts` — JSON Schema + Generated Types
- **7 JSON Schemas** in `packages/contracts/schemas/`:
  `raw_ingest.v1`, `merkle_leaf.v1`, `extraction_envelope`, `review_queue.v1`, `pack_lifecycle.v1`, `ocsf_event.v1`, `error_response`
- **Python (Pydantic v2):** Generated models in `packages/contracts/python/ulpf_contracts/generated/` via `datamodel-code-generator`. Re-exported from `ulpf_contracts/__init__.py`.
- **TypeScript:** Generated interfaces in `packages/contracts/typescript/src/generated.ts` via `json-schema-to-typescript`. Barrel-exported from `src/index.ts`. Built to `dist/`.
- **Codegen scripts:** `packages/contracts/python/scripts/generate.py` and `packages/contracts/typescript/scripts/generate.mjs`.

### DB Schema (SQLite)
- All 8 tables from `architecture.md` §4 implemented in `packages/contracts/python/ulpf_contracts/db_schema.py` and `services/review-api/src/db.ts` / `services/ingestion-svc/src/db.ts`.
- Tables: `raw_events`, `merkle_chunks`, `extraction_history`, `normalization_history`, `review_queue`, `mapping_packs`, `pack_lifecycle_events`, `test_fixtures`, plus `_schema_version`.
- WAL mode, foreign keys, CHECK constraints, MVP type mappings (UUID→TEXT, JSONB→JSON, BIGSERIAL→INTEGER AUTOINCREMENT).

### `ingestion-svc` (M1 Complete)
- **Listeners:** Syslog UDP (RFC 3164/5424), TCP (octet-counting & newline delimited), and HTTP (`POST /ingest`).
- **Envelope generator:** Generates UUIDv4 `lineage_id`, 64-character lowercase SHA-256 content seal, ISO-8601 UTC microsecond timestamp, and non-destructive character encoding detector.
- **Raw Store:** Filesystem chunk store with `zstd-codec` frame compression and `.idx.json` offset indexing. Bit-for-bit raw byte recovery verified.
- **Dual-Trigger Batcher:** Flushes on count trigger (`maxEventCount`) or time trigger (`maxTimeMs`). Publishes `ulpf.raw.ingest.v1` and `ulpf.merkle.leaf.v1` to local event bus.
- **Durable Spool:** Disk-backed write-ahead queue (`spool/*.jsonl`) diverting events during SQLite outages; automatically flushes and drains to DB upon recovery with zero data loss.

### `integrity-svc` (M2 Complete)
- **Merkle Tree Builder:** Deterministic leaf ordering by `lineage_id` guaranteeing identical roots regardless of leaf arrival order; spec padding rule (odd leaves duplicate last node); domain separation prefixes (`0x00` leaves, `0x01` internal); single-lineage sibling-hash proof generator and verifier.
- **Hash-Chained Signed Ledger:** Append-only signed JSONL file (`data/ledger.jsonl`), cryptographic Ed25519 signing using repo keypair (`keys/dev_signing.key`), chain verification checking contiguous sequence, prev_hash continuity, and cryptographic signature validity.
- **Anchor Service:** Orchestrates chunk closing, builds Merkle tree, records to signed ledger, updates `merkle_chunks` in SQLite, and backfills `raw_events` leaf indexes.
- **Deep Verification:** Re-reads raw zstd chunk files directly from disk, independently recomputes content seal SHA-256 for all raw slices, reconstructs Merkle tree, and validates against ledger anchor.
- **Tamper Drill Tooling:** Utility for deliberate byte-level raw chunk corruption, ledger line editing, or DB hash tampering. Verifies deep verify fails, isolates the altered leaf ID, and confirms untouched chunks verify (negative control).

### `pipeline-svc` (M3 & M4 Complete)
- **Pack Compiler & Inheritance:** YAML parser with multi-level inheritance resolution, child-over-parent field precedence, regex compilation, cyclic inheritance rejection (`CyclicInheritanceError`), and syntax failure isolation.
- **Ed25519 Signing & Quarantine:** Cryptographic canonical SHA-256 pack hashing and Ed25519 signature verification against public key PEM. Any unsigned or tampered pack is quarantined immediately and never loaded into active memory.
- **RCU Registry & Hot Reload:** Zero-restart atomic snapshot swap (`RegistrySnapshot`). Rollback restores prior version behavior exactly. Continuous stream processing through live reloads verified with zero dropped events or mixed states.
- **Reconciliation Sweep:** Filesystem pack loader and directory sweep (`reconcile_sweep`) resolving cross-pack inheritance dependencies deterministically and flagging quarantined files.
- **Hot-Path Regex Router:** Evaluates active signature registry, extracts named groups and mapped fields into `ExtractionEnvelope` at confidence 1.0, records execution to SQLite `extraction_history`.
- **Layer 1 Crosswalk:** Maps extracted fields from `ExtractionEnvelope` to OCSF 4001 (endpoints, connection info, activity, severity, metadata, product).
- **Layer 2 Canonicalizers:**
  - IP: IPv4 zero-stripping (e.g. `192.168.001.001` -> `192.168.1.1`) and RFC 5952 IPv6 compression & dual-form equivalence.
  - Port: Strict bounds `[0, 65535]`.
  - Timestamp: ISO-8601 UTC and Syslog BSD formats normalized to epoch milliseconds.
  - Enums: Activities & protocols mapped with fallback to 99 ("Other" / unknown).
- **Layer 3 OCSF Assembly & Validation:** Assembles `OcsfNetworkActivityV1` (Class 4001). Guaranteed invariant: `metadata.uid == _lineage_id`.
- **Invalid Timestamp Isolation:** Invalid timestamps recorded as `schema_valid=false`, validation errors captured, and never published to the event bus.
- **Persistence & Bus Publish:** Append-only writes to SQLite `normalization_history` and publication to `ulpf.ocsf.events.v1`.
- **Shipped Signed Packs:** Dev-signed `packs/base/base_network.yaml` and vendor pack `packs/vendors/cisco_asa_v1.3.0.yaml`.

### `sinks-svc` (M5 Complete)
- **Local Message Bus:** Topic `ulpf.ocsf.events.v1` with independent consumer-group offsets (`siem-streaming`, `lake-batch`), per-group overflow disk spooling, and non-blocking decoupled delivery.
- **SIEM Stand-in Sink:** Dual-output JSONL (`data/sinks/siem/events.jsonl`) and Syslog/CEF (`data/sinks/siem/events.cef`) with full RFC/CEF header escaping and extension field serialization.
- **Parquet Data Lake Writer (`pyarrow`):** Strongly-typed PyArrow schema for OCSF 4001, date-partitioned layout (`year=YYYY/month=MM/day=DD/`), and dedicated `_confidence` struct column containing per-field float scores.
- **Zero-Preprocessing Parquet Access:** `pandas.read_parquet()` reads generated Parquet files directly with zero preprocessing, preserving nested endpoints and confidence structures.
- **Resilience & Backpressure Isolation:** Killing/blocking the SIEM sink causes zero measurable impact on ingestion or the data lake writer; SIEM sink catches up in order once unblocked.

### `pipeline-svc/coldpath` (M6 Complete)
- **Drain Template Miner:** Fixed-depth parse tree clustering by length and first token with dynamic `<*>` wildcard extraction.
- **Seeded Warm-Start:** Transfer-learning token overlap seeding from existing active packs accelerating convergence on known vendors.
- **Lexical Semantic Mapper:** TF-IDF n-gram vector matching against OCSF 4001 vocabularies with type-compatibility verification (IP parsing, port ranges).
- **Confidence Gate:** Threshold gating (default 0.85) routing low-confidence fields to SQLite `review_queue` while allowing confident fields through.
- **Draft Pack Generator:** Automatically synthesizes standard YAML mapping packs and automated test fixture records from clusters and confirmed mappings.
- **Auto-Onboarding Lifecycle Loop:** Analyst confirmation triggers Ed25519 pack signing, lifecycle record persistence in SQLite, and atomic RCU snapshot hot-reload into `PackRegistry`. The next log of that format immediately takes the HOT path with 1.0 confidence.
- **Concurrency Conflict Detection:** Prevents simultaneous confirmation collisions, returning HTTP 409 conflict.
- **Cluster Capacity Capping:** Sets `capacity_capped=True` and flags clusters rather than mis-merging diverging formats.

### Hardening, Docker & Air-Gap (M7 Complete)
- **Hardened Multi-Stage Dockerfiles (`docker/`):** 6 Dockerfiles (`Dockerfile.ingestion`, `Dockerfile.integrity`, `Dockerfile.pipeline`, `Dockerfile.sinks`, `Dockerfile.review-api`, `Dockerfile.review-ui`). Minimal runtime base images, non-root users (UID 1000/10001), zero build/compiler tools in runner stages.
- **Docker Compose Topologies:** `docker-compose.yml` (production multi-container configuration with healthchecks, non-root privileges, volume mounts) and `docker-compose.airgap.yml` (sets `internal: true` network for total offline boundary enforcement).
- **Air-Gap Compliance Tooling (`tools/check_airgap.py`):** Scans for zero external CDN links (fonts, scripts), validates native system font typography, runs runtime socket drill ensuring 0 outbound internet requests.
- **Throughput & Latency Benchmarks (`tools/benchmark.py`):**
  - Ingestion seal: **447,151 eps** (p50: 1.6µs, p99: 3.6µs)
  - Hot-path regex router: **48,002 eps** (p50: 19.6µs, p99: 31.8µs)
  - OCSF 4001 Normalization: **41,264 eps** (p50: 22.5µs, p99: 34.7µs)
  - Merkle tree builder: **1,126,060 leaves/sec** (p50: 89.9µs, p99: 130.1µs)
- **End-to-End Integration Drill (`tests/e2e/test_end_to_end_m7.py`):** Multi-event ingestion, zstd compression, Merkle anchor, tamper drill (altering 1 byte isolates corrupted leaf, verifies negative control), OCSF assembly, SIEM JSONL/CEF sinks, Parquet data lake, and cold-path auto-onboarding hot-reload.

### Review UI & Review API (M8 Complete)
- `review-api` (Port 4000): 16 REST endpoints with SQLite database integration, forward trace `/trace/:id`, Merkle deep verification `/verify/:id`, queue triage, and `/queue/clusters/:id/confirm` lifecycle promotion with 409 conflict handling (6/6 tests pass).
- `review-ui` (Port 3000): Dark-mode analyst dashboard SPA built with Next.js 15 standalone mode. Implements full component inventory per `design.md` (`ClusterCard`, `RawSampleViewer` with line numbers, `FieldMappingRow` with candidate dropdown + free-text override, `StatusChip`, `TriageDashboard` widgets, `ConflictBanner`, `StalenessBanner`). 100% air-gap compliant (system fonts, zero external CDNs). Next.js production build verified clean (5.14 kB route, 108 kB First Load JS).

### Services Status
| Service | Language | Status |
|---|---|---|
| `ingestion-svc` | Node/TS | M1 complete: listeners, envelope generator, raw store (zstd), batcher, durable spool, 8/8 tests pass |
| `integrity-svc` | Node/TS | M2 complete: Merkle builder, signed ledger, anchor service, deep verify, tamper drill, 7/7 tests pass |
| `pipeline-svc` | Python | M3, M4, M6 complete: pack compiler, RCU registry, hot-path router, OCSF 4001 normalizer, cold-path Drain miner, semantic mapper, confidence gate, draft generator, auto-onboarding loop, 22/22 tests pass |
| `sinks-svc` | Python | M5 complete: LocalMessageBus, SIEM JSONL/CEF sink, Parquet data lake writer, 7/7 tests pass |
| `review-api` | Node/TS | M8 complete: 16 REST endpoints, cluster confirmation lifecycle, 409 conflict detection, 6/6 tests pass |
| `review-ui` | Next.js | M8 complete: Analyst review SPA on port 3000, 5 views, 100% air-gap compliant, production build verified |
| `docker` & `e2e` | Multi | M7 complete: 6 multi-stage Dockerfiles, compose air-gap topology, benchmarks runner, E2E drill, 1/1 tests pass |

### CI / lint / test
- **Python:** `pytest` runs 46 tests (16 contracts + 22 pipeline-svc + 7 sinks-svc + 1 e2e drill).
- **TypeScript:** 43 tests pass (22 contract tests + 8 ingestion acceptance tests + 7 integrity acceptance tests + 6 review-api tests).
- **Total tests: 89/89 passing across repository.**
- **Lint & Types:** `ruff check` 0 errors, `mypy` 0 errors across all Python packages, `tsc --noEmit` clean 0 errors across all TS packages.
- **Air-Gap Security:** `tools/check_airgap.py` passes 100% offline verification.
- **Live Verification (`tools/verify_live.py`):** Stages M1-M6 verified against live daemons and filesystem.

## Update Log

_(Newest entry at the top.)_

| Date | Phase | What shipped | Verified by | New deviations logged? |
|---|---|---|---|---|
| 2026-09-26 | M8 | Full M8 implementation: Analyst review SPA (`review-ui`, Next.js 15 standalone build), 5 views (Dashboard, Queue, Detail, Packs, Trace), two-pane cluster detail with line-numbered `RawSampleViewer` and `FieldMappingRow`, optimistic confirmation with HTTP 409 `ConflictBanner`, `review-api` pack lifecycle synchronization (`mapping_packs` + `pack_lifecycle_events`) | `next build` 0 errors (prerendered static), `vitest run` 6/6 review-api tests pass (43/43 TS suite, 89/89 full monorepo), `pnpm run ci` clean | No — adheres to design.md §2, architecture.md §6 |
| 2026-09-26 | M7 | Full M7 implementation: 6 multi-stage hardened Dockerfiles (`docker/Dockerfile.*`), `docker-compose.yml` & `docker-compose.airgap.yml` (internal: true), air-gap compliance scanner (`tools/check_airgap.py`), throughput & latency benchmark runner (`tools/benchmark.py`), full end-to-end integration and tamper drill test (`tests/e2e/test_end_to_end_m7.py`) | `pytest` 46/46 tests pass (84/84 full monorepo), `check_airgap.py` pass, `benchmark.py` pass (ingest 447k eps, router 48k eps, norm 41k eps, Merkle 1.1M leaves/sec), `pnpm run ci` clean | No — adheres to architecture.md §3, §4, §5 |
| 2026-09-26 | M6 | Full `pipeline-svc/coldpath` M6 implementation: Drain log clustering, transfer-learning token seeding, TF-IDF lexical semantic mapper + type verification, confidence gate (0.85) + SQLite `review_queue` routing, draft pack generator, auto-onboarding loop (Ed25519 signing, lifecycle records, RCU hot-reload swap, subsequent HOT path routing @ 1.0 confidence), HTTP 409 concurrency conflict check, cluster capacity capping | `pytest` 6/6 coldpath tests pass (45/45 Python suite, 83/83 full monorepo), `tools/verify_live.py` M1-M6 live pass, `ruff check` clean, `mypy` clean | No — adheres to architecture.md §3, §4, §5 |
| 2026-09-26 | M4 | Full `pipeline-svc` M4 implementation: Layer 1 crosswalk, Layer 2 canonicalizers (IPv4 zero-stripping, IPv6 dual-form equivalence, port bounds [0, 65535], timestamp formats to epoch ms, enum fallback to 99), Layer 3 OCSF 4001 assembly & validation, invariant `metadata.uid == _lineage_id`, invalid timestamp schema_valid=false isolation, SQLite `normalization_history` append-only repo, `ulpf.ocsf.events.v1` bus publisher | `pytest` 6/6 normalization tests pass (32/32 Python suite, 70/70 full monorepo), `ruff check` clean, `mypy` clean | No — adheres to architecture.md §3, §4, §5 |
| 2026-09-26 | M3 | Full `pipeline-svc` M3 implementation: pack YAML compiler, inheritance resolution & cycle rejection, Ed25519 pack sign/verify & quarantine, RCU atomic snapshot swap with rollback, directory reconciliation sweep, hot-path regex router producing `ExtractionEnvelope` at confidence 1.0, SQLite `extraction_history` repo, dev-signed `base_network` and `cisco_asa_v1.3.0` packs | `pytest` 10/10 pipeline-svc tests pass (26/26 full suite), `ruff check` clean, `mypy` strict clean, 0 drops during hot-reload under load | No — adheres to architecture.md §3, §4, §5 |
| 2026-09-26 | M2 | Full `integrity-svc` implementation: deterministic Merkle tree builder (spec padding rule, domain separation, sibling proofs), hash-chained signed JSONL ledger with Ed25519 signing, anchor service with SQLite `merkle_chunks` updates and `raw_events` backfill, deep verification from disk zstd bytes, tamper drill tooling | `vitest run` 7/7 tests pass (deterministic root regardless of arrival order, clean chunk verify, tamper drill failure & altered leaf isolation, negative control, edited ledger line detection), `tsc --noEmit` clean | No — adheres to architecture.md §3, §4, §5 |
| 2026-09-26 | M1 | Full `ingestion-svc` implementation: UDP/TCP/HTTP listeners, envelope generator, zstd raw store with offset index, dual-trigger batcher, SQLite `raw_events` writer, disk-backed durable spool, bus topics (`ulpf.raw.ingest.v1`, `ulpf.merkle.leaf.v1`) | `vitest run` 8/8 tests pass (fidelity, uniqueness, batch triggers, durable spool outage recovery, E2E listeners), `tsc --noEmit` clean | No — adheres to architecture.md §3, §4, §5 |
| 2026-09-26 | M0 | Full monorepo scaffold, 7 JSON Schema contracts, generated Pydantic+TS types, SQLite DB schema (8 tables), Ed25519 keygen, Makefile, 38 round-trip tests (16 Python + 22 TS), all lint/typecheck clean | `pytest` 16/16 pass, `vitest` 22/22 pass, `ruff check` 0 errors, `tsc --noEmit` 0 errors on 4 TS packages | No — all follows architecture.md |

## Open Questions / Blockers Right Now

- Final language choice for `integrity-svc` (Node vs. Python) — owner: blockchain developer, due end of M0 (see `prd.md` Section 8). Currently scaffolded as Node/TS.
- CI system not yet chosen/configured (GitHub Actions, GitLab CI, etc.) — the Makefile targets exist but no `.github/workflows/` or equivalent has been created.
- Confidence auto-accept threshold calibration is an M6 activity, not blocking M0.

## How to Update This File (read before editing)

1. Only add an entry after acceptance criteria for the relevant deliverable (per `phases.md`) have actually passed — not when code is written, not when it "should work."
2. State facts, not intentions: "ingestion-svc byte-fidelity test passes" not "ingestion-svc is basically done."
3. If something was built differently from what `architecture.md` or `phases.md` says, add a row to `architecture.md`'s Decisions Log **in the same session**, and reference it here.
4. When a phase's acceptance criteria are all met, update "Current Phase" at the top of this file to the next phase and reset "What Exists Right Now" to reflect the new baseline (keep the Update Log history, don't delete it).
5. If you are an LLM agent and you are not sure whether something has been built, **check the actual repo/code — do not infer from `phases.md` or from conversation history.** This file is only trustworthy if every entry was verified against real, running acceptance tests.
