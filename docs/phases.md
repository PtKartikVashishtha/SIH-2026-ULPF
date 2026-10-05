# ULPF — Phases

**Scope of this document:** the full MVP project, broken into coding phases M0–M8. This is the plan; `context.md` is the truth about what has actually landed. If the two disagree, `context.md` wins and this file's phase should be corrected to match reality (with a note, not a silent edit).

---

## How to Use This

- Phases run roughly in order, but M2–M5 can overlap once contracts are frozen (M0) and ingestion (M1) is producing real envelopes.
- Each phase lists **deliverables**, **acceptance criteria** (a phase isn't done until these pass), and **owner(s)** given the team of 8 (3 ML, 2 backend, 1 blockchain, 1 frontend, 1 app dev).
- Nobody starts a phase's work until the previous phase it depends on has met its acceptance criteria — see the Dependency Table (Section 10).
- After each phase: update `context.md` (what shipped, what deviated, what's next) before starting the next phase. This is not optional — see `agent.md`.

---

## M0 — Contracts, Scaffold & Repo Setup

**Owner:** PM/tech lead, with one representative from each area for sign-off.

**Deliverables:**
- Full monorepo folder structure (per `README.md` Section 4) with empty service scaffolds.
- `packages/contracts`: JSON Schema for every payload in `architecture.md` Section 5, plus generated Pydantic models (Python services) and TypeScript types (Node/Next.js services).
- DB schema (architecture.md Section 4) implemented as migrations, runnable against SQLite.
- CI skeleton: lint + type-check + unit test stage for both the Python and Node/TS sides, `--network none` smoke-test stage stubbed in.
- `docs/context.md` initialized, `docs/agent.md` reviewed and acknowledged by every contributor.
- Ed25519 dev keypair generated (`ulpf keygen` equivalent), stored under a gitignored `keys/` directory.

**Acceptance criteria:**
- Every service scaffold builds/lints with zero errors on an empty implementation.
- A sample payload for each contract round-trips (encode → validate → decode) in both Python and TypeScript against the *same* generated types.
- `make lint test` (or the Node equivalent) is green in CI.

## M1 — Ingestion, Lineage, Raw Store

**Owner:** 2 backend developers (`ingestion-svc`, Node/TS).

**Deliverables:** Syslog UDP/TCP + HTTP listeners, envelope generator (lineage_id, sha256, encoding detection, context metadata), dual-trigger batcher (count or time window), zstd compression, filesystem raw store with offset index, `raw_events` writes, durable spool for DB/store outages, bus publish of `raw.ingest` and `merkle.leaf`.

**Acceptance criteria:** byte-for-byte fidelity test passes; N identical payloads produce N distinct `lineage_id`s; independently recomputed sha256 matches; both batch triggers (count, time) close a batch correctly; killing and restarting the DB mid-run loses nothing.

## M2 — Integrity: Merkle, Ledger, Verification

**Owner:** Blockchain developer (`integrity-svc`).

**Deliverables:** Merkle tree builder (spec padding rule), hash-chained signed ledger file, anchor service (consumes `merkle.leaf`, closes chunks in step with `ingestion-svc`), deep verification (re-hashes raw bytes from the store, not just DB values), single-lineage sibling-hash proof, tamper-drill tooling.

**Acceptance criteria:** deterministic root regardless of leaf-arrival order; `verify` passes on a clean chunk; after the tamper drill, deep verify fails and isolates the altered leaf while an untouched chunk still verifies (negative control); an edited ledger line is detected by chain verification.

## M3 — Packs, Signing, Hot Path

**Owner:** Backend developer (Python side of `pipeline-svc`), with the blockchain developer for signing/key handling.

**Deliverables:** pack YAML schema + compiler + inheritance resolution, Ed25519 sign/verify + quarantine, filesystem watcher + reconciliation sweep, atomic registry snapshot swap (RCU-style), signature registry + regex extractor (hot path), `extraction_history` writes, shipped base packs + Cisco ASA pack.

**Acceptance criteria:** ASA fixtures produce correct envelopes at confidence 1.0; an unsigned/tampered pack is quarantined and never loaded; a valid pack becomes active with zero restart; a continuous event stream through a reload shows zero drops or mixed views; a failed compile leaves the previous snapshot untouched; rollback restores prior behavior exactly; inheritance overrides work and cycles are rejected.

## M4 — Normalization to OCSF 4001

**Owner:** Backend developer (Python side of `pipeline-svc`).

**Deliverables:** Layer 1 crosswalk, Layer 2 canonicalizers (IP, timestamp, port, enum), Layer 3 OCSF assembly, schema validator, `normalization_history` writes, `ocsf.events` publish.

**Acceptance criteria:** canonicalizer unit + property tests pass (IPv4 zero-stripping, IPv6 dual-form equivalence, port bounds, timestamp formats, enum fallback to 99); a known ASA log produces a golden-matching OCSF record; an invalid timestamp is recorded as `schema_valid=false` and never published; `metadata.uid == _lineage_id` always.

## M5 — Sinks

**Owner:** One of the ML developers or a backend developer with Python/`pyarrow` familiarity — confirm assignment during M0 (`sinks-svc`).

**Deliverables:** local message bus with independent consumer-group offsets and per-group overflow spooling, JSONL + syslog/CEF SIEM stand-in, Parquet writer with typed columns and a `_confidence` struct column.

**Acceptance criteria:** the same event appears correctly in both the SIEM stand-in and Parquet; `pandas.read_parquet` works with zero preprocessing; killing/blocking the SIEM sink causes zero measurable impact on ingestion or the data lake writer, and the SIEM sink catches up in order once restored.

## M6 — Cold Path, Review, Auto-Onboarding Loop *(the hard phase)*

**Owner:** 3 ML developers, split as:
- **ML dev 1 — Template mining:** Drain wrapper, transfer-learning token-overlap seeding, cluster manager, capacity capping.
- **ML dev 2 — Semantic mapping:** lexical embedder (TF-IDF), vector index, type-compatibility scoring, confidence gate.
- **ML dev 3 — Evaluation & calibration:** sample-log corpus, threshold tuning (default 0.85), draft pack quality checks, transfer-learning convergence benchmarks.

Plus: 1 backend developer for `review-api` (REST endpoints, `review_queue` writes), blockchain developer for pack-lifecycle anchoring integration.

**Deliverables:** Drain-based clustering, seeded warm-start, lexical semantic mapper, confidence gate + review queue, draft pack generator, `review-api` endpoints (`/internal/packs/*`), pack lifecycle state machine + `pack_lifecycle_events`, auto-generated `test_fixtures`, CLI review tool (web UI is M8, optional).

**Acceptance criteria:** repeated unknown-format lines converge to one stable template; a similar-vendor format converges measurably faster with seeding than without; a forced low-similarity field lands in `review_queue` (not silently accepted) while the event still reaches output flagged in `_confidence`; one analyst confirmation signs → anchors → hot-reloads the pack, and the next log of that format takes the hot path; concurrent confirmations on the same cluster produce a `409` for the loser; the cluster-capacity cap flags rather than mis-merges.

## M7 — Hardening, Docker, Air-Gap, End-to-End

**Owner:** PM/tech lead + one representative per service for their own container.

**Deliverables:** multi-stage Dockerfiles per service (pinned digests, no build tooling in runtime images), Docker Compose topology, `/health`/`/ready` wired into health checks, `--network none` smoke test automated in CI, full end-to-end demo test (Section 2 of the original kickoff prompt / `context.md`'s demo script), throughput/latency benchmarks recorded, every active pack's fixtures passing in CI.

**Acceptance criteria:** the full demo script passes end-to-end; the stack runs under `--network none` with zero outbound connection attempts; benchmark numbers are recorded in `architecture.md`'s Decisions Log.

## M8 — Review Web UI (optional for MVP sign-off, required before broader rollout)

**Owner:** Frontend developer (`review-ui`, Next.js), app developer for the app-facing surface (`design.md` Section 3).

**Deliverables:** queue view, cluster detail view, submit flow, live status chip, triage dashboard — per `design.md`.

**Acceptance criteria:** an analyst can do the entire M6 review flow through the browser instead of the CLI, with identical outcomes (same endpoints, same state machine).

---

## Upgrade Path (post-MVP — not a phase yet, tracked here for planning)

| Order | Upgrade | Changes | Must not change |
|---|---|---|---|
| 1 | SQLite → PostgreSQL | DB URL/engine, JSON→JSONB, partitioning | Table/column names, repository interfaces |
| 2 | Local filesystem → MinIO | `RawStore`/lake implementation | `storage_pointer` format |
| 3 | Local bus → Kafka/Redpanda/NATS JetStream | `Bus` implementation, retention config | Topic names, message contracts, consumer group names |
| 4 | Ledger file → PoA Ethereum/Fabric node | `Ledger` implementation, moves into its own deployable | Anchored payload shape, verify algorithm |
| 5 | Lexical embedder → ONNX MiniLM + FAISS | `Embedder`/`VectorIndex` implementation | Confidence-gate logic and thresholds (recalibrate, don't rewrite) |
| 6 | Regex extractor → VRL engine | `Extractor` implementation | Pack YAML `extraction_rules` schema |
| 7 | Monorepo services → independently deployed containers matching the original 8-container topology | Deployment only | Interfaces and contracts |
| 8 | mTLS, RBAC, offline bundle importer, cold archival, Parquet compaction, HEC/OpenSearch translators, trained zstd dictionaries | Feature work per `docs/spec/` docs 07/08/09/13 | — |

## Dependency Table (Section 10 referenced above)

| Phase | Depends on | Blocks |
|---|---|---|
| M0 | — | Everything |
| M1 | M0 | M2, M3 (needs raw payload + lineage_id) |
| M2 | M1 | Provenance verification used by M6 |
| M3 | M0, M1 | M4 |
| M4 | M3 | M5 |
| M5 | M4 | M7 |
| M6 | M1, M3, M4 | M7 (auto-onboarding loop closes here), M8 |
| M7 | M1–M6 | Demo/UAT sign-off |
| M8 | M6 | Broader rollout, not MVP sign-off |
