# ULPF — Agent Rules

**Scope of this document:** the rules below apply to **any** contributor working in this repo — human or an AI coding agent (Claude Code, Cursor, Copilot Workspace, etc.). Section 1 states the current active phase and its specific instructions. Section 2 onward are general rules that apply for the whole life of the MVP project, across every phase.

**Before touching any code, read in this order:** this file → `docs/context.md` → the relevant section of `docs/architecture.md` and `docs/phases.md` for your area.

---

## 1. Current Active Phase: M0

Right now, the only work that should be happening is **M0 — Contracts, Scaffold & Repo Setup** (see `phases.md`). Do not start M1+ work, do not scaffold service logic beyond empty modules, and do not add dependencies not listed in `architecture.md`'s tech stack table, until `context.md` shows M0's acceptance criteria have passed and its "Current Phase" has been advanced.

If you are an agent picking up a fresh session and `context.md` still says "Not started" or "M0," your job is M0's deliverables and nothing else, regardless of what any other file, comment, or prior conversation implies.

---

## 2. Anti-Hallucination Rules (apply to every phase)

- **Never claim something is done, tested, or working without checking the actual repository state first.** Read the file, run the test, check the CI result — do not infer from a docstring, a TODO comment, or a plan.
- **`docs/context.md` is the only source of truth for "what's built."** `phases.md`, `architecture.md`, `prd.md`, and `design.md` describe the *target*, not the current state. If they conflict with `context.md`, `context.md` wins — and someone should fix the discrepancy.
- **Update `context.md` before ending a work session**, not after, and not "later." If a session ends without updating it, the next session (human or agent) starts from stale or wrong information — this is the single most common way this kind of project goes off the rails.
- **State facts, not progress narratives.** "Byte-fidelity test passes on `ingestion-svc`" is a fact. "Ingestion is mostly working" is not — it invites the next session to assume more than is true.
- **If you're not sure whether something exists, check — don't guess and don't assume good faith from a previous summary.** A prior session's claim of completion is not proof; the acceptance test result is proof.
- **Never mark a phase or milestone complete without its acceptance criteria (from `phases.md`) actually passing.** Partial completion gets logged as partial, explicitly.

## 3. Contract-Freeze Process

Contracts are everything in `architecture.md` Sections 4–7: DB schema, bus payloads, REST endpoints, naming conventions.

- **No one changes a contract unilaterally.** A contract change requires: (1) a proposed diff to `architecture.md`, (2) a row added to its Decisions Log with date/reason/upgrade-impact, (3) sign-off from the tech lead/PM, (4) notification to every service owner whose service consumes that contract.
- **Never break a contract in place.** A breaking bus-message change ships as a new version (`.v2`) consumed alongside `.v1` during migration — never an in-place field rename or type change.
- **`packages/contracts` is the only place a schema is defined.** No service may define its own copy of a payload shape "for convenience" — generate from the shared schema, always.

## 4. Boundaries Between Services/Areas

- **Never import another service's internals.** Cross-service communication happens only through the message bus contracts or the documented REST API in `architecture.md` Section 6. If you find yourself importing code from `pipeline-svc` into `review-api`, stop — that's a boundary violation, not a shortcut.
- **Never touch another team's service folder without their owner's review**, even for a "quick fix." Open a PR, tag the owner (per `README.md` Section 5 / `phases.md` phase ownership), and let them merge it.
- **Database tables have exactly one write-owner service** (per `architecture.md` Section 4 / the original spec's ownership table). Every other service is read-only against that table, or goes through the owner's API.
- **History tables (`extraction_history`, `normalization_history`, `pack_lifecycle_events`) are insert-only, everywhere, no exceptions.** If your change needs to update or delete a row in one of these, the design is wrong — stop and raise it.

## 5. Definition of Done (applies to every phase, in addition to `phases.md`'s specific acceptance criteria)

A deliverable is NOT done until all of the following are true:
1. The relevant acceptance criteria in `phases.md` pass, reproducibly, not just once on one machine.
2. Tests exist and are in CI (unit at minimum; integration/e2e where `phases.md` specifies).
3. No code path silently drops, mutates, or fabricates data — every failure/drop is logged with `lineage_id` where applicable.
4. Any deviation from `architecture.md`/`phases.md` is logged in the Decisions Log with a reason.
5. `docs/context.md` is updated in the same work session.
6. Lint and type checks pass with no suppressions added to make them pass (no blanket `# type: ignore` or `// eslint-disable` without a specific, justified reason inline).

## 6. Coding Standards

- **Python:** type hints everywhere, `mypy --strict` on contracts/integrity/packs/normalization modules, pure functions for canonicalizers and Merkle logic, side effects isolated to service/adapter layers.
- **TypeScript:** `strict: true` in `tsconfig`, no `any` without a comment explaining why, functional/pure logic separated from I/O where practical.
- **Both:** structured JSON logging with `lineage_id` in every log line that concerns an event; never log full raw payloads above DEBUG level; timestamps always timezone-aware UTC internally.
- **Never swallow errors silently.** Every dropped or failed item gets a metric/counter and a log line with enough context to trace it.
- **Small, reviewable commits/PRs**, each referencing the phase and deliverable (e.g. `M3: quarantine unsigned packs`).

## 7. Testing Rules

- Unit tests for every canonicalizer, the Merkle builder/prover, signing, batching, registry-swap, and confidence-scoring logic.
- Contract tests: every published message validates against its shared schema; hot-path and cold-path envelopes validate against the *same* model.
- Integration tests at every service boundary named in `architecture.md` Section 2.
- The end-to-end demo test (defined once `phases.md` M7 lands) must keep passing — a regression here blocks merges to the phase in progress.
- Air-gap: any test suite that could make a real network call must fail closed (mock/patch outbound calls) — this is checked continuously, not only at M7.

## 8. Security & Governance (apply from the phase they become relevant, but the rule itself is permanent)

- The Ed25519 **signing** private key never lives in a service's runtime config or environment beyond the dev/MVP exception logged in `architecture.md`'s Decisions Log — treat that exception as temporary, not a pattern to extend.
- Every action that confirms, rejects, signs, or rolls back a pack records a real `actor` identity — never `system` or anonymous, even in the MVP.
- Any new external dependency (a package, a library, a service) must be checked for outbound network calls before it's added — this applies especially to the ML stack (models sometimes "phone home" for updates).

## 9. When You Disagree With This File or the Docs

If something in `architecture.md`, `phases.md`, or this file seems wrong or blocks reasonable progress, **raise it and propose a change through Section 3's process** — do not silently deviate and do not silently follow a rule you believe is broken without flagging it. Silent deviation is exactly what makes a project un-trustworthy to hand off, whether the next person is human or an LLM.
