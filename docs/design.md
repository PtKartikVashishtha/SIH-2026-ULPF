# ULPF — Design Document

**Scope of this document:** the full MVP project's design surface — the analyst Review UI (Next.js), the app-facing surface, and the conventions the CLI/API follow so everything feels consistent. This is a reference doc, not a phase log; check `phases.md` for when each screen actually gets built.

---

## 1. Design Principles

- **Analyst efficiency over polish.** The review flow (FR-I.1) exists to let one analyst action confirm an entire log-format cluster. Every screen should reduce clicks-per-onboarded-format, not add visual flourish.
- **Never hide the raw evidence.** Any screen showing a proposed mapping must show the raw sample it came from, next to it, always.
- **Show system state honestly.** A pending/stalled/failed state is shown as such — no screen may imply success before the underlying pipeline has actually confirmed it (see Status Tracker, Section 4).
- **Air-gap safe.** No CDN fonts, no CDN icon packs, no external analytics/telemetry in the UI. Vendor everything (fonts, icons) into the repo.
- **Accessible by default.** Keyboard-navigable review flow (analysts will do this dozens of times a day), sufficient color contrast, no color-only status indicators (pair color with text/icon).

## 2. Design System (`review-ui`, Next.js + React)

### 2.1 Tokens

| Token | Value (starting point — tune once the frontend dev picks a direction) |
|---|---|
| Font | System font stack by default (`-apple-system, Segoe UI, Roboto, sans-serif`); vendor a single local webfont only if a specific look is required |
| Base spacing unit | 4px, scale: 4/8/12/16/24/32/48 |
| Border radius | 6px (cards), 4px (inputs/buttons) |
| Primary color | Used for primary actions (Confirm, Submit) — pick one accessible brand color and derive a 5-step scale |
| Semantic colors | `success` (promoted/anchored), `warning` (pending/degraded), `danger` (quarantined/rejected/failed), `info` (in_review) — each paired with a label, never color alone |
| Confidence score display | Numeric (0.00–1.00) always shown alongside any color/bar treatment |

### 2.2 Component Inventory

Build these as reusable components before wiring up pages — every review-flow screen composes from this set:

- `ClusterCard` — cluster_id, sample volume, age, status chip
- `RawSampleViewer` — monospace, line-numbered, non-editable, shows up to 5 representative samples per cluster
- `FieldMappingRow` — raw token/context → proposed OCSF attribute (dropdown of top-3 candidates + free-text override) → similarity score badge
- `StatusChip` — one of: `pending`, `in_review`, `confirmed`, `signed`, `anchored`, `promoted`, `rejected`, `quarantined`, `rolled_back` — each with a fixed color+icon+label mapping, defined once and reused everywhere
- `TriageDashboard` widgets — pending count, oldest-unresolved age, per-analyst load
- `ConflictBanner` — shown when `/confirm` returns 409, offers "view the winning confirmation"
- `StalenessBanner` — shown when the queue view is serving cached data because `review-api`/bus is unreachable

### 2.3 Layout

- **Queue view** (landing page): table/list of clusters, sortable by `volume_desc` (default) or age, filterable by status. One row = one cluster, not one raw sample.
- **Cluster detail view**: two-pane — left: discovered template + up to 5 raw samples; right: field-by-field `FieldMappingRow` list. One **Submit** button at the bottom confirms the *entire cluster* in one action (never a per-field submit button).
- **Status progression**: a single `StatusChip` on both the queue view and the cluster detail view, polling `review-api` (default every 3s) so the analyst sees `confirmed → signed → anchored → promoted` without navigating away.
- **Trace/verify view** (auditor-facing, lower priority — can be CLI-only in the MVP): input a `lineage_id`, show the forward trace and Merkle verification result.

### 2.4 Forms

- Mapping correction is a **searchable dropdown** (not free typing from scratch) sourced from the OCSF attribute catalog, with a free-text escape hatch for attributes not in the top-3 candidates.
- Every form submission is optimistic in the UI but must reconcile against the server response — on `409`, roll back the optimistic state and show `ConflictBanner`.
- No form may submit silently on blur/auto-save for a *confirm* action — confirmation is always an explicit, deliberate click (this is a governance action, not a draft).

### 2.5 Empty / Error / Loading States

- Empty queue → explicit "no clusters pending review" state, not a blank table.
- `review-api` unreachable → `StalenessBanner` + last-known-good cached view (read-only), never a full-page error blocking read access.
- Any pipeline failure surfaced by the Status Tracker (e.g., signing failed downstream of a confirm) → explicit failure state with a "this needs investigation" call-out, never silently stuck on "confirmed" forever.

## 3. App-Facing Surface (owner: app developer)

Scope to be confirmed with the PM (the original spec has no dedicated app) — treat this as one of:
- An operations/monitoring dashboard (queue health, ingestion throughput, air-gap status) consuming the same `review-api`/`/health`, `/ready` endpoints plus a small metrics endpoint.
- A lightweight desktop/analyst companion app, same API surface as `review-ui`, different shell.

Whichever direction is chosen, it must **only** talk to the documented REST API in `architecture.md` Section 6 — never directly to the Index DB or bus.

## 4. CLI Conventions (`pipeline-svc`, Python — used before the web UI exists)

Since the review web UI is a later phase, the CLI is the first analyst-facing surface and should mirror the same information architecture so the eventual web UI isn't a redesign:

- `ulpf review` — queue view (list clusters, sorted by volume) → select a cluster → shows template + samples + field mappings → accept/pick-alternate/override per field → one submit confirms the cluster → live status line as it progresses.
- `ulpf trace <lineage_id>` — mirrors the (future) trace view.
- `ulpf verify <lineage_id> [--deep]` — mirrors the (future) verify view.
- Use `rich` for tables/status coloring in the terminal, with the same semantic color mapping as `StatusChip` (Section 2.2) — so a `pending` cluster is always the same color whether seen in the terminal or the browser.

## 5. API/Contract Conventions (applies to both `review-api` and `pipeline-svc`)

- All timestamps in API responses are ISO-8601 UTC strings; all internal storage is UTC.
- All list endpoints are paginated (`?cursor=` or `?page=`/`?limit=`) even if the MVP's first dataset is small — retrofitting pagination later breaks UI contracts.
- Error responses use a single consistent shape: `{ "error": { "code": "string", "message": "string", "details": {} } }` across every service, Python and Node alike.
- Every mutating endpoint (`/confirm`, `/reject`, `/rollback`) requires an `actor` identity in the request (never anonymous) — this feeds `pack_lifecycle_events.actor` directly.

## 6. Open Design Decisions (resolve during M6/M8 — see `phases.md`)

- Final color palette and typography — owner: frontend developer.
- Whether the app-facing surface is a dashboard or an analyst companion app — owner: PM + app developer.
- Auth mechanism for the review UI (local RBAC recommended per the spec's security doc) — owner: backend + blockchain dev (key/identity handling overlaps).
