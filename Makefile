# ─────────────────────────────────────────────────────────────
# ULPF — Makefile (M0 scaffold)
#
# Targets:
#   setup              Full first-time setup (Python + Node deps, DB, keypair)
#   generate-contracts Regenerate Pydantic + TS types from JSON Schema
#   lint               Lint Python + Node/TS
#   typecheck          Type-check Python + Node/TS
#   test               Run all tests
#   ci                 lint + typecheck + test (what CI runs)
#   db-migrate         Run SQLite migrations
#   keygen             Generate Ed25519 dev keypair
#   clean              Remove build artifacts and .db files
# ─────────────────────────────────────────────────────────────

.PHONY: setup generate-contracts lint typecheck test ci db-migrate keygen clean \
        lint-python lint-ts typecheck-python typecheck-ts test-python test-ts

# ── Paths ──
CONTRACTS_PY   := packages/contracts/python
CONTRACTS_TS   := packages/contracts/typescript
SCHEMAS        := packages/contracts/schemas
PIPELINE_SVC   := services/pipeline-svc
SINKS_SVC      := services/sinks-svc
INGESTION_SVC  := services/ingestion-svc
INTEGRITY_SVC  := services/integrity-svc
REVIEW_API     := services/review-api

# ═══════════════════════════════════════════════════════════
# Setup
# ═══════════════════════════════════════════════════════════

setup: setup-python setup-node db-migrate keygen
	@echo "✓ Setup complete"

setup-python:
	pip install -e "$(CONTRACTS_PY)[dev]"
	@echo "✓ Python contracts installed"

setup-node:
	cd $(CONTRACTS_TS) && npm install
	cd $(INGESTION_SVC) && npm install
	cd $(INTEGRITY_SVC) && npm install
	cd $(REVIEW_API) && npm install
	@echo "✓ Node packages installed"

# ═══════════════════════════════════════════════════════════
# Code Generation
# ═══════════════════════════════════════════════════════════

generate-contracts: generate-contracts-python generate-contracts-ts
	@echo "✓ All contracts regenerated"

generate-contracts-python:
	cd $(CONTRACTS_PY) && python scripts/generate.py
	@echo "✓ Python Pydantic models regenerated"

generate-contracts-ts:
	cd $(CONTRACTS_TS) && node scripts/generate.mjs
	@echo "✓ TypeScript types regenerated"

# ═══════════════════════════════════════════════════════════
# Lint
# ═══════════════════════════════════════════════════════════

lint: lint-python lint-ts
	@echo "✓ All linting passed"

lint-python:
	ruff check $(CONTRACTS_PY) $(PIPELINE_SVC) $(SINKS_SVC)
	@echo "✓ Python lint passed"

lint-ts:
	cd $(CONTRACTS_TS) && npx tsc --noEmit
	cd $(INGESTION_SVC) && npx tsc --noEmit
	cd $(INTEGRITY_SVC) && npx tsc --noEmit
	cd $(REVIEW_API) && npx tsc --noEmit
	@echo "✓ TypeScript lint passed"

# ═══════════════════════════════════════════════════════════
# Type Check
# ═══════════════════════════════════════════════════════════

typecheck: typecheck-python typecheck-ts
	@echo "✓ All type checks passed"

typecheck-python:
	cd $(CONTRACTS_PY) && mypy ulpf_contracts/
	@echo "✓ Python type check passed"

typecheck-ts:
	cd $(CONTRACTS_TS) && npx tsc --noEmit
	cd $(INGESTION_SVC) && npx tsc --noEmit
	cd $(INTEGRITY_SVC) && npx tsc --noEmit
	cd $(REVIEW_API) && npx tsc --noEmit
	@echo "✓ TypeScript type check passed"

# ═══════════════════════════════════════════════════════════
# Test
# ═══════════════════════════════════════════════════════════

test: test-python test-ts
	@echo "✓ All tests passed"

test-python:
	pytest $(CONTRACTS_PY)/tests/ -v
	@echo "✓ Python tests passed"

test-ts:
	cd $(CONTRACTS_TS) && npx vitest run
	@echo "✓ TypeScript tests passed"

# ═══════════════════════════════════════════════════════════
# CI (all-in-one)
# ═══════════════════════════════════════════════════════════

ci: lint typecheck test
	@echo "✓ CI pipeline passed"

# ═══════════════════════════════════════════════════════════
# Database
# ═══════════════════════════════════════════════════════════

db-migrate:
	python -m ulpf_contracts.db_schema
	@echo "✓ Database migration complete"

# ═══════════════════════════════════════════════════════════
# Key Generation
# ═══════════════════════════════════════════════════════════

keygen:
	python tools/keygen.py keys/
	@echo "✓ Ed25519 dev keypair generated"

# ═══════════════════════════════════════════════════════════
# Air-Gap Operations
# ═══════════════════════════════════════════════════════════

airgap-up:
	docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d
	@echo "✓ Air-gapped stack started"

airgap-down:
	docker compose -f docker-compose.yml -f docker-compose.airgap.yml down
	@echo "✓ Air-gapped stack stopped"

airgap-check:
	python tools/check_airgap.py

# ═══════════════════════════════════════════════════════════
# Clean
# ═══════════════════════════════════════════════════════════

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name node_modules -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name dist -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.db" -delete 2>/dev/null || true
	find . -name "*.db-journal" -delete 2>/dev/null || true
	rm -rf .mypy_cache .ruff_cache .pytest_cache
	@echo "✓ Clean complete"
