# hashcat-benchmark-suite — top-level Makefile
# Usage: make help

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---------- configurable variables ----------
PYTHON        ?= python3
HASHCAT_SRC   ?= ../hashcat
HASHCAT_BIN   ?= $(HASHCAT_SRC)/hashcat
ROCKYOU_PATH  ?= $(HOME)/wordlists/rockyou.txt
ROCKYOU_SHA256 := 9076652d8ae75ce713e23ab09e10d9ee1323b0b4a6d592ba1a46f8e5e4b5a836
TRIALS        ?= 30
QUICK_TRIALS  ?= 3
RESULTS_DIR   ?= results

# ---------- help ----------
.PHONY: help
help: ## Print this help message
	@echo "hashcat-benchmark-suite"
	@echo "======================"
	@echo ""
	@echo "Quick start:  make setup && make run-all && make submit"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-22s %s\n", $$1, $$2}'
	@echo ""
	@echo "Configuration (override via environment or command line):"
	@echo "  HASHCAT_SRC   = $(HASHCAT_SRC)"
	@echo "  HASHCAT_BIN   = $(HASHCAT_BIN)"
	@echo "  ROCKYOU_PATH  = $(ROCKYOU_PATH)"
	@echo "  TRIALS        = $(TRIALS)"
	@echo "  QUICK_TRIALS  = $(QUICK_TRIALS)"
	@echo "  RESULTS_DIR   = $(RESULTS_DIR)"

# ---------- setup & detection ----------
.PHONY: setup
setup: ## Validate Python, hashcat binary, and gh CLI
	@echo "--- Checking Python ---"
	@$(PYTHON) --version || { echo "ERROR: $(PYTHON) not found"; exit 1; }
	@echo ""
	@echo "--- Checking hashcat binary ---"
	@test -x "$(HASHCAT_BIN)" || { echo "ERROR: hashcat not found at $(HASHCAT_BIN)"; exit 1; }
	@$(HASHCAT_BIN) --version || { echo "ERROR: hashcat failed to report version"; exit 1; }
	@echo ""
	@echo "--- Checking gh CLI ---"
	@gh --version || { echo "ERROR: gh CLI not found"; exit 1; }
	@echo ""
	@echo "--- Checking Python dependencies ---"
	@$(PYTHON) -c "import json, subprocess, hashlib, pathlib" || { echo "ERROR: missing stdlib modules"; exit 1; }
	@echo ""
	@echo "All prerequisites satisfied."

.PHONY: detect
detect: ## Detect system hardware and configuration
	@$(PYTHON) tools/detect_system.py

# ---------- tests ----------
.PHONY: test
test: ## Run pytest test suite
	@$(PYTHON) -m pytest tests/ -v

# ---------- corpus ----------
.PHONY: generate-corpus
generate-corpus: ## Generate test corpus (deterministic + random + adversarial)
	@$(PYTHON) tools/generate_corpus.py --output-dir corpus

# ---------- rockyou.txt validation ----------
.PHONY: real-world-check
real-world-check:
	@test -f "$(ROCKYOU_PATH)" || { echo "ERROR: rockyou.txt not found at $(ROCKYOU_PATH)"; exit 1; }
	@echo "Validating rockyou.txt SHA-256..."
	@ACTUAL=$$(shasum -a 256 "$(ROCKYOU_PATH)" | awk '{print $$1}'); \
	if [ "$$ACTUAL" != "$(ROCKYOU_SHA256)" ]; then \
		echo "ERROR: SHA-256 mismatch"; \
		echo "  expected: $(ROCKYOU_SHA256)"; \
		echo "  actual:   $$ACTUAL"; \
		exit 1; \
	fi
	@echo "rockyou.txt validated."

# ---------- correctness ----------
.PHONY: run-correctness
run-correctness: ## Run correctness tests via Makefile.correctness
	@$(MAKE) -f Makefile.correctness run \
		PYTHON="$(PYTHON)" \
		HASHCAT_BIN="$(HASHCAT_BIN)" \
		RESULTS_DIR="$(RESULTS_DIR)"

# ---------- synthetic benchmarks ----------
.PHONY: run-synthetic
run-synthetic: ## Run synthetic benchmarks ($(TRIALS) trials)
	@$(PYTHON) tools/run_synthetic.py \
		--hashcat "$(HASHCAT_BIN)" \
		--trials $(TRIALS) \
		--output-dir "$(RESULTS_DIR)"

.PHONY: quick-synthetic
quick-synthetic: ## Run synthetic benchmarks ($(QUICK_TRIALS) trials, fast iteration)
	@$(PYTHON) tools/run_synthetic.py \
		--hashcat "$(HASHCAT_BIN)" \
		--trials $(QUICK_TRIALS) \
		--output-dir "$(RESULTS_DIR)"

# ---------- real-world benchmarks ----------
.PHONY: run-real-world
run-real-world: real-world-check ## Run real-world benchmarks with rockyou.txt ($(TRIALS) trials)
	@$(PYTHON) tools/run_real_world.py \
		--hashcat "$(HASHCAT_BIN)" \
		--wordlist "$(ROCKYOU_PATH)" \
		--trials $(TRIALS) \
		--output-dir "$(RESULTS_DIR)"

.PHONY: quick-real-world
quick-real-world: real-world-check ## Run real-world benchmarks with rockyou.txt ($(QUICK_TRIALS) trials)
	@$(PYTHON) tools/run_real_world.py \
		--hashcat "$(HASHCAT_BIN)" \
		--wordlist "$(ROCKYOU_PATH)" \
		--trials $(QUICK_TRIALS) \
		--output-dir "$(RESULTS_DIR)"

# ---------- run-all ----------
.PHONY: run-all
run-all: run-correctness run-synthetic ## Run correctness + synthetic; real-world if rockyou.txt present
	@if [ -f "$(ROCKYOU_PATH)" ]; then \
		echo ""; \
		echo "=== rockyou.txt found — running real-world benchmarks ==="; \
		$(MAKE) run-real-world \
			PYTHON="$(PYTHON)" \
			HASHCAT_BIN="$(HASHCAT_BIN)" \
			ROCKYOU_PATH="$(ROCKYOU_PATH)" \
			TRIALS="$(TRIALS)" \
			RESULTS_DIR="$(RESULTS_DIR)"; \
	else \
		echo ""; \
		echo "=== Skipping real-world benchmarks (rockyou.txt not found at $(ROCKYOU_PATH)) ==="; \
	fi

# ---------- submit ----------
.PHONY: submit
submit: ## Package and submit results
	@$(PYTHON) tools/submit_results.py \
		--results-dir "$(RESULTS_DIR)"

# ---------- clean ----------
.PHONY: clean
clean: ## Remove build artifacts and generated corpus
	rm -rf build/ __pycache__ .pytest_cache
	rm -rf corpus/deterministic corpus/random corpus/adversarial corpus/real_world
	rm -rf $(RESULTS_DIR)/*.json $(RESULTS_DIR)/*.csv
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned."
