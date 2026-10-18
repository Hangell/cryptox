SHELL := /bin/sh
.DEFAULT_GOAL := check

# Keep top-level checks sequential; Go controls its own test parallelism.
.NOTPARALLEL:

GO ?= go
GOFMT ?= gofmt
PACKAGES ?= ./...
TEST_TIMEOUT ?= 5m
TEST_SHUFFLE ?= on
FUZZ_TIME ?= 30s
FUZZ_TIMEOUT ?= 5m
FUZZ_PARALLEL ?= 2

# Keep this pin aligned with the reviewed version used in CI.
GOVULNCHECK_VERSION := v1.9.0

# Keep this pin aligned with the version installed in CI.
GOLANGCI_LINT_VERSION ?= v2.15.0
LINT ?= golangci-lint

REPORT_DIR := .reports
COVERAGE_FILE := $(REPORT_DIR)/coverage.out

# Include new packages without formatting vendored code or reports.
FIND_GO = find . -type d \( -name .git -o -name vendor -o -name .reports \) -prune \
	-o -type f -name '*.go'

.PHONY: help fmt fmt-check vet mod-verify test test-fast coverage-html \
	lint lint-install fuzz security check ci bench clean

help: ## List available targets.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "%-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format project Go files.
	$(FIND_GO) -exec $(GOFMT) -w {} +

fmt-check: ## Check formatting without modifying source files.
	@set -eu; \
	files="$$($(FIND_GO) -exec $(GOFMT) -l {} +)"; \
	if [ -n "$$files" ]; then \
		printf '%s\n' "$$files"; \
		printf '%s\n' "Run 'make fmt' to format these files." >&2; \
		exit 1; \
	fi

vet: ## Run Go static analysis.
	$(GO) vet $(PACKAGES)

mod-verify: ## Verify downloaded module-cache integrity.
	$(GO) mod verify

lint: ## Run golangci-lint static analysis.
	@command -v $(LINT) >/dev/null 2>&1 || { \
		printf '%s\n' 'golangci-lint not found. Install it with:'; \
		printf '%s\n' '  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)'; \
		exit 1; \
	}
	$(LINT) run

lint-install: ## Install golangci-lint at the pinned version.
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

test-fast: ## Run tests without race detection or coverage.
	$(GO) test -count=1 -timeout=$(TEST_TIMEOUT) $(PACKAGES)

test: ## Run tests with race detection, shuffled order and coverage.
	@mkdir -p $(REPORT_DIR)
	@rm -f $(COVERAGE_FILE) $(REPORT_DIR)/coverage.html
	$(GO) test -race -count=1 -shuffle=$(TEST_SHUFFLE) \
		-timeout=$(TEST_TIMEOUT) -covermode=atomic -coverpkg=./... \
		-coverprofile=$(COVERAGE_FILE) $(PACKAGES)
	$(GO) tool cover -func=$(COVERAGE_FILE)

coverage-html: test ## Generate an HTML coverage report.
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(REPORT_DIR)/coverage.html

fuzz: ## Discover fuzz targets and run each one sequentially.
	@set -eu; \
	packages="$$($(GO) list $(PACKAGES))"; \
	found=0; \
	for pkg in $$packages; do \
		names="$$($(GO) test "$$pkg" -list '^Fuzz')"; \
		targets="$$(printf '%s\n' "$$names" | sed -n '/^Fuzz[[:alnum:]_]*$$/p')"; \
		for target in $$targets; do \
			found=1; \
			printf '\n==> Fuzzing %s: %s\n' "$$pkg" "$$target"; \
			$(GO) test "$$pkg" -run='^$$' -fuzz="^$${target}$$" \
				-fuzztime=$(FUZZ_TIME) -timeout=$(FUZZ_TIMEOUT) \
				-parallel=$(FUZZ_PARALLEL); \
		done; \
	done; \
	if [ "$$found" -eq 0 ]; then \
		printf '%s\n' 'No fuzz targets found in the selected packages.' >&2; \
		exit 1; \
	fi

security: ## Check known vulnerabilities, including test dependencies.
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) -test $(PACKAGES)

check: fmt-check vet mod-verify test ## Run local quality checks.

ci: check lint security fuzz ## Run quality checks, linting, vulnerability scan and fuzzing.

bench: ## Run benchmarks without race or coverage instrumentation.
	$(GO) test -run='^$$' -bench=. -benchmem -count=3 $(PACKAGES)

clean: ## Remove reports; preserve fuzz regression inputs and Go caches.
	rm -f $(COVERAGE_FILE) $(REPORT_DIR)/coverage.html
