
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --no-builtin-rules --warn-undefined-variables

# Default goal
.DEFAULT_GOAL := build

MAKE := make
APP_NAME ?= cic-relay
VERSION  ?= dev
COMMIT   ?= $(shell git rev-parse --short HEAD)
BUILD_DIR ?= ./output/$(COMMIT)

# ---- Coverage outputs ----
COVERAGE_FILE ?= /output/$(COMMIT)/coverage.out
COVERAGE_HTML ?= /output/$(COMMIT)/coverage.html

# ---- Build flags ----
LD_FLAGS ?= -X main.BuildID=$(VERSION)-$(COMMIT) \
            -X main.CommitHash=$(COMMIT) \
            -X main.Timestamp=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

GOFLAGS  ?= -mod=readonly -trimpath
GCFLAGS  ?= all=-dwarf=false
LDFLAGS  ?= $(LD_FLAGS) -s -w

# Kapcsolható race detektor: dev/CI ON, release OFF (RACE=0)
RACE ?= 1
ifeq ($(RACE),1)
  GO_RACE := -race
else
  GO_RACE :=
endif
define GO_EXEC
	docker compose exec -T builder sh -eu -o pipefail -c 'cd /git-source && $(1)'
endef
define GO_FIXER
	docker compose exec -T fixer sh -eu -o pipefail -c 'cd /git-source && $(1)'
endef
# Run dev shell in persistent builder
shell:
	docker compose exec builder sh

# Clean output for this commit
clean:
	rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build output for commit $(COMMIT)"

# ---- Help ----
## Show available make targets
help: ## Show available make targets
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---- Infra / prepare ----
infra-init: ## Initialize dockerized infra and dirs
	@mkdir -p output tmp/{build,cache,gomodcache,bin}
	@{ command -v sudo >/dev/null 2>&1 && sudo chown -R $(shell id -u):$(shell id -g) ./output; } || true
	docker compose up -d

prepare: infra-init ## Prepare local/dev environment
	@mkdir -p $(BUILD_DIR)
	@sudo chown -R $(shell id -u):$(shell id -g) ./output
# ---- Quality gate ----
fmt: ## Apply gofmt -s (and goimports if available)
	$(call GO_FIXER, git config --global --add safe.directory /git-source && \
		git ls-files -z -- "*.go" | xargs -0 gofmt -s -w ; \
		if command -v goimports >/dev/null 2>&1; then \
			git ls-files -z -- "*.go" | xargs -0 goimports -w ; \
		fi )

fmt-check: ## Fail if formatting differs
	$(call GO_EXEC, M="$$(git ls-files -z -- "*.go" | xargs -0 gofmt -s -l)"; \
		test -z "$$M" || { printf "%s\n" "$$M"; echo "Code not formatted. Run make fmt"; exit 1; })

lint: ## Run static linters (staticcheck, ineffassign)
	$(call GO_EXEC, \
		set -euo pipefail; \
		PKGS="$$(go list ./... | grep -v /vendor/)"; \
		if [ -z "$$PKGS" ]; then \
			echo "No Go packages to lint."; \
			exit 0; \
		fi; \
		echo "Staticcheck on: $$PKGS"; \
		GO111MODULE=on GOFLAGS="$(GOFLAGS)" staticcheck $$PKGS \
	)

vet: ## Run go vet
	$(call GO_EXEC, \
		set -euo pipefail; \
		PKGS="$$(go list ./... | grep -v /vendor/)"; \
		if [ -z "$$PKGS" ]; then \
			echo "No Go packages to lint."; \
			exit 0; \
		fi; \
		echo "Vet on: $$PKGS"; \
		GO111MODULE=on GOFLAGS="$(GOFLAGS)" go vet $$PKGS \
	)

quality: fmt-check lint vet vuln ## Quality gate: all checks must pass

# ---- Tests & coverage ----
test: ## Run unit tests (verbose, race)
	$(call GO_EXEC, \
		set -euo pipefail; \
		PKGS="$$(go list ./... | grep -v /vendor/)"; \
		if [ -z "$$PKGS" ]; then \
			echo "No Go packages to lint."; \
			exit 0; \
		fi; \
		echo "Test on: $$PKGS"; \
		GO111MODULE=on GOFLAGS="$(GOFLAGS)" go test $(GO_RACE) -v $$PKGS \
	)

coverage: coverage-profile coverage-html ## Run tests with coverage (profile + HTML)
	@echo "Coverage HTML: $(COVERAGE_HTML)"

coverage-profile: ## Run tests with coverage (profile)
		$(call GO_EXEC, \
		set -euo pipefail; \
		PKGS="$$(go list ./... | grep -v /vendor/)"; \
		if [ -z "$$PKGS" ]; then \
			echo "No Go packages to lint."; \
			exit 0; \
		fi; \
		echo "Staticcheck on: $$PKGS"; \
		mkdir -p $(BUILD_DIR) \
		&& GOFLAGS="$(GOFLAGS)" go test $(GO_RACE) -covermode=atomic -coverprofile=$(COVERAGE_FILE) $$PKGS \
	)


coverage-html: ## Run tests with coverage (HTML)
	$(call GO_EXEC, mkdir -p $(BUILD_DIR) \
		&& go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML))

COVERAGE_MIN ?= 85

coverage-threshold: coverage ## Fail if coverage < $(COVERAGE_MIN)%
	docker compose exec -T builder sh -c 'cd /git-source && \
		go tool cover -func=$(COVERAGE_FILE) | \
		awk -v MIN=$(COVERAGE_MIN) '"'"'/^total:/ { gsub("%","",$$3); v=$$3+0 } END { if (v < MIN) { printf "Coverage below %d%% (got %.1f%%)\n", MIN, v; exit 1 } else { printf "Coverage OK: %.1f%% >= %d%%\n", v, MIN } }'"'"''

# Per-csomag küszöbök — igazítsd igény szerint:
# cabinet: 95, canonicalize: 85, certutils: 70, cmd/relay: 80, egyebek: 75
coverage-check-pkgs: ## Fail if packages coverage < $(COVERAGE_MIN)%
	docker compose exec builder sh -c 'cd /git-source && \
		set -e; \
		for p in $$(go list ./... | grep -v /vendor/); do \
		  GO111MODULE=on GOFLAGS="$(GOFLAGS)" go test $$p -coverprofile=/tmp/cover.out >/dev/null; \
		  pc=$$(go tool cover -func=/tmp/cover.out | awk '\''END{print $$3}'\'' | tr -d "%"); \
		  case "$$p" in \
		    *"/core/cabinet") min=95 ;; \
		    *"/tools/canonicalize") min=85 ;; \
		    *"/tools/certutils") min=70 ;; \
		    *"/cmd/relay") min=80 ;; \
		    *) min=75 ;; \
		  esac; \
		  echo "$$p: $$pc% (min $$min%)"; \
		  awk -v p=$$pc -v m=$$min '\''BEGIN{exit (p+0 < m+0)}'\''; \
		done'

vuln: ## Run Go vulnerability scan (govulncheck)
	$(call GO_EXEC, \
		set -euo pipefail; \
		PKGS="$$(go list ./... | grep -v /vendor/)"; \
		if [ -z "$$PKGS" ]; then \
			echo "No Go packages to lint."; \
			exit 0; \
		fi; \
		echo "govulncheck on: $$PKGS"; \
		GO111MODULE=on GOFLAGS="$(GOFLAGS)" govulncheck $$PKGS \
	)


# Stop and clean up infrastructure
infra-down: ## Stop and clean infra
	docker compose down

# Build crt_parser tool
build-crt-parser: prepare ## build-crt-parser
	@echo "🔨 Building crt_parser..."
	docker compose exec builder sh -c 'cd /git-source/tools/certutils && go build -ldflags "$(LD_FLAGS)" -o /output/$(COMMIT)/crt_parser crt_parser.go'
	@echo "✅ crt_parser built at $(BUILD_DIR)/crt_parser"


# Golden verification (LLM-ready overlay)

build-canonicalize: prepare ## build-canonicalize
	@echo "🔨 Building canonicalize..."
	docker compose exec builder sh -c 'cd /git-source/tools/canonicalize && mkdir -p /output/$(COMMIT) && go build -trimpath -ldflags "$(LD_FLAGS)" -o /output/$(COMMIT)/canonicalize .'
	@echo "✅ canonicalize built at $(BUILD_DIR)/canonicalize"


# Automatikus build → bináris felderítés → verify
verify-auto: ## verify-auto
	@set -e; \
	BIN=$$(ls -1t output/*/canonicalize 2>/dev/null | head -n1 || true); \
	if [ -z "$$BIN" ]; then \
	  echo "→ Building canonicalize..."; \
	  $(MAKE) build-canonicalize; \
	  BIN=$$(ls -1t output/*/canonicalize | head -n1); \
	fi; \
	echo "→ Using BINARY=$$BIN"; \
	$(MAKE) verify BINARY="$$BIN"

# Hibakereső target – megmutatja, mit lát
verify-debug: ## verify-debug
	@set -x; ls -l output/*/canonicalize || true; env | grep -E 'BINARY|MAKE|PATH' || true

# --- MANIFEST ellenőrzés / frissítés ---

# Ellenőrzés (sha256sum -c)
manifest-verify: ##manifest-verify
	docker compose exec builder sh -c 'cd /git-source && \
		test -f MANIFEST.sha256 && sha256sum -c MANIFEST.sha256'

# Frissítés (újra-generálás) – kizárjuk .git és output mappákat
manifest-update: ##manifest-update
	docker compose exec builder sh -c 'cd /git-source && \
		git ls-files -z  \
		| xargs -0 sha256sum' | grep -v "MANIFEST.sha256" | LC_ALL=C sort > MANIFEST.sha256 ; \
	echo "MANIFEST.sha256 updated"

verify-full: ##verify-full
	$(MAKE) quality
	$(MAKE) coverage-check-pkgs
	$(MAKE) manifest-verify
# Coverage report (profile)
COVERAGE_FILE ?= /output/$(COMMIT)/coverage.out
# Coverage HTML report
COVERAGE_HTML ?= /output/$(COMMIT)/coverage.html



# Build the application
build: prepare quality test coverage coverage-check-pkgs ## Build binary with quality gates
	@echo "🔨 Building $(APP_NAME)..."
	docker compose exec builder sh -c ' cd /git-source/cmd/relay \
		&& go build $(GO_RACE) $(GOFLAGS) -gcflags="$(GCFLAGS)" -ldflags "$(LDFLAGS)" \
		 -o /output/$(COMMIT)/$(APP_NAME)'
	@echo "✅ Build complete at $(BUILD_DIR)/$(APP_NAME)"
	@$(MAKE) manifest-src
	@if [ -z "$(NO_PUBLISH)" ]; then $(MAKE) mq-publish; fi

# ---- Artefakt és forrás MANIFEST-ek ----
MANIFEST := /output/$(COMMIT)/MANIFEST.sha256

manifest-src: ## Snapshot of tracked sources (audit)
	$(call GO_FIXER, git ls-files -z | xargs -0 sha256sum > /output/$(COMMIT)/SOURCE.MANIFEST.sha256)
	@echo "Source manifest: /output/$(COMMIT)/SOURCE.MANIFEST.sha256"

# ---- Optional: TDD loop ----
tdd: ## TDD loop with reflex
	$(call GO_EXEC, \
		command -v reflex >/dev/null 2>&1 || go install github.com/cespare/reflex@latest; \
		reflex -r "(\.go|go\.mod|go\.sum)$$" -- sh -c "GOFLAGS=-mod=readonly\ -trimpath go test -race -count=1 ./..." \
	)

cache-populate: ##cache-populate
	docker compose run --rm --entrypoint bash mod-cache-loader -c " \
		GOFLAGS=-buildvcs=false GOBIN=/go/bin \
		&& go mod download \
		&& go mod download gopkg.in/yaml.v3 \
		&& echo staticcheck && go install honnef.co/go/tools/cmd/staticcheck@v0.6.1 \
		&& echo ineffassign && go install github.com/gordonklaus/ineffassign@v0.1.0 \
		&& echo reflex && go install github.com/cespare/reflex@v0.3.1 \
		&& echo govulncheck && go install golang.org/x/vuln/cmd/govulncheck@v1.1.4 \
	"

# ---- Optional: MQ publish (guarded by NO_PUBLISH) ----
mq-publish: ## Example publish step (override as needed)
	docker compose exec nats-cli sh -c ' \
		FILE="/output/$(COMMIT)/$(APP_NAME)" && \
		if [ -f $$FILE ]; then \
			nats pub build.result.$(COMMIT) "✅ Build ready: $$FILE"; \
		else \
				nats pub build.result.$(COMMIT) "❌ Build failed or missing output."; \
		fi '

# ---- Phony ----
.PHONY: help infra-init prepare fmt fmt-check lint vet quality \
        test coverage coverage-threshold build verify manifest-src \
        tdd cache-populate mq-publish verify-auto verify-debug \
	manifest-verify manifest-update verify-full clean shell
