# Initialize infrastructure (MQ, builder)
infra-init:
	@mkdir -p output tmp/{build,cache,gomodcache,bin}
	@sudo chown -R $(shell id -u):$(shell id -g) output tmp
	docker compose up -d

# Default goal
.DEFAULT_GOAL := build

MAKE := make
APP_NAME := cic-relay
VERSION := dev
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_DIR := ./output/$(COMMIT)
LD_FLAGS := -X main.BuildID=$(VERSION)-$(COMMIT) \
            -X main.CommitHash=$(COMMIT) \
            -X main.Timestamp=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Create output directory
prepare:
	@mkdir -p $(BUILD_DIR)
	@sudo chown -R $(shell id -u):$(shell id -g) ./output

# Build the application
build: prepare test coverage quality
	@echo "🔨 Building $(APP_NAME)..."
	docker compose exec builder sh -c 'git config --global safe.directory /git-source && cd /git-source/cmd/relay && go build -ldflags "$(LD_FLAGS)" -o /output/$(COMMIT)/$(APP_NAME)'
	@echo "✅ Build complete at $(BUILD_DIR)/$(APP_NAME)"
	@$(MAKE) mq-publish

# Run dev shell in persistent builder
shell:
	docker compose exec builder sh

# Clean output for this commit
clean:
	rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build output for commit $(COMMIT)"

# Populate Go module cache
cache-populate:
	docker compose run --rm --entrypoint bash mod-cache-loader -c " \
		GOFLAGS=-buildvcs=false GOBIN=/go/bin \
		go mod download && \
		go mod download gopkg.in/yaml.v3 && \
		go install honnef.co/go/tools/cmd/staticcheck@v0.6.1 && \
		go install github.com/gordonklaus/ineffassign@v0.1.0 \
	"
tdd:
	# reflex helyett lehet inotify-tools is; reflex-et itt installáljuk futáskor
	docker compose exec -T builder sh -lc '\
		reflex -r "(\\.go|go\\.mod|go\\.sum)$$" -- sh -c "go test -race -count=1 ./..." \
	'

test:
	docker compose exec builder sh -c 'cd /git-source && go test ./... -v'

coverage:
	docker compose exec builder sh -c 'cd /git-source && go test -cover ./...'

coverage-html:
	docker compose exec builder sh -c 'cd /git-source && mkdir /output/$(COMMIT) -p && go test -coverprofile=/output/$(COMMIT)/coverage.out ./... && go tool cover -html=/output/$(COMMIT)/coverage.out -o /output/$(COMMIT)/coverage.html'

# Code quality checks
quality:
	docker compose exec builder sh -c 'cd /git-source && GOFLAGS=-buildvcs=false  staticcheck ./... &&  GOFLAGS=-buildvcs=false ineffassign ./...'

# Lint suggestions (non-blocking)
lint:
	docker compose exec builder sh -c 'cd /git-source && go vet ./... && staticcheck ./...'

# Publish build result to MQ
mq-publish:
	docker compose exec nats-cli sh -c ' \
		FILE="/output/$(COMMIT)/$(APP_NAME)" && \
		if [ -f $$FILE ]; then \
			nats pub build.result.$(COMMIT) "✅ Build ready: $$FILE"; \
		else \
			nats pub build.result.$(COMMIT) "❌ Build failed or missing output."; \
		fi '

# Stop and clean up infrastructure
infra-down:
	docker compose down

# Build crt_parser tool
build-crt-parser: prepare
	@echo "🔨 Building crt_parser..."
	docker compose exec builder sh -c 'cd /git-source/tools/certutils && go build -ldflags "$(LD_FLAGS)" -o /output/$(COMMIT)/crt_parser crt_parser.go'
	@echo "✅ crt_parser built at $(BUILD_DIR)/crt_parser"


# Golden verification (LLM-ready overlay)
.PHONY: verify
verify:
	@scripts/ai_verify.sh
	$(MAKE) quality
	$(MAKE) coverage-check-pkgs

build-canonicalize: prepare
	@echo "🔨 Building canonicalize..."
	docker compose exec builder sh -c 'cd /git-source/tools/canonicalize && mkdir -p /output/$(COMMIT) && go build -trimpath -ldflags "$(LD_FLAGS)" -o /output/$(COMMIT)/canonicalize .'
	@echo "✅ canonicalize built at $(BUILD_DIR)/canonicalize"

COVERMIN ?= 40.0
coverage-gate:
	docker compose exec -T builder sh -lc '\
		go test -race -covermode=atomic -coverprofile=/output/$(COMMIT)/cover.out ./... && \
		go tool cover -func=/output/$(COMMIT)/cover.out | tail -n1 | \
		awk -v min=$(COVERMIN) '\''{gsub("%","",$3); if ($$3+0 < min) {printf "Coverage %.1f%% < min %.1f%%\n", $$3, min; exit 1}}'\'' \
	'

# --- Coverage küszöbök (docker compose exec mintára) ---
# Használat:
#   make coverage-check            # globális min 85%
#   make COVER_MIN=90 coverage-check
#   make coverage-check-pkgs       # per-csomag minimumok

coverage-check:
	docker compose exec builder sh -c 'cd /git-source && \
		go test -coverprofile=/tmp/coverage.out ./... >/dev/null && \
		pct=$$(go tool cover -func=/tmp/coverage.out | awk '\''END{print $$3}'\'' | tr -d "%"); \
		min=$${COVER_MIN:-85}; \
		echo "Total coverage: $$pct% (min $$min%)"; \
		awk -v p=$$pct -v m=$$min '\''BEGIN{exit (p+0 < m+0)}'\'' || { echo "Coverage below threshold"; exit 1; }'

# Per-csomag küszöbök — igazítsd igény szerint:
# cabinet: 95, canonicalize: 85, certutils: 70, cmd/relay: 80, egyebek: 75
coverage-check-pkgs:
	docker compose exec builder sh -c 'cd /git-source && \
		set -e; \
		for p in $$(go list ./... | grep -v /vendor/); do \
		  go test $$p -coverprofile=/tmp/cover.out >/dev/null; \
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

.PHONY: verify-auto verify-debug

# Automatikus build → bináris felderítés → verify
verify-auto:
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
verify-debug:
	@set -x; ls -l output/*/canonicalize || true; env | grep -E 'BINARY|MAKE|PATH' || true

# --- MANIFEST ellenőrzés / frissítés ---
.PHONY: manifest-verify manifest-update

# Ellenőrzés (sha256sum -c)
manifest-verify:
	docker compose exec builder sh -c 'cd /git-source && \
		test -f MANIFEST.sha256 && sha256sum -c MANIFEST.sha256'

# Frissítés (újra-generálás) – kizárjuk .git és output mappákat
manifest-update:
	docker compose exec builder sh -c 'cd /git-source && \
		git ls-files -z  \
		| xargs -0 sha256sum' | grep -v "MANIFEST.sha256" | LC_ALL=C sort > MANIFEST.sha256 ; \
	echo "MANIFEST.sha256 updated"

.PHONY: verify-full
verify-full:
	$(MAKE) quality
	$(MAKE) coverage-check-pkgs
	$(MAKE) manifest-verify
