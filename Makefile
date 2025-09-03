# Initialize infrastructure (MQ, builder)
infra-init:
	@mkdir -p output tmp/{build,cache,gomodcache,bin}
	@sudo chown -R $(shell id -u):$(shell id -g) output tmp
	docker compose up -d

# Default goal
.DEFAULT_GOAL := build

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

build-canonicalize: prepare
	@echo "🔨 Building canonicalize..."
	docker compose exec builder sh -c 'cd /git-source/tools/canonicalize && mkdir -p /output/$(COMMIT) && go build -trimpath -ldflags "$(LD_FLAGS)" -o /output/$(COMMIT)/canonicalize .'
	@echo "✅ canonicalize built at $(BUILD_DIR)/canonicalize"
