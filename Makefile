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

# Create output directory
prepare:
	@mkdir -p $(BUILD_DIR)
	@sudo chown -R $(shell id -u):$(shell id -g) ./output

# Build the application
build: prepare test coverage quality
	@echo "🔨 Building $(APP_NAME)..."
	docker compose exec builder go build -o /output/$(COMMIT)/$(APP_NAME) /git-source/main.go
	@echo "✅ Build complete at $(BUILD_DIR)/$(APP_NAME)"
	@$(MAKE) mq-publish		FILE="/output/$(COMMIT)/$(APP_NAME)" && \
		if [ -f $$FILE ]; then \
			nats pub build.result.$(COMMIT) "✅ Build ready: $$FILE"; \
		else \
			nats pub build.result.$(COMMIT) "❌ Build failed or missing output."; \
		fi '
"✅ Build complete at $(BUILD_DIR)/$(APP_NAME)""✅ Build complete at $(BUILD_DIR)/$(APP_NAME)"

# Run dev shell in persistent builder
shell:
	docker compose exec builder sh

# Clean output for this commit
clean:
	rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build output for commit $(COMMIT)"

# Populate Go module cache
cache-populate:
	docker compose run --rm --entrypoint sh mod-cache-loader -c '
		go mod download && \
		go install honnef.co/go/tools/cmd/staticcheck@v0.4.6 && \
		go install github.com/gordonklaus/ineffassign@v0.1.0
	'

test:
	docker compose exec builder sh -c 'cd /git-source && go test ./... -v'

coverage:
	docker compose exec builder sh -c 'cd /git-source && go test -cover ./...'

coverage-html:
	docker compose exec builder sh -c 'cd /git-source && go test -coverprofile=/output/$(COMMIT)/coverage.out ./... && go tool cover -html=/output/$(COMMIT)/coverage.out -o /output/$(COMMIT)/coverage.html'

# Code quality checks
quality:
	docker compose exec builder sh -c 'cd /git-source && staticcheck ./... && ineffassign .'

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

