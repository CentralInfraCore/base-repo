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
build: prepare
	@echo "🔨 Building $(APP_NAME)..."
	docker compose exec builder go build -o /output/$(COMMIT)/$(APP_NAME) /git-source/main.go
	@echo "✅ Build complete at $(BUILD_DIR)/$(APP_NAME)"

# Run dev shell in persistent builder
shell:
	docker compose exec builder sh

# Clean output for this commit
clean:
	rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build output for commit $(COMMIT)"

# Populate Go module cache
cache-populate:
	docker compose run --rm mod-cache-loader go mod download

test:
	docker compose exec builder sh -c 'cd /git-source && go test ./... -v'

coverage:
	docker compose exec builder sh -c 'cd /git-source && go test -cover ./...'

coverage-html:
	docker compose exec builder sh -c 'cd /git-source && go test -coverprofile=/output/$(COMMIT)/coverage.out ./... && go tool cover -html=/output/$(COMMIT)/coverage.out -o /output/$(COMMIT)/coverage.html'
