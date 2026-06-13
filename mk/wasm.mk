# ---- WASM module build & test ----
#
# TinyGo target decision (wasm-template-plan.md, sec. 2.1): TinyGo
# `-target wasip1 -scheduler=none` is the only build path proven against the
# relay host (CIC-Relay/core/cabinet/Makefile:28 uses `-target wasi`). If the
# pinned TinyGo version does not define the `wasip1` build tag, fall back to
# `-target wasi` via WASM_TARGET below and adjust module/abi.go's build tag to
# match.

.PHONY: wasm.build wasm.test wasm.buildhash wasm.rebuild-verify

WASM_TARGET ?= wasip1
WASM_OUT    := module/module.wasm

# Build the guest module with TinyGo inside the builder container.
wasm.build: ## Build module/module.wasm with TinyGo (-target $(WASM_TARGET) -scheduler=none)
	@echo "--- Building WASM guest module (TinyGo -target $(WASM_TARGET)) ---"
	docker compose exec -T builder sh -eu -o pipefail -c \
		'cd /app/module && tinygo build -o module.wasm -target $(WASM_TARGET) -scheduler=none .'
	@$(MAKE) wasm.buildhash

# Compute sha256(module.wasm) and write it into project.yaml's metadata.buildHash.
# This is the WASM-specific signed-artifact delta (wasm-template-plan.md, sec. 2.2):
# the schemas release signs the *source-spec* checksum (tools/infra.py), the
# buildHash is filled here in the build-gap between prepare and finalize.
wasm.buildhash: ## Compute sha256(module.wasm) -> project.yaml metadata.buildHash
	@test -f $(WASM_OUT) || { echo "$(WASM_OUT) not found — run 'make wasm.build' first"; exit 1; }
	docker compose exec -T builder sh -eu -o pipefail -c \
		'cd /app && python -m tools.compiler set-build-hash --file $(WASM_OUT) --project project.yaml'

# Reproducible-build check: rebuild the guest module to a scratch path
# (does NOT overwrite the committed module.wasm) and compare its sha256
# against project.yaml's metadata.buildHash. A mismatch means either the
# committed module.wasm is stale (run `make wasm.build`) or the TinyGo
# build is not reproducible in this environment.
wasm.rebuild-verify: ## Rebuild module.wasm to a scratch path and verify sha256 == project.yaml metadata.buildHash
	@echo "--- Verifying reproducible build of module/module.wasm ---"
	docker compose exec -T builder sh -eu -o pipefail -c \
		'cd /app/module && tinygo build -o /tmp/module.wasm.rebuild-verify -target $(WASM_TARGET) -scheduler=none . && \
		REBUILD_HASH=$$(sha256sum /tmp/module.wasm.rebuild-verify | cut -d" " -f1) && \
		rm -f /tmp/module.wasm.rebuild-verify && \
		EXPECTED_HASH=$$(grep -E "^[[:space:]]*buildHash:" /app/project.yaml | sed -E "s/^[[:space:]]*buildHash:[[:space:]]*//") && \
		echo "rebuilt sha256:        $$REBUILD_HASH" && \
		echo "project.yaml buildHash: $$EXPECTED_HASH" && \
		if [ "$$REBUILD_HASH" != "$$EXPECTED_HASH" ]; then \
			echo "FATAL: rebuilt module/module.wasm does not match project.yaml metadata.buildHash" >&2; \
			echo "  rebuilt:  $$REBUILD_HASH" >&2; \
			echo "  expected: $$EXPECTED_HASH" >&2; \
			echo "Run \"make wasm.build\" to refresh module.wasm and metadata.buildHash, then commit both." >&2; \
			exit 1; \
		fi; \
		echo "OK: rebuild matches metadata.buildHash"'

# Host-load smoke test: load module.wasm with wazero (same runtime as
# CIC-Relay/core/cabinet/cicwasm.go), verify the ABI exports and one
# Call("get", ...) round trip.
wasm.test: ## Host-load module.wasm against the relay cabinet ABI (go test)
	@test -f $(WASM_OUT) || { echo "$(WASM_OUT) not found — run 'make wasm.build' first"; exit 1; }
	docker compose exec -T builder sh -eu -o pipefail -c \
		'cd /app/module && GOFLAGS=-mod=mod go test -run TestHostLoad -v .'
