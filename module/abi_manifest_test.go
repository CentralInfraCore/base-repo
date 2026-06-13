//go:build !wasip1

package main

// abi_manifest_test.go checks that the compiled module/module.wasm exports
// every function declared in project.yaml's abi.exports list (KB c689,
// docs/contracts/wasm-abi.md). A mismatch fails `make wasm.test` — the ABI
// manifest is the source of truth for what the relay host
// (CIC-Relay/core/cabinet/cicwasm.go:243-247) requires from a guest module.
//
// project.yaml is read with a small line-based scanner rather than a YAML
// library: this template module intentionally has no YAML dependency
// (module/go.mod only requires wazero), and the abi.exports list is a
// simple, hand-curated block.

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// projectYAMLPath is project.yaml relative to module/ (repo root's project.yaml).
const projectYAMLPath = "../project.yaml"

// readABIExports extracts the abi.exports list from project.yaml.
func readABIExports(t *testing.T, path string) []string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer f.Close()

	var exports []string
	inABI := false
	inExports := false
	exportsIndent := -1

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 {
			inABI = trimmed == "abi:"
			inExports = false
			continue
		}
		if !inABI {
			continue
		}

		if inExports {
			if strings.HasPrefix(trimmed, "- ") && indent > exportsIndent {
				exports = append(exports, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
				continue
			}
			inExports = false
		}

		if trimmed == "exports:" {
			inExports = true
			exportsIndent = indent
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if len(exports) == 0 {
		t.Fatalf("no abi.exports found in %s", path)
	}
	return exports
}

// TestHostLoadABIManifestExportsPresent verifies that every function declared in
// project.yaml's abi.exports list is actually exported by module.wasm.
func TestHostLoadABIManifestExportsPresent(t *testing.T) {
	_, instance, _, _, _ := loadModule(t)

	wantExports := readABIExports(t, projectYAMLPath)
	for _, name := range wantExports {
		if instance.ExportedFunction(name) == nil {
			t.Errorf("project.yaml abi.exports declares %q, but module.wasm does not export it", name)
		}
	}
}
