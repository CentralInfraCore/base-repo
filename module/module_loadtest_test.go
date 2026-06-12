//go:build !wasip1

package main

// module_loadtest_test.go is a host-load smoke test, mirroring the relay
// cabinet ABI checks (CIC-Relay/core/cabinet/cicwasm.go):
//   - wazero + wasi_snapshot_preview1 instantiation, WithStartFunctions()
//     (cicwasm.go:66, :178) — these are libraries, not applications.
//   - the host requires three exported functions: Call, allocate, deallocate
//     (cicwasm.go:243-247).
//   - result packing is (size << 32) | pointer, payload is {data,error}
//     (cicwasm.go:325, :346).
//
// It does not import the relay's internal cabinet package — a template
// repository should not depend on CIC-Relay as a Go module. Instead it
// re-implements the minimal host-load contract directly against wazero,
// the same runtime cicwasm.go uses.

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// wasmPath is where `make wasm.build` (mk/wasm.mk) emits the TinyGo artifact.
const wasmPath = "module.wasm"

func TestHostLoad(t *testing.T) {
	wasmBytes, err := os.ReadFile(wasmPath)
	if os.IsNotExist(err) {
		t.Skipf("module.wasm not built — run `make wasm.build` first (path: %s)", wasmPath)
	}
	if err != nil {
		t.Fatalf("failed to read %s: %v", wasmPath, err)
	}

	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		t.Fatalf("failed to instantiate wasi: %v", err)
	}

	compiled, err := runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		t.Fatalf("failed to compile module: %v", err)
	}

	// Don't call _start — guest modules are libraries, not applications
	// (cicwasm.go:177-178).
	moduleConfig := wazero.NewModuleConfig().WithName("module_loadtest").WithStartFunctions()
	instance, err := runtime.InstantiateModule(ctx, compiled, moduleConfig)
	if err != nil {
		t.Fatalf("failed to instantiate module: %v", err)
	}
	defer instance.Close(ctx)

	callFn := instance.ExportedFunction("Call")
	allocateFn := instance.ExportedFunction("allocate")
	deallocateFn := instance.ExportedFunction("deallocate")
	if callFn == nil || allocateFn == nil || deallocateFn == nil {
		t.Fatalf("module does not export required ABI functions (Call/allocate/deallocate) — cicwasm.go:243-247")
	}

	// Round-trip Call("get", "{}", "{}") and verify the {data,error} envelope.
	op := "get"
	auth := "{}"
	data := "{}"

	opPtr, opLen := writeString(t, ctx, instance, allocateFn, op)
	defer deallocateFn.Call(ctx, uint64(opPtr), uint64(opLen))
	authPtr, authLen := writeString(t, ctx, instance, allocateFn, auth)
	defer deallocateFn.Call(ctx, uint64(authPtr), uint64(authLen))
	dataPtr, dataLen := writeString(t, ctx, instance, allocateFn, data)
	defer deallocateFn.Call(ctx, uint64(dataPtr), uint64(dataLen))

	results, err := callFn.Call(ctx, uint64(opPtr), uint64(opLen), uint64(authPtr), uint64(authLen), uint64(dataPtr), uint64(dataLen))
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	packed := results[0]
	resultLen := uint32(packed >> 32)
	resultPtr := uint32(packed)

	if packed == 0 {
		t.Fatal("Call returned packed 0 (null/empty) for op=get")
	}
	defer deallocateFn.Call(ctx, uint64(resultPtr), uint64(resultLen))

	resultBytes, ok := instance.Memory().Read(resultPtr, resultLen)
	if !ok {
		t.Fatalf("failed to read result from guest memory at ptr=%d, len=%d", resultPtr, resultLen)
	}

	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(resultBytes, &envelope); err != nil {
		t.Fatalf("failed to unmarshal {data,error} envelope: %v (raw: %s)", err, resultBytes)
	}

	t.Logf("Call(\"get\") -> data=%s error=%s", envelope.Data, envelope.Error)
}

func writeString(t *testing.T, ctx context.Context, instance api.Module, allocateFn api.Function, s string) (uint32, uint32) {
	data := []byte(s)
	results, err := allocateFn.Call(ctx, uint64(len(data)))
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}
	ptr := uint32(results[0])
	if !instance.Memory().Write(ptr, data) {
		t.Fatalf("Memory.Write failed for %q", s)
	}
	return ptr, uint32(len(data))
}
