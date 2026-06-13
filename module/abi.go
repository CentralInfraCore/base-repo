//go:build wasip1

// Package main is the WASM guest entrypoint. abi.go is the iSDK boilerplate —
// it implements the host-required ABI (allocate/deallocate/Call) and dispatches
// op-strings to the domain handlers in handlers.go. DO NOT EDIT for normal modules.
package main

// #include <stdlib.h>
import "C"

import (
	"unsafe"
)

func main() {}

//export allocate
func allocate(size uint32) uintptr {
	return uintptr(C.malloc(C.size_t(size)))
}

//export deallocate
func deallocate(ptr uintptr, size uint32) {
	C.free(unsafe.Pointer(ptr))
}

//export Call
func Call(opPtr, opLen, authPtr, authLen, dataPtr, dataLen uint32) uint64 {
	op := readString(opPtr, opLen)
	auth := readBytes(authPtr, authLen)
	data := readBytes(dataPtr, dataLen)

	var out []byte
	var derr error
	switch op { // op-dispatch — host: cicwasm.go:267-281
	case "init":
		out, derr = Init(auth, data)
	case "process":
		out, derr = Process(auth, data)
	case "get":
		out, derr = Get(auth, data)
	case "notify":
		out, derr = Notify(auth, data)
	default:
		return pack(marshalErr(CodeInput, "unknown op: "+op))
	}
	if derr != nil {
		if ge, ok := derr.(*GuestError); ok {
			return pack(marshalErr(ge.Code, ge.Message))
		}
		return pack(marshalErr(CodeRuntime, derr.Error()))
	}
	return pack(marshalData(out))
}

// pack mirrors the host contract: (size << 32) | pointer (cicwasm.go:325).
func pack(b []byte) uint64 {
	if len(b) == 0 {
		return 0 // host treats packed 0 as null/empty (cicwasm.go:337-339)
	}
	ptr := allocate(uint32(len(b)))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(b)), b)
	return (uint64(uint32(len(b))) << 32) | uint64(ptr)
}

// readString reads a host-written UTF-8 string from guest memory at ptr/len.
func readString(ptr, length uint32) string {
	return string(readBytes(ptr, length))
}

// readBytes reads a host-written byte slice from guest memory at ptr/len.
// The host writes via Memory().Write before calling Call (cicwasm.go:371-383)
// and deallocates the region afterwards — the guest must not retain the slice.
func readBytes(ptr, length uint32) []byte {
	if length == 0 {
		return nil
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
	out := make([]byte, length)
	copy(out, src)
	return out
}
