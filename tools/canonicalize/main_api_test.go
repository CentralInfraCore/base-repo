package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain_Smoke_OK(t *testing.T) {
	// bemenet -> ideiglenes fájl, mert os.Stdin egy *os.File
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.json")
	input := `{"b":2,"a":1,"arr":[3,"x"]}`
	if err := os.WriteFile(inPath, []byte(input), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	f, err := os.Open(inPath)
	if err != nil {
		t.Fatalf("open stdin file: %v", err)
	}
	os.Stdin = f
	defer f.Close()

	r, w, _ := os.Pipe()
	os.Stdout = w

	main()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	got := strings.TrimSpace(buf.String())
	want := `{"a":1,"arr":[3,"x"],"b":2}`

	if got != want {
		t.Fatalf("canonical output mismatch\nwant=%s\ngot =%s", want, got)
	}
}
