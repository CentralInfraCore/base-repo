package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateSymbols(t *testing.T) {
	// The path is relative to the test's working directory, which is the package directory.
	pkgPattern := "./testdata/testpkg"

	// Generate the symbols documentation
	generatedBytes, err := generateSymbols([]string{pkgPattern})
	require.NoError(t, err, "generateSymbols should not return an error")

	// Read the golden file
	goldenFile := filepath.Join("testdata", "golden.md")
	goldenBytes, err := os.ReadFile(goldenFile)
	require.NoError(t, err, "Failed to read golden file %s", goldenFile)

	// Normalize line endings for comparison, just in case
	generated := strings.ReplaceAll(string(generatedBytes), "\r\n", "\n")
	golden := strings.ReplaceAll(string(goldenBytes), "\r\n", "\n")

	// Compare the generated output with the golden file
	require.Equal(t, golden, generated, "Generated symbols do not match the golden file. Run 'go run ./tools/symbolsgen' to update it.")
}
