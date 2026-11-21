// Command canonicalize reads one JSON document from stdin and writes its
// canonical form (sorted object keys, no insignificant whitespace, produced by
// pkg/canonicaljson) to stdout, followed by a newline. It lets shell steps hash
// a document exactly the way the Go services do. A read, parse or write
// failure is printed to stderr and exits with status 1.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"centralrelay/pkg/canonicaljson"
)

// RunFunc is a variable that holds the actual run function.
// It can be reassigned for testing purposes.
var RunFunc = Run

// main runs RunFunc on stdin and stdout and exits with status 1 on error.
func main() {
	if err := RunFunc(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Run reads the whole input, parses it as JSON and writes the canonical JSON
// of the result plus a newline to output. Empty input is an error. Numbers go
// through float64, so integers beyond 2^53 lose precision.
func Run(input io.Reader, output io.Writer) error {
	stdin, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if len(stdin) == 0 {
		return fmt.Errorf("empty input")
	}

	var v any
	if err := json.Unmarshal(stdin, &v); err != nil {
		return fmt.Errorf("failed to unmarshal json: %w", err)
	}

	canonicalBytes, err := canonicaljson.ToJSON(v)
	if err != nil {
		return fmt.Errorf("failed to create canonical json: %w", err)
	}

	_, err = fmt.Fprintln(output, string(canonicalBytes))
	if err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}
