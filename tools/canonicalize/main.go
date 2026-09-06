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

func main() {
	if err := RunFunc(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

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
