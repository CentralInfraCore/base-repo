package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"centralrelay/pkg/canonicaljson"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
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

	fmt.Println(string(canonicalBytes))
	return nil
}
