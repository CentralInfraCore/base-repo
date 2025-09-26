package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"centralrelay/pkg/canonicaljson"
)

// mockReader is a reader that always returns an error on read.
type mockReader struct{}

func (r *mockReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

// failingWriter is a writer that always returns an error on write.
type failingWriter struct{}

func (fw *failingWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

func TestRun_Success(t *testing.T) {
	input := strings.NewReader(`{"c": 3, "a": 1, "b": 2}`)
	var output bytes.Buffer
	expectedOutput := `{"a":1,"b":2,"c":3}`

	err := Run(input, &output)

	assert.NoError(t, err)
	assert.Equal(t, expectedOutput, strings.TrimSpace(output.String()))
}

func TestRun_ReadError(t *testing.T) {
	input := &mockReader{}
	var output bytes.Buffer

	err := Run(input, &output)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read input")
}

func TestRun_EmptyInput(t *testing.T) {
	input := strings.NewReader("")
	var output bytes.Buffer

	err := Run(input, &output)

	assert.Error(t, err)
	assert.Equal(t, "empty input", err.Error())
}

func TestRun_UnmarshalError(t *testing.T) {
	input := strings.NewReader(`{"key": "value"`) // Malformed JSON
	var output bytes.Buffer

	err := Run(input, &output)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal json")
}

func TestRun_WriteError(t *testing.T) {
	input := strings.NewReader(`{"a": 1}`)
	output := &failingWriter{}

	err := Run(input, output)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write output")
}

func TestRun_CanonicalJsonError(t *testing.T) {
	// Mock canonicaljson.ToJSON to return an error
	canonicaljson.SetToJSONMock(func(v any) ([]byte, error) {
		return nil, errors.New("canonicaljson error")
	})
	defer canonicaljson.SetToJSONMock(nil) // Restore original after test

	input := strings.NewReader(`{"a": 1}`)
	var output bytes.Buffer

	err := Run(input, &output)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create canonical json")
}
