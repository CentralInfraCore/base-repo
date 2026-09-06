package canonicaljson

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingWriter is a mock io.Writer that fails on demand.
type failingWriter struct {
	failOn int // Fail on the Nth write call
	calls  int
}

func (fw *failingWriter) Write(p []byte) (n int, err error) {
	fw.calls++
	if fw.calls == fw.failOn {
		return 0, errors.New("writer failed")
	}
	return len(p), nil
}

func TestToJSON_DataTypes(t *testing.T) {
	testCases := []struct {
		name     string
		input    any
		expected string
		wantErr  bool
	}{
		{
			name:     "nil value",
			input:    nil,
			expected: "null",
		},
		{
			name:     "boolean true",
			input:    true,
			expected: "true",
		},
		{
			name:     "boolean false",
			input:    false,
			expected: "false",
		},
		{
			name:     "float64",
			input:    123.456,
			expected: "123.456",
		},
		{
			name:     "float64 zero",
			input:    0.0,
			expected: "0",
		},
		{
			name:    "float64 NaN",
			input:   math.NaN(),
			wantErr: true, // json.Marshal fails on NaN
		},
		{
			name:     "string",
			input:    "hello world",
			expected: `"hello world"`,
		},
		{
			name:     "empty slice",
			input:    []any{},
			expected: "[]",
		},
		{
			name:     "slice of primitives",
			input:    []any{1.0, "two", true, nil},
			expected: `[1,"two",true,null]`,
		},
		{
			name:     "empty map",
			input:    map[string]any{},
			expected: "{}",
		},
		{
			name:     "simple map",
			input:    map[string]any{"c": 3.0, "a": 1.0, "b": 2.0},
			expected: `{"a":1,"b":2,"c":3}`,
		},
		{
			name: "nested structure",
			input: map[string]any{
				"zulu": "last",
				"alpha": []any{
					"one",
					map[string]any{
						"gamma": true,
						"beta":  false,
					},
				},
				"x-ray": 123,
			},
			expected: `{"alpha":["one",{"beta":false,"gamma":true}],"x-ray":123,"zulu":"last"}`,
		},
		{
			name:     "default type int",
			input:    42, // This will fall through to the default json.Marshal
			expected: "42",
		},
		{
			name: "default type struct",
			input: struct {
				Name string `json:"name"`
				Age  int    `json:"age"`
			}{Name: "John", Age: 30},
			expected: `{"age":30,"name":"John"}`,
		},
		{
			name:    "unsupported type",
			input:   make(chan int),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ToJSON(tc.input)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(result))
		})
	}
}

func TestToJSON_ErrorCases(t *testing.T) {
	t.Run("writeCanonicalJSON write error", func(t *testing.T) {
		buf := failingWriter{failOn: 1}
		err := writeCanonicalJSON(&buf, map[string]any{"a": 1})
		assert.Error(t, err)
	})

	t.Run("writeJSONString marshal error", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeJSONString(&buf, math.Inf(1))
		assert.Error(t, err)
		assert.Equal(t, "", buf.String()) // Verify buffer is empty
	})

	t.Run("writeJSONString write error", func(t *testing.T) {
		buf := failingWriter{failOn: 1}
		err := writeJSONString(&buf, "test")
		assert.Error(t, err)
	})

	t.Run("writeJSONArray", func(t *testing.T) {
		arr := []any{"a", "b"}
		t.Run("fail on open bracket", func(t *testing.T) {
			buf := failingWriter{failOn: 1}
			err := writeJSONArray(&buf, arr)
			assert.Error(t, err)
		})
		t.Run("fail on comma", func(t *testing.T) {
			buf := failingWriter{failOn: 2}
			err := writeJSONArray(&buf, arr)
			assert.Error(t, err)
		})
		t.Run("fail on item write", func(t *testing.T) {
			arrWithErr := []any{math.NaN()}
			var buf bytes.Buffer
			err := writeJSONArray(&buf, arrWithErr)
			assert.Error(t, err)
			assert.Equal(t, "[", buf.String()) // Verify partial write
		})
		t.Run("fail on close bracket", func(t *testing.T) {
			buf := failingWriter{failOn: 3}
			err := writeJSONArray(&buf, arr)
			assert.Error(t, err)
		})
	})

	t.Run("writeJSONMap", func(t *testing.T) {
		m := map[string]any{"a": 1, "b": 2}
		t.Run("fail on open brace", func(t *testing.T) {
			buf := failingWriter{failOn: 1}
			err := writeJSONMap(&buf, m)
			assert.Error(t, err)
		})
		t.Run("fail on comma", func(t *testing.T) {
			buf := failingWriter{failOn: 2}
			err := writeJSONMap(&buf, m)
			assert.Error(t, err)
		})
		t.Run("fail on key write error", func(t *testing.T) {
			buf := failingWriter{failOn: 2} // Fails on writing the first key
			err := writeJSONMap(&buf, map[string]any{"a": 1})
			assert.Error(t, err)
		})
		t.Run("fail on colon", func(t *testing.T) {
			buf := failingWriter{failOn: 3}
			err := writeJSONMap(&buf, m)
			assert.Error(t, err)
		})
		t.Run("fail on value write", func(t *testing.T) {
			mErrVal := map[string]any{"a": math.NaN()}
			var buf bytes.Buffer
			err := writeJSONMap(&buf, mErrVal)
			assert.Error(t, err)
			assert.Equal(t, "{\"a\":", buf.String()) // Verify partial write
		})
		t.Run("fail on close brace", func(t *testing.T) {
			buf := failingWriter{failOn: 4} // {,"a":1,"b":2} -> fails on }
			err := writeJSONMap(&buf, m)
			assert.Error(t, err)
		})
	})
}

func TestSetToJSONMock(t *testing.T) {
	// Ensure the mock is reset after this test
	defer SetToJSONMock(nil)

	// Set a mock function
	mockFunc := func(v any) ([]byte, error) {
		return []byte("mocked_output"), nil
	}
	SetToJSONMock(mockFunc)

	// Verify that ToJSON now uses the mock
	result, err := ToJSON("some_input")
	require.NoError(t, err)
	assert.Equal(t, "mocked_output", string(result))

	// Verify that ToJSONOriginal still uses the original behavior
	originalResult, err := ToJSONOriginal("some_input")
	require.NoError(t, err)
	assert.Equal(t, `"some_input"`, string(originalResult))
}
