package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

var ErrInput = fmt.Errorf("ErrInput")

func main() {
	// Read all stdin
	data, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fmt.Fprintln(os.Stderr, ErrInput.Error())
		os.Exit(2)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		fmt.Fprintln(os.Stderr, ErrInput.Error())
		os.Exit(2)
	}
	var buf bytes.Buffer
	writeCanonicalJSON(&buf, v)
	buf.WriteByte('\n')
	os.Stdout.Write(buf.Bytes())
}

// writeCanonicalJSON writes a stable, canonical JSON encoding with sorted keys and compact form.
func writeCanonicalJSON(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONString(buf, k)
			buf.WriteByte(':')
			writeCanonicalJSON(buf, x[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalJSON(buf, x[i])
		}
		buf.WriteByte(']')
	case json.Number:
		buf.WriteString(x.String())
	case string:
		writeJSONString(buf, x)
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		b, _ := json.Marshal(x)
		buf.Write(b)
	}
}

func writeJSONString(buf *bytes.Buffer, s string) {
	b, _ := json.Marshal(s)
	buf.Write(b)
}
