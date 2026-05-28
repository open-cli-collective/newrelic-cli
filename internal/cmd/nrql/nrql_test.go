package nrql

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmitPassthroughJSON_PreservesIndentedWireShape pins the byte shape
// contract for `nrq nrql`: 2-space indent + trailing newline. The --link
// path bypasses this and emits a plain URL — that exception is by design
// and unchanged by #108.
func TestEmitPassthroughJSON_PreservesIndentedWireShape(t *testing.T) {
	var buf bytes.Buffer
	payload := map[string]interface{}{
		"results": []interface{}{
			map[string]interface{}{"count": float64(42)},
		},
	}
	require.NoError(t, emitPassthroughJSON(&buf, payload))

	out := buf.String()
	assert.True(t, strings.HasSuffix(out, "\n"), "must end in a newline")
	assert.Contains(t, out, "\n  \"results\"", "must be pretty-printed with 2-space indent")

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, payload, got)
}
