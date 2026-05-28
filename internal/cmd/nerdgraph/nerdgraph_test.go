package nerdgraph

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmitPassthroughJSON_PreservesIndentedWireShape pins the byte shape
// contract for `nrq nerdgraph query`: 2-space indent + trailing newline.
// This is the format the deleted View.JSON path produced
// (MarshalWithMigration → json.Indent + "\n"); breaking it would silently
// reformat every downstream NerdGraph consumer.
func TestEmitPassthroughJSON_PreservesIndentedWireShape(t *testing.T) {
	var buf bytes.Buffer
	payload := map[string]interface{}{
		"actor": map[string]interface{}{
			"user": map[string]interface{}{"email": "u@example.com"},
		},
	}
	require.NoError(t, emitPassthroughJSON(&buf, payload))

	out := buf.String()
	// Trailing newline (Encoder.Encode appends).
	assert.True(t, strings.HasSuffix(out, "\n"), "must end in a newline")
	// Two-space indent inside the object (json.Indent style).
	assert.Contains(t, out, "\n  \"actor\"", "must be pretty-printed with 2-space indent")
	// And it must round-trip back to the same payload.
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, payload, got)
}
