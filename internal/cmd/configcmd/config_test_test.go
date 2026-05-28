package configcmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
)

// TestRenderTest_JSONFlagOverridesGlobalOutput pins the carve-out
// composition rule for `config test`: the subcommand-local --json flag
// wins even when the global -o table is set. The third retained envelope
// (alongside set-credential and config show) is exercised via the pure
// renderTest helper so this test doesn't need to mock the API client.
func TestRenderTest_JSONFlagOverridesGlobalOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	o := &testOptions{
		Options: &root.Options{
			Output: "table", // global says table
			Stdout: buf,
			Stderr: &bytes.Buffer{},
		},
		json: true, // local says JSON — local must win
	}
	result := &api.ConnectionTestResult{
		APIKeyValid:   true,
		AccountAccess: true,
		AccountID:     42,
		AccountName:   "Acct",
		UserEmail:     "u@example.com",
		Region:        "US",
	}
	require.NoError(t, renderTest(o, result, false))

	var st connectionTestStatus
	require.NoError(t, json.Unmarshal(buf.Bytes(), &st),
		"local --json must emit JSON envelope even when -o table is set; got:\n%s",
		buf.String())
	assert.True(t, st.Success)
	assert.True(t, st.APIKeyValid)
	assert.True(t, st.AccountAccess)
	assert.Equal(t, "u@example.com", st.UserEmail)
}

// TestRenderTest_TextPath_NoEnvelopeWithoutJSONFlag is the sibling
// negative: without --json the text path runs (no JSON envelope shape on
// stdout; human-readable Success/Print output instead).
func TestRenderTest_TextPath_NoEnvelopeWithoutJSONFlag(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	o := &testOptions{
		Options: &root.Options{
			Output: "table",
			Stdout: stdout,
			Stderr: stderr,
		},
		json: false,
	}
	result := &api.ConnectionTestResult{APIKeyValid: true, UserEmail: "x@y.z"}
	require.NoError(t, renderTest(o, result, true))

	combined := stdout.String() + stderr.String()
	assert.Contains(t, combined, "API key valid")
	assert.NotContains(t, combined, `"api_key_valid"`,
		"text path must not emit JSON-shaped lines")
	// Stdout in the text path carries the User line; the absence test that
	// matters is "no JSON envelope braces wrapping the whole stream".
	assert.False(t, json.Valid(stdout.Bytes()),
		"text-path stdout must not parse as a JSON envelope: %q", stdout.String())
}
