package me

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

const apiKeySentinel = "NRAK-SHOULD-NEVER-APPEAR-IN-ME-OUTPUT"

func newView(t *testing.T, f view.Format) (*view.View, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	v := view.New(&out, &out)
	v.Format = f
	return v, &out
}

// §1.12: no surface (table/plain) ever contains the api_key. The
// ConnectionTestResult has no key field, but pin it so a future field
// addition can't regress the secret-absence guarantee. JSON output was
// removed per cli-common docs/output-and-rendering.md §2.
func TestRenderMe_NeverLeaksAPIKey(t *testing.T) {
	res := &api.ConnectionTestResult{
		APIKeyValid: true, AccountAccess: true,
		UserID: "1234", UserEmail: "u@example.com",
		AccountID: 42, AccountName: "Acct", Region: "US",
	}
	for _, f := range []view.Format{view.FormatTable, view.FormatPlain} {
		v, out := newView(t, f)
		require.NoError(t, renderMe(v, res, true))
		s := out.String()
		assert.NotContains(t, s, apiKeySentinel)
		assert.NotContains(t, strings.ToLower(s), "api_key\"")
		assert.Contains(t, s, "u@example.com", "identity must render (%s)", f)
	}
}

// account fields are omitted entirely when no account is configured.
func TestRenderMe_NoAccountConfigured_OmitsAccountFields(t *testing.T) {
	res := &api.ConnectionTestResult{APIKeyValid: true, UserID: "1", UserEmail: "x@y.z", Region: "EU"}
	v, out := newView(t, view.FormatTable)
	require.NoError(t, renderMe(v, res, false))
	s := out.String()
	assert.NotContains(t, s, "Account ID")
	assert.NotContains(t, s, "Account name")
	assert.Contains(t, s, "x@y.z")
}

// evaluate is the scripted health-check predicate the installer relies on.
func TestEvaluate_Predicate(t *testing.T) {
	tests := []struct {
		name              string
		res               *api.ConnectionTestResult
		accountConfigured bool
		wantErr           bool
	}{
		{"valid key, no account configured", &api.ConnectionTestResult{APIKeyValid: true}, false, false},
		{"valid key + account access", &api.ConnectionTestResult{APIKeyValid: true, AccountAccess: true}, true, false},
		{"valid key but account NOT accessible (configured)", &api.ConnectionTestResult{APIKeyValid: true, AccountAccess: false, ErrorMessage: "no access"}, true, true},
		{"invalid key", &api.ConnectionTestResult{APIKeyValid: false, ErrorMessage: "bad key"}, false, true},
		{"invalid key, account configured", &api.ConnectionTestResult{APIKeyValid: false}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := evaluate(tt.res, tt.accountConfigured)
			if tt.wantErr {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), apiKeySentinel)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
