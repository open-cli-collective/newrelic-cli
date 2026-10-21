package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/ascode"
	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

const (
	dashboardGUID   = "MTIzNDU2N3xWSVp8REFTSEJPQVJEfDEyMzQ1Njc4OQ=="
	deleteMutation  = `mutation { dashboardDelete(guid: "` + dashboardGUID + `") { status errors { type } } }`
	currentUserRead = `{ actor { user { email name } } }`
)

// nerdGraphRoute answers a NerdGraph request whose query contains match
// with the given fixture from testdata/ascode.
type nerdGraphRoute struct {
	match   string
	fixture string
}

// sentRequest records one NerdGraph request and what stderr held when it
// was sent, so tests can prove the note precedes the write.
type sentRequest struct {
	query        string
	stderrAtSend string
}

// noticeHarness runs the real nrq command tree against a stubbed NerdGraph
// endpoint (http.DefaultTransport is swapped for the test's duration) with an
// API key planted in the hermetic file-backend keyring.
type noticeHarness struct {
	t      *testing.T
	routes []nerdGraphRoute
	stderr *bytes.Buffer
	sent   []sentRequest
	// stdin is what the command reads, e.g. a delete confirmation answer.
	stdin string
}

func newNoticeHarness(t *testing.T, routes ...nerdGraphRoute) *noticeHarness {
	t.Helper()
	testutil.Setup(t)
	t.Setenv("NEWRELIC_ACCOUNT_ID", "1234567")
	t.Setenv(ascode.DisableEnv, "")

	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	require.NoError(t, st.SetAPIKey("NRAK-TEST-PLACEHOLDER"))
	require.NoError(t, st.Close())

	h := &noticeHarness{t: t, routes: routes}
	orig := http.DefaultTransport
	http.DefaultTransport = h
	t.Cleanup(func() { http.DefaultTransport = orig })
	return h
}

func (h *noticeHarness) RoundTrip(req *http.Request) (*http.Response, error) {
	var body struct {
		Query string `json:"query"`
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	h.sent = append(h.sent, sentRequest{query: body.Query, stderrAtSend: h.stderr.String()})

	for _, r := range h.routes {
		if strings.Contains(body.Query, r.match) {
			payload, err := os.ReadFile(filepath.Join("testdata", "ascode", r.fixture))
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(payload)),
				Request:    req,
			}, nil
		}
	}
	h.t.Fatalf("unexpected NerdGraph request: %s", body.Query)
	return nil, nil
}

// run executes nrq with args and returns stdout, stderr and the error.
func (h *noticeHarness) run(args ...string) (string, string, error) {
	h.t.Helper()
	h.sent = nil
	rootCmd, opts := buildRootCommand()
	var stdout, stderr bytes.Buffer
	h.stderr = &stderr
	opts.Stdout = &stdout
	opts.Stderr = &stderr
	opts.Stdin = strings.NewReader(h.stdin)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(append([]string{"--no-color"}, args...))
	err := rootCmd.Execute()
	return stdout.String(), stderr.String(), err
}

// sentWith returns the requests whose query contains match.
func (h *noticeHarness) sentWith(match string) []sentRequest {
	var out []sentRequest
	for _, s := range h.sent {
		if strings.Contains(s.query, match) {
			out = append(out, s)
		}
	}
	return out
}

func fixtureData(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ascode", name))
	require.NoError(t, err)
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &resp))
	var data interface{}
	require.NoError(t, json.Unmarshal(resp.Data, &data))
	pretty, err := json.MarshalIndent(data, "", "  ")
	require.NoError(t, err)
	return string(pretty) + "\n"
}

func TestNerdGraphMutation_NoteOnStderrOnly(t *testing.T) {
	want := fixtureData(t, "nerdgraph_dashboard_deleted.json")
	for _, alias := range []string{"nerdgraph", "ng", "graphql"} {
		t.Run(alias, func(t *testing.T) {
			h := newNoticeHarness(t, nerdGraphRoute{"dashboardDelete", "nerdgraph_dashboard_deleted.json"})
			stdout, stderr, err := h.run(alias, "query", deleteMutation)
			require.NoError(t, err)

			assert.Equal(t, ascode.Message(ascode.Dashboard), stderr, "exactly one note, nothing else")
			assert.Equal(t, want, stdout, "stdout is the unchanged JSON passthrough")
			assert.True(t, json.Valid([]byte(stdout)))

			sent := h.sentWith("dashboardDelete")
			require.Len(t, sent, 1)
			assert.Equal(t, ascode.Message(ascode.Dashboard), sent[0].stderrAtSend, "note precedes the write")
		})
	}
}

func TestNerdGraphMutation_MultipleKindsOneNote(t *testing.T) {
	h := newNoticeHarness(t, nerdGraphRoute{"dashboardDelete", "nerdgraph_dashboard_deleted.json"})
	doc := `mutation {
		dashboardDelete(guid: "` + dashboardGUID + `") { status }
		alertsPolicyDelete(accountId: 1234567, id: 123456789) { id }
	}`
	_, stderr, err := h.run("ng", "query", doc)
	require.NoError(t, err)
	assert.Equal(t, ascode.Message(ascode.Dashboard, ascode.AlertPolicy), stderr)
	assert.Equal(t, 1, strings.Count(stderr, "Note:"))
}

func TestNerdGraphReadOnlyQuery_NoNote(t *testing.T) {
	h := newNoticeHarness(t, nerdGraphRoute{"actor", "nerdgraph_current_user.json"})
	stdout, stderr, err := h.run("nerdgraph", "query", currentUserRead)
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Equal(t, fixtureData(t, "nerdgraph_current_user.json"), stdout)
}

func TestNerdGraphMutation_Silenced(t *testing.T) {
	h := newNoticeHarness(t, nerdGraphRoute{"dashboardDelete", "nerdgraph_dashboard_deleted.json"})
	t.Setenv(ascode.DisableEnv, "1")
	stdout, stderr, err := h.run("ng", "query", deleteMutation)
	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Equal(t, fixtureData(t, "nerdgraph_dashboard_deleted.json"), stdout)
}

func TestNerdGraphMutation_NoteShownWhenWriteFails(t *testing.T) {
	h := newNoticeHarness(t, nerdGraphRoute{"dashboardDelete", "nerdgraph_error.json"})
	stdout, stderr, err := h.run("ng", "query", deleteMutation)
	require.Error(t, err)
	assert.Empty(t, stdout)
	assert.True(t, strings.HasPrefix(stderr, ascode.Message(ascode.Dashboard)), stderr)
}

const (
	monitorID    = "00000000-0000-4000-8000-000000000001"
	monitorInput = "testdata/ascode/synthetics_monitor_input.json"
	dashInput    = "testdata/ascode/dashboard_input.json"
)

var (
	dashboardGetRoute = nerdGraphRoute{"entity(guid", "dashboard_get.json"}
	monitorFindRoute  = nerdGraphRoute{"entitySearch", "synthetics_monitor_search.json"}
)

func TestWriteCommands_NoteOnceBeforeWrite(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		routes   []nerdGraphRoute
		mutation string
		kind     ascode.Kind
	}{
		{
			name:     "dashboards create",
			args:     []string{"dash", "create", "-f", dashInput},
			routes:   []nerdGraphRoute{{"dashboardCreate", "dashboard_created.json"}},
			mutation: "dashboardCreate",
			kind:     ascode.Dashboard,
		},
		{
			name:     "dashboards update",
			args:     []string{"dashboard", "update", dashboardGUID, "-f", dashInput},
			routes:   []nerdGraphRoute{{"dashboardUpdate", "dashboard_updated.json"}},
			mutation: "dashboardUpdate",
			kind:     ascode.Dashboard,
		},
		{
			name:     "dashboards delete --force",
			args:     []string{"dashboards", "delete", dashboardGUID, "--force"},
			routes:   []nerdGraphRoute{{"dashboardDelete", "nerdgraph_dashboard_deleted.json"}, dashboardGetRoute},
			mutation: "dashboardDelete",
			kind:     ascode.Dashboard,
		},
		{
			name:     "synthetics create",
			args:     []string{"syn", "create", "-f", monitorInput},
			routes:   []nerdGraphRoute{{"syntheticsCreateSimpleMonitor", "synthetics_monitor_created.json"}},
			mutation: "syntheticsCreateSimpleMonitor",
			kind:     ascode.SyntheticMonitor,
		},
		{
			name:     "synthetics update",
			args:     []string{"synthetic", "update", monitorID, "-f", monitorInput},
			routes:   []nerdGraphRoute{{"syntheticsUpdateSimpleMonitor", "synthetics_monitor_updated.json"}, monitorFindRoute},
			mutation: "syntheticsUpdateSimpleMonitor",
			kind:     ascode.SyntheticMonitor,
		},
		{
			name: "synthetics delete --force",
			args: []string{"synthetics", "delete", monitorID, "--force"},
			// delete resolves the monitor by ID, then again by its GUID.
			routes: []nerdGraphRoute{
				{"syntheticsDeleteMonitor", "synthetics_monitor_deleted.json"},
				monitorFindRoute,
				{"entity(guid", "synthetics_monitor_get.json"},
			},
			mutation: "syntheticsDeleteMonitor",
			kind:     ascode.SyntheticMonitor,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newNoticeHarness(t, tt.routes...)
			_, stderr, err := h.run(tt.args...)
			require.NoError(t, err)

			note := ascode.Message(tt.kind)
			assert.True(t, strings.HasPrefix(stderr, note), stderr)
			assert.Equal(t, 1, strings.Count(stderr, "Note:"), "note printed once")
			sent := h.sentWith(tt.mutation)
			require.Len(t, sent, 1)
			assert.Equal(t, note, sent[0].stderrAtSend, "note precedes the write")
		})
	}
}

func TestDeleteDeclined_NoteBeforePromptAndNoWrite(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		routes   []nerdGraphRoute
		mutation string
		kind     ascode.Kind
		prompt   string
	}{
		{
			name:     "dashboards delete",
			args:     []string{"dashboards", "delete", dashboardGUID},
			routes:   []nerdGraphRoute{dashboardGetRoute},
			mutation: "dashboardDelete",
			kind:     ascode.Dashboard,
			prompt:   `Delete dashboard "Checkout Overview"`,
		},
		{
			name:     "synthetics delete",
			args:     []string{"synthetics", "delete", monitorID},
			routes:   []nerdGraphRoute{monitorFindRoute},
			mutation: "syntheticsDeleteMonitor",
			kind:     ascode.SyntheticMonitor,
			prompt:   `Delete synthetic monitor "checkout-service health"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newNoticeHarness(t, tt.routes...)
			h.stdin = "n\n"
			stdout, stderr, err := h.run(tt.args...)
			require.NoError(t, err)
			assert.Empty(t, stdout)

			note := ascode.Message(tt.kind)
			require.True(t, strings.HasPrefix(stderr, note), stderr)
			assert.True(t, strings.HasPrefix(strings.TrimPrefix(stderr, note), tt.prompt),
				"prompt follows the note: %q", stderr)
			assert.Empty(t, h.sentWith(tt.mutation), "a declined delete sends no mutation")
		})
	}
}

func TestDashboardsCreate_SilencedStdoutUnchanged(t *testing.T) {
	h := newNoticeHarness(t, nerdGraphRoute{"dashboardCreate", "dashboard_created.json"})
	stdout, stderr, err := h.run("dash", "create", "-f", dashInput, "-o", "plain")
	require.NoError(t, err)
	assert.Equal(t, ascode.Message(ascode.Dashboard), stderr)

	t.Setenv(ascode.DisableEnv, "true")
	silencedStdout, silencedStderr, err := h.run("dash", "create", "-f", dashInput, "-o", "plain")
	require.NoError(t, err)
	assert.Empty(t, silencedStderr)
	assert.Equal(t, silencedStdout, stdout, "the note never changes stdout")
}
