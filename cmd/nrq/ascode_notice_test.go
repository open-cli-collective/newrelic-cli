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
	opts.Stdin = strings.NewReader("")
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

func TestDashboardsCreate_Note(t *testing.T) {
	input := filepath.Join("testdata", "ascode", "dashboard_input.json")
	route := nerdGraphRoute{"dashboardCreate", "dashboard_created.json"}

	h := newNoticeHarness(t, route)
	stdout, stderr, err := h.run("dash", "create", "-f", input, "-o", "plain")
	require.NoError(t, err)
	assert.Equal(t, ascode.Message(ascode.Dashboard), stderr)
	sent := h.sentWith("dashboardCreate")
	require.Len(t, sent, 1)
	assert.Equal(t, ascode.Message(ascode.Dashboard), sent[0].stderrAtSend, "note precedes the write")

	t.Setenv(ascode.DisableEnv, "true")
	silencedStdout, silencedStderr, err := h.run("dash", "create", "-f", input, "-o", "plain")
	require.NoError(t, err)
	assert.Empty(t, silencedStderr)
	assert.Equal(t, silencedStdout, stdout, "the note never changes stdout")
}

func TestDashboardsDelete_NoteOnce(t *testing.T) {
	h := newNoticeHarness(t,
		nerdGraphRoute{"dashboardDelete", "nerdgraph_dashboard_deleted.json"},
		nerdGraphRoute{"entity(guid", "dashboard_get.json"},
	)
	stdout, stderr, err := h.run("dashboards", "delete", dashboardGUID, "--force")
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Equal(t, 1, strings.Count(stderr, "Note:"))
	assert.True(t, strings.HasPrefix(stderr, ascode.Message(ascode.Dashboard)), stderr)
	sent := h.sentWith("dashboardDelete")
	require.Len(t, sent, 1)
	assert.Equal(t, ascode.Message(ascode.Dashboard), sent[0].stderrAtSend, "note precedes the write")
}

func TestSyntheticsCreate_Note(t *testing.T) {
	h := newNoticeHarness(t, nerdGraphRoute{"syntheticsCreateSimpleMonitor", "synthetics_monitor_created.json"})
	input := filepath.Join("testdata", "ascode", "synthetics_monitor_input.json")
	stdout, stderr, err := h.run("syn", "create", "-f", input, "-o", "plain")
	require.NoError(t, err)
	assert.Equal(t, ascode.Message(ascode.SyntheticMonitor), stderr)
	assert.Contains(t, stdout, "checkout-service health")
	sent := h.sentWith("syntheticsCreateSimpleMonitor")
	require.Len(t, sent, 1)
	assert.Equal(t, ascode.Message(ascode.SyntheticMonitor), sent[0].stderrAtSend, "note precedes the write")
}
