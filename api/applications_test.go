package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAppGUID = "MTIzNDU2N3xBUE18QVBQTElDQVRJT058OTg3NjU0MzIx"

func TestListApplications(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "applications_entity_search.json"))

	client := NewTestClient(server)
	apps, err := client.ListApplications()

	require.NoError(t, err)
	require.Len(t, apps, 3)

	assert.Equal(t, 12345678, apps[0].ID)
	assert.Equal(t, EntityGUID(testAppGUID), apps[0].GUID)
	assert.Equal(t, "My Application", apps[0].Name)
	assert.Equal(t, "java", apps[0].Language)
	assert.Equal(t, "NOT_ALERTING", apps[0].HealthStatus)
	assert.True(t, apps[0].Reporting)
	assert.Equal(t, "2024-01-01T00:00:00Z", apps[0].LastReportedAt)

	assert.Equal(t, "Inactive App", apps[2].Name)
	assert.False(t, apps[2].Reporting)

	server.AssertLastPath(t, "/graphql")
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "entitySearch")
	assert.Contains(t, string(req.Body), "APPLICATION")
}

func TestListApplications_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entitySearch": {"results": {"nextCursor": null, "entities": []}}}}
	}`)

	client := NewTestClient(server)
	apps, err := client.ListApplications()

	require.NoError(t, err)
	assert.Empty(t, apps)
}

func TestListApplications_Pagination(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	page1 := `{
		"data": {"actor": {"entitySearch": {"results": {
			"nextCursor": "cursor-2",
			"entities": [{"guid": "guid-1", "name": "App One", "applicationId": 1, "language": "go", "reporting": true, "alertSeverity": "NOT_ALERTING"}]
		}}}}
	}`
	page2 := `{
		"data": {"actor": {"entitySearch": {"results": {
			"nextCursor": null,
			"entities": [{"guid": "guid-2", "name": "App Two", "applicationId": 2, "language": "go", "reporting": true, "alertSeverity": "NOT_ALERTING"}]
		}}}}
	}`

	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if len(server.Requests()) == 1 {
			_, _ = w.Write([]byte(page1))
			return
		}
		_, _ = w.Write([]byte(page2))
	})

	client := NewTestClient(server)
	apps, err := client.ListApplications()

	require.NoError(t, err)
	require.Len(t, apps, 2)
	assert.Equal(t, "App One", apps[0].Name)
	assert.Equal(t, "App Two", apps[1].Name)

	requests := server.Requests()
	require.Len(t, requests, 2)
	assert.Contains(t, string(requests[1].Body), "cursor-2")
}

func TestListApplications_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "invalid api key"}`)

	client := NewTestClient(server)
	_, err := client.ListApplications()

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestGetApplication_ByGUID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entity": {
			"guid": "`+testAppGUID+`",
			"name": "My Application",
			"applicationId": 12345678,
			"language": "java",
			"reporting": true,
			"alertSeverity": "NOT_ALERTING",
			"lastReportingChangeAt": 1704067200000
		}}}
	}`)

	client := NewTestClient(server)
	app, err := client.GetApplication(testAppGUID)

	require.NoError(t, err)
	require.NotNil(t, app)

	assert.Equal(t, 12345678, app.ID)
	assert.Equal(t, EntityGUID(testAppGUID), app.GUID)
	assert.Equal(t, "My Application", app.Name)
	assert.Equal(t, "java", app.Language)
	assert.Equal(t, "NOT_ALERTING", app.HealthStatus)

	// GUID input resolves without an entity search round-trip.
	server.AssertRequestCount(t, 1)
}

func TestGetApplication_ByNumericID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		req := server.LastRequest()
		if strings.Contains(string(req.Body), "entitySearch") {
			_, _ = w.Write(LoadTestFixture(t, "applications_entity_search.json"))
			return
		}
		_, _ = w.Write([]byte(`{
			"data": {"actor": {"entity": {
				"guid": "` + testAppGUID + `",
				"name": "My Application",
				"applicationId": 12345678,
				"language": "java",
				"reporting": true,
				"alertSeverity": "NOT_ALERTING",
				"lastReportingChangeAt": 1704067200000
			}}}
		}`))
	})

	client := NewTestClient(server)
	app, err := client.GetApplication("12345678")

	require.NoError(t, err)
	assert.Equal(t, 12345678, app.ID)
	assert.Equal(t, "My Application", app.Name)
}

func TestGetApplication_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entitySearch": {"results": {"nextCursor": null, "entities": []}}}}
	}`)

	client := NewTestClient(server)
	_, err := client.GetApplication("99999")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no APM application found")
}

func TestListApplicationMetrics(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		req := server.LastRequest()
		if strings.Contains(string(req.Body), "uniques(metricName") {
			_, _ = w.Write([]byte(`{
				"data": {"actor": {"account": {"nrql": {"results": [
					{"uniques.metricName": ["Apdex", "HttpDispatcher", "WebTransaction/Function/handler"]}
				]}}}}
			}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"data": {"actor": {"entity": {
				"guid": "` + testAppGUID + `",
				"name": "My Application",
				"applicationId": 12345678,
				"language": "java",
				"reporting": true,
				"alertSeverity": "NOT_ALERTING"
			}}}
		}`))
	})

	client := NewTestClient(server)
	metrics, err := client.ListApplicationMetrics(testAppGUID)

	require.NoError(t, err)
	require.Len(t, metrics, 3)
	assert.Equal(t, "Apdex", metrics[0].Name)
	assert.Equal(t, "HttpDispatcher", metrics[1].Name)

	// The NRQL query targets the app by its resolved name.
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "My Application")
}

func TestListApplicationMetrics_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	_, err := client.ListApplicationMetrics("12345678")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestListApplicationsREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "applications_list.json"))

	client := NewTestClient(server)
	apps, err := client.ListApplicationsREST()

	require.NoError(t, err)
	require.Len(t, apps, 3)

	assert.Equal(t, 12345678, apps[0].ID)
	assert.Equal(t, "My Application", apps[0].Name)
	assert.Equal(t, "java", apps[0].Language)
	assert.Equal(t, "green", apps[0].HealthStatus)
	assert.True(t, apps[0].Reporting)

	server.AssertLastPath(t, "/applications.json")
	server.AssertLastMethod(t, "GET")
}

func TestGetApplicationREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "application_single.json"))

	client := NewTestClient(server)
	app, err := client.GetApplicationREST("12345678")

	require.NoError(t, err)
	require.NotNil(t, app)

	assert.Equal(t, 12345678, app.ID)
	assert.Equal(t, "My Application", app.Name)

	server.AssertLastPath(t, "/applications/12345678.json")
}

func TestListApplicationMetricsREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "application_metrics.json"))

	client := NewTestClient(server)
	metrics, err := client.ListApplicationMetricsREST("12345678")

	require.NoError(t, err)
	require.Len(t, metrics, 4)

	assert.Equal(t, "HttpDispatcher", metrics[0].Name)
	assert.Contains(t, metrics[0].Values, "call_count")

	server.AssertLastPath(t, "/applications/12345678/metrics.json")
}
