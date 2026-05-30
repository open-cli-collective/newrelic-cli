package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListApplications(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "applications_list.json"))

	client := NewTestClient(server)
	apps, err := client.ListApplications()

	require.NoError(t, err)
	require.Len(t, apps, 3)

	assert.Equal(t, 12345678, apps[0].ID)
	assert.Equal(t, "My Application", apps[0].Name)
	assert.Equal(t, "java", apps[0].Language)
	assert.Equal(t, "green", apps[0].HealthStatus)
	assert.True(t, apps[0].Reporting)

	assert.Equal(t, "Inactive App", apps[2].Name)
	assert.False(t, apps[2].Reporting)

	server.AssertLastPath(t, "/applications.json")
	server.AssertLastMethod(t, "GET")
}

func TestListApplications_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "empty_list.json"))

	client := NewTestClient(server)
	apps, err := client.ListApplications()

	require.NoError(t, err)
	assert.Empty(t, apps)
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

func TestGetApplication(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "application_single.json"))

	client := NewTestClient(server)
	app, err := client.GetApplication("12345678")

	require.NoError(t, err)
	require.NotNil(t, app)

	assert.Equal(t, 12345678, app.ID)
	assert.Equal(t, "My Application", app.Name)
	assert.Equal(t, "java", app.Language)
	assert.Equal(t, "green", app.HealthStatus)

	server.AssertLastPath(t, "/applications/12345678.json")
}

func TestGetApplication_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusNotFound, `{"error": "application not found"}`)

	client := NewTestClient(server)
	_, err := client.GetApplication("99999")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestListApplicationMetrics(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "application_metrics.json"))

	client := NewTestClient(server)
	metrics, err := client.ListApplicationMetrics("12345678")

	require.NoError(t, err)
	require.Len(t, metrics, 4)

	assert.Equal(t, "HttpDispatcher", metrics[0].Name)
	assert.Contains(t, metrics[0].Values, "call_count")
	assert.Contains(t, metrics[0].Values, "average_response_time")

	server.AssertLastPath(t, "/applications/12345678/metrics.json")
}

func TestListApplicationMetrics_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusNotFound, `{"error": "application not found"}`)

	client := NewTestClient(server)
	_, err := client.ListApplicationMetrics("99999")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}
