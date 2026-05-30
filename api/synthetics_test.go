package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListSyntheticMonitors(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_monitors.json"))

	client := NewTestClient(server)
	monitors, err := client.ListSyntheticMonitors()

	require.NoError(t, err)
	require.Len(t, monitors, 3)

	assert.Equal(t, "syn-001", monitors[0].ID)
	assert.Equal(t, "Homepage Check", monitors[0].Name)
	assert.Equal(t, "SIMPLE", monitors[0].Type)
	assert.Equal(t, 5, monitors[0].Frequency)
	assert.Equal(t, "ENABLED", monitors[0].Status)
	assert.Equal(t, "https://example.com", monitors[0].URI)

	server.AssertLastPath(t, "/synthetics/monitors.json")
}

func TestListSyntheticMonitors_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{"monitors": []}`)

	client := NewTestClient(server)
	monitors, err := client.ListSyntheticMonitors()

	require.NoError(t, err)
	assert.Empty(t, monitors)
}

func TestListSyntheticMonitors_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "unauthorized"}`)

	client := NewTestClient(server)
	_, err := client.ListSyntheticMonitors()

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestGetSyntheticMonitor(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_monitor_single.json"))

	client := NewTestClient(server)
	monitor, err := client.GetSyntheticMonitor("syn-001")

	require.NoError(t, err)
	require.NotNil(t, monitor)

	assert.Equal(t, "syn-001", monitor.ID)
	assert.Equal(t, "Homepage Check", monitor.Name)
	assert.Equal(t, "SIMPLE", monitor.Type)
	assert.Equal(t, "https://example.com", monitor.URI)

	server.AssertLastPath(t, "/synthetics/monitors/syn-001")
}

func TestGetSyntheticMonitor_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusNotFound, `{"error": "monitor not found"}`)

	client := NewTestClient(server)
	_, err := client.GetSyntheticMonitor("nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}
