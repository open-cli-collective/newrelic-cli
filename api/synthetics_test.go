package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMonitorGUID = "MTIzNDU2N3xTWU5USHxNT05JVE9SfGFiMTJjZDM0LTU2NzgtOTBlZi1hYmNkLTEyMzQ1Njc4OTBhYg=="

func TestListSyntheticMonitors(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_entity_search.json"))

	client := NewTestClient(server)
	monitors, err := client.ListSyntheticMonitors()

	require.NoError(t, err)
	require.Len(t, monitors, 3)

	assert.Equal(t, "syn-001", monitors[0].ID)
	assert.Equal(t, EntityGUID(testMonitorGUID), monitors[0].GUID)
	assert.Equal(t, "Homepage Check", monitors[0].Name)
	assert.Equal(t, "SIMPLE", monitors[0].Type)
	assert.Equal(t, 5, monitors[0].Frequency)
	assert.Equal(t, "ENABLED", monitors[0].Status)
	assert.Equal(t, "https://example.com", monitors[0].URI)

	assert.Equal(t, "DISABLED", monitors[2].Status)

	server.AssertLastPath(t, "/graphql")
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "entitySearch")
	assert.Contains(t, string(req.Body), "SYNTH")
}

func TestListSyntheticMonitors_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entitySearch": {"results": {"nextCursor": null, "entities": []}}}}
	}`)

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

func TestGetSyntheticMonitor_ByMonitorID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_entity_search.json"))

	client := NewTestClient(server)
	monitor, err := client.GetSyntheticMonitor("syn-001")

	require.NoError(t, err)
	require.NotNil(t, monitor)

	assert.Equal(t, "syn-001", monitor.ID)
	assert.Equal(t, "Homepage Check", monitor.Name)
	assert.Equal(t, "SIMPLE", monitor.Type)
	assert.Equal(t, "https://example.com", monitor.URI)
}

func TestGetSyntheticMonitor_ByName(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_entity_search.json"))

	client := NewTestClient(server)
	monitor, err := client.GetSyntheticMonitor("API Check")

	require.NoError(t, err)
	assert.Equal(t, "syn-002", monitor.ID)
	assert.Equal(t, "SCRIPT_API", monitor.Type)
}

func TestGetSyntheticMonitor_ByGUID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entity": {
			"guid": "`+testMonitorGUID+`",
			"name": "Homepage Check",
			"monitorId": "syn-001",
			"monitorType": "SIMPLE",
			"period": 5,
			"monitoredUrl": "https://example.com",
			"monitorSummary": {"status": "ENABLED"}
		}}}
	}`)

	client := NewTestClient(server)
	monitor, err := client.GetSyntheticMonitor(testMonitorGUID)

	require.NoError(t, err)
	assert.Equal(t, "syn-001", monitor.ID)

	// GUID input resolves without an entity search round-trip.
	server.AssertRequestCount(t, 1)
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "entity(guid")
}

func TestGetSyntheticMonitor_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entitySearch": {"results": {"nextCursor": null, "entities": []}}}}
	}`)

	client := NewTestClient(server)
	_, err := client.GetSyntheticMonitor("missing-monitor")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no synthetic monitor found")
}

func TestCreateSyntheticMonitor_Simple(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"result": {
			"errors": [],
			"monitor": {
				"guid": "`+testMonitorGUID+`",
				"id": "syn-new",
				"name": "New Monitor",
				"period": "EVERY_10_MINUTES",
				"status": "ENABLED",
				"uri": "https://example.com"
			}
		}}
	}`)

	client := NewTestClient(server)
	monitor, err := client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name:      "New Monitor",
		Type:      "SIMPLE",
		Frequency: 10,
		URI:       "https://example.com",
		Locations: []string{"AWS_US_EAST_1"},
	})

	require.NoError(t, err)
	require.NotNil(t, monitor)

	assert.Equal(t, "syn-new", monitor.ID)
	assert.Equal(t, EntityGUID(testMonitorGUID), monitor.GUID)
	assert.Equal(t, "SIMPLE", monitor.Type)
	assert.Equal(t, 10, monitor.Frequency)
	assert.Equal(t, "ENABLED", monitor.Status)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "syntheticsCreateSimpleMonitor")
	assert.Contains(t, string(req.Body), `"period":"EVERY_10_MINUTES"`)
	assert.Contains(t, string(req.Body), `"public":["AWS_US_EAST_1"]`)
	// The client's account ID is passed to the mutation.
	assert.Contains(t, string(req.Body), `"accountId":12345`)
}

func TestCreateSyntheticMonitor_ScriptApiWithRuntime(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"result": {
			"errors": [],
			"monitor": {
				"guid": "`+testMonitorGUID+`",
				"id": "syn-new",
				"name": "API Monitor",
				"period": "EVERY_5_MINUTES",
				"status": "ENABLED"
			}
		}}
	}`)

	client := NewTestClient(server)
	monitor, err := client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name:      "API Monitor",
		Type:      "SCRIPT_API",
		Frequency: 5,
		Script:    "console.log('ok')",
		Locations: []string{"AWS_US_EAST_1"},
		Runtime: &SyntheticMonitorRuntime{
			RuntimeType:        "NODE_API",
			RuntimeTypeVersion: "16.10",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "SCRIPT_API", monitor.Type)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "syntheticsCreateScriptApiMonitor")
	assert.Contains(t, string(req.Body), `"runtimeType":"NODE_API"`)
	assert.Contains(t, string(req.Body), `"script":"console.log('ok')"`)
}

func TestCreateSyntheticMonitor_MutationError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"result": {
			"errors": [{"description": "location invalid", "type": "BAD_REQUEST"}],
			"monitor": null
		}}
	}`)

	client := NewTestClient(server)
	_, err := client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name:      "Bad Monitor",
		Type:      "SIMPLE",
		Frequency: 10,
		URI:       "https://example.com",
		Locations: []string{"NOT_A_LOCATION"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "location invalid")
}

func TestCreateSyntheticMonitor_Validation(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)

	_, err := client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name: "x", Type: "CERT_CHECK", Frequency: 10,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported monitor type")

	_, err = client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name: "x", Type: "SIMPLE", Frequency: 10, Locations: []string{"AWS_US_EAST_1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uri is required")

	_, err = client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name: "x", Type: "SCRIPT_API", Frequency: 10, Locations: []string{"AWS_US_EAST_1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "script is required")

	_, err = client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name: "x", Type: "SIMPLE", Frequency: 10, URI: "https://example.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "location is required")

	_, err = client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name: "x", Type: "SIMPLE", Frequency: 7, URI: "https://example.com", Locations: []string{"AWS_US_EAST_1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid frequency")

	_, err = client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name: "x", Type: "SIMPLE", Frequency: 10, Status: "MUTED", URI: "https://example.com", Locations: []string{"AWS_US_EAST_1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status")

	server.AssertRequestCount(t, 0)
}

func TestCreateSyntheticMonitor_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	_, err := client.CreateSyntheticMonitor(&SyntheticMonitorInput{
		Name: "x", Type: "SIMPLE", Frequency: 10, URI: "https://example.com", Locations: []string{"AWS_US_EAST_1"},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestUpdateSyntheticMonitor(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		req := server.LastRequest()
		if strings.Contains(string(req.Body), "entitySearch") {
			_, _ = w.Write(LoadTestFixture(t, "synthetics_entity_search.json"))
			return
		}
		_, _ = w.Write([]byte(`{
			"data": {"result": {
				"errors": [],
				"monitor": {
					"guid": "` + testMonitorGUID + `",
					"id": "syn-001",
					"name": "Homepage Check v2",
					"period": "EVERY_15_MINUTES",
					"status": "ENABLED",
					"uri": "https://example.com"
				}
			}}
		}`))
	})

	client := NewTestClient(server)
	monitor, err := client.UpdateSyntheticMonitor("syn-001", &SyntheticMonitorInput{
		Name:      "Homepage Check v2",
		Frequency: 15,
	})

	require.NoError(t, err)
	assert.Equal(t, "Homepage Check v2", monitor.Name)
	assert.Equal(t, 15, monitor.Frequency)
	assert.Equal(t, "SIMPLE", monitor.Type)

	req := server.LastRequest()
	require.NotNil(t, req)
	// The monitor's existing type selects the mutation.
	assert.Contains(t, string(req.Body), "syntheticsUpdateSimpleMonitor")
}

func TestUpdateSyntheticMonitor_TypeChangeRejected(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_entity_search.json"))

	client := NewTestClient(server)
	_, err := client.UpdateSyntheticMonitor("syn-001", &SyntheticMonitorInput{
		Name: "x", Type: "SCRIPT_API", Frequency: 15,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "type cannot be changed")
}

func TestDeleteSyntheticMonitor(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		req := server.LastRequest()
		if strings.Contains(string(req.Body), "entitySearch") {
			_, _ = w.Write(LoadTestFixture(t, "synthetics_entity_search.json"))
			return
		}
		_, _ = w.Write([]byte(`{
			"data": {"syntheticsDeleteMonitor": {"deletedGuid": "` + testMonitorGUID + `"}}
		}`))
	})

	client := NewTestClient(server)
	err := client.DeleteSyntheticMonitor("syn-001")

	require.NoError(t, err)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "syntheticsDeleteMonitor")
}

func TestListSyntheticMonitorsREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_monitors.json"))

	client := NewTestClient(server)
	monitors, err := client.ListSyntheticMonitorsREST()

	require.NoError(t, err)
	require.Len(t, monitors, 3)

	assert.Equal(t, "syn-001", monitors[0].ID)
	assert.Equal(t, "Homepage Check", monitors[0].Name)

	server.AssertLastPath(t, "/synthetics/monitors.json")
}

func TestGetSyntheticMonitorREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "synthetics_monitor_single.json"))

	client := NewTestClient(server)
	monitor, err := client.GetSyntheticMonitorREST("syn-001")

	require.NoError(t, err)
	assert.Equal(t, "syn-001", monitor.ID)

	server.AssertLastPath(t, "/synthetics/monitors/syn-001")
}

func TestDeleteSyntheticMonitorREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusNoContent, "")

	client := NewTestClient(server)
	err := client.DeleteSyntheticMonitorREST("syn-001")

	require.NoError(t, err)
	server.AssertLastMethod(t, "DELETE")
}
