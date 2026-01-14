package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListDashboards(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "dashboards_list.json"))

	client := NewTestClient(server)
	dashboards, err := client.ListDashboards()

	require.NoError(t, err)
	require.Len(t, dashboards, 2)

	// Verify first dashboard
	assert.Equal(t, EntityGUID("MXxWSVp8REFTSEJPQVJEfDEyMzQ1"), dashboards[0].GUID)
	assert.Equal(t, "Production Overview", dashboards[0].Name)
	assert.Equal(t, 12345, dashboards[0].AccountID)

	// Verify second dashboard
	assert.Equal(t, "API Performance", dashboards[1].Name)

	// Verify GraphQL endpoint and query
	server.AssertLastPath(t, "/graphql")
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "entitySearch")
	assert.Contains(t, string(req.Body), "DASHBOARD")
}

func TestListDashboards_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"entitySearch": {
					"results": {
						"entities": []
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	dashboards, err := client.ListDashboards()

	require.NoError(t, err)
	assert.Empty(t, dashboards)
}

func TestListDashboards_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	_, err := client.ListDashboards()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestListDashboards_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "unauthorized"}`)

	client := NewTestClient(server)
	_, err := client.ListDashboards()

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestGetDashboard(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "dashboard_detail.json"))

	client := NewTestClient(server)
	dashboard, err := client.GetDashboard(EntityGUID("MXxWSVp8REFTSEJPQVJEfDEyMzQ1"))

	require.NoError(t, err)
	require.NotNil(t, dashboard)

	assert.Equal(t, EntityGUID("MXxWSVp8REFTSEJPQVJEfDEyMzQ1"), dashboard.GUID)
	assert.Equal(t, "Production Overview", dashboard.Name)
	assert.Equal(t, "Main production metrics dashboard", dashboard.Description)
	assert.Equal(t, "PUBLIC_READ_WRITE", dashboard.Permissions)

	// Verify pages
	require.Len(t, dashboard.Pages, 2)
	assert.Equal(t, "Overview", dashboard.Pages[0].Name)
	assert.Equal(t, "Details", dashboard.Pages[1].Name)

	// Verify widgets on first page
	require.Len(t, dashboard.Pages[0].Widgets, 2)
	assert.Equal(t, "Error Rate", dashboard.Pages[0].Widgets[0].Title)
	assert.Equal(t, "Throughput", dashboard.Pages[0].Widgets[1].Title)
}

func TestGetDashboard_WithWidgets(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "dashboard_detail.json"))

	client := NewTestClient(server)
	dashboard, err := client.GetDashboard(EntityGUID("MXxWSVp8REFTSEJPQVJEfDEyMzQ1"))

	require.NoError(t, err)

	// Check widget visualization
	widget := dashboard.Pages[0].Widgets[0]
	assert.Equal(t, "widget-1", widget.ID)
	require.NotNil(t, widget.Visualization)
	assert.Equal(t, "viz.line", widget.Visualization["id"])
}

func TestGetDashboard_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"entity": null
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.GetDashboard(EntityGUID("nonexistent"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dashboard not found")
}

func TestGetDashboard_GraphQLError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "graphql_error.json"))

	client := NewTestClient(server)
	_, err := client.GetDashboard(EntityGUID("invalid-guid"))

	require.Error(t, err)
}
