package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListAlertPolicies(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "alert_policies_search.json"))

	client := NewTestClient(server)
	policies, err := client.ListAlertPolicies()

	require.NoError(t, err)
	require.Len(t, policies, 3)

	assert.Equal(t, 111, policies[0].ID)
	assert.Equal(t, "Production Alerts", policies[0].Name)
	assert.Equal(t, "PER_POLICY", policies[0].IncidentPreference)

	server.AssertLastPath(t, "/graphql")
	server.AssertLastMethod(t, "POST")
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "policiesSearch")
}

func TestListAlertPolicies_Pagination(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	page1 := `{
		"data": {"actor": {"account": {"alerts": {"policiesSearch": {
			"nextCursor": "cursor-2",
			"policies": [{"id": "111", "name": "Production Alerts", "incidentPreference": "PER_POLICY"}]
		}}}}}
	}`
	page2 := `{
		"data": {"actor": {"account": {"alerts": {"policiesSearch": {
			"nextCursor": null,
			"policies": [{"id": "222", "name": "Staging Alerts", "incidentPreference": "PER_CONDITION"}]
		}}}}}
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
	policies, err := client.ListAlertPolicies()

	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.Equal(t, 111, policies[0].ID)
	assert.Equal(t, 222, policies[1].ID)

	requests := server.Requests()
	require.Len(t, requests, 2)
	assert.Contains(t, string(requests[1].Body), "cursor-2")
}

func TestListAlertPolicies_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"account": {"alerts": {"policiesSearch": {"nextCursor": null, "policies": []}}}}}
	}`)

	client := NewTestClient(server)
	policies, err := client.ListAlertPolicies()

	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestListAlertPolicies_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "invalid api key"}`)

	client := NewTestClient(server)
	_, err := client.ListAlertPolicies()

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestListAlertPolicies_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	_, err := client.ListAlertPolicies()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestListAlertPoliciesREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "alert_policies_list.json"))

	client := NewTestClient(server)
	policies, err := client.ListAlertPoliciesREST()

	require.NoError(t, err)
	require.Len(t, policies, 3)

	assert.Equal(t, 111, policies[0].ID)
	assert.Equal(t, "Production Alerts", policies[0].Name)
	assert.Equal(t, "PER_POLICY", policies[0].IncidentPreference)

	server.AssertLastPath(t, "/alerts_policies.json")
}

func TestGetAlertPolicy(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"account": {
					"alerts": {
						"policy": {
							"id": "111",
							"name": "Production Alerts",
							"incidentPreference": "PER_POLICY"
						}
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	policy, err := client.GetAlertPolicy("111")

	require.NoError(t, err)
	require.NotNil(t, policy)

	assert.Equal(t, 111, policy.ID)
	assert.Equal(t, "Production Alerts", policy.Name)
	assert.Equal(t, "PER_POLICY", policy.IncidentPreference)

	server.AssertLastPath(t, "/graphql")
	server.AssertLastMethod(t, "POST")
}

func TestGetAlertPolicy_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"account": {
					"alerts": {
						"policy": null
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.GetAlertPolicy("99999")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy not found")
}

func TestGetAlertPolicy_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = "" // Remove account ID

	_, err := client.GetAlertPolicy("111")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}
