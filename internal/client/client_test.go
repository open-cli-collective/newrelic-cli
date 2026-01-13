package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- doRequest Tests ---

func TestDoRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-api-key", r.Header.Get("Api-Key"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test-api-key",
		HTTPClient: http.DefaultClient,
	}

	resp, err := client.doRequest("GET", server.URL, nil)
	require.NoError(t, err)
	assert.Contains(t, string(resp), "ok")
}

func TestDoRequest_WithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		var body map[string]string
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "test", body["key"])
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received": true}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test-api-key",
		HTTPClient: http.DefaultClient,
	}

	resp, err := client.doRequest("POST", server.URL, map[string]string{"key": "test"})
	require.NoError(t, err)
	assert.Contains(t, string(resp), "received")
}

func TestDoRequest_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "unauthorized"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test-api-key",
		HTTPClient: http.DefaultClient,
	}

	_, err := client.doRequest("GET", server.URL, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}

func TestDoRequest_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client := &Client{
		APIKey:     "test-api-key",
		HTTPClient: http.DefaultClient,
	}

	_, err := client.doRequest("GET", server.URL, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

// --- Application Tests ---

func TestListApplications_Success(t *testing.T) {
	data := loadTestData(t, "applications_list.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	apps, err := client.ListApplications()

	require.NoError(t, err)
	require.Len(t, apps, 2)
	assert.Equal(t, 12345, apps[0].ID)
	assert.Equal(t, "Test Application", apps[0].Name)
	assert.Equal(t, "go", apps[0].Language)
	assert.Equal(t, "green", apps[0].HealthStatus)
	assert.True(t, apps[0].Reporting)
}

func TestListApplications_Empty(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{"applications": []}`))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	apps, err := client.ListApplications()

	require.NoError(t, err)
	assert.Empty(t, apps)
}

func TestListApplications_HTTPError(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusUnauthorized, []byte(`{"error": "unauthorized"}`))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	_, err := client.ListApplications()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}

func TestListApplications_ParseError(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`invalid json`))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	_, err := client.ListApplications()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestGetApplication_Success(t *testing.T) {
	data := loadTestData(t, "application_single.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	app, err := client.GetApplication("12345")

	require.NoError(t, err)
	assert.Equal(t, 12345, app.ID)
	assert.Equal(t, "Test Application", app.Name)
}

func TestGetApplication_HTTPError(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusNotFound, []byte(`{"error": "not found"}`))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	_, err := client.GetApplication("99999")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
}

// --- Metrics Tests ---

func TestListApplicationMetrics_Success(t *testing.T) {
	data := loadTestData(t, "application_metrics.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	metrics, err := client.ListApplicationMetrics("12345")

	require.NoError(t, err)
	require.Len(t, metrics, 2)
	assert.Equal(t, "HttpDispatcher", metrics[0].Name)
	assert.Contains(t, metrics[0].Values, "average_response_time")
}

func TestListApplicationMetrics_Empty(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{"metrics": []}`))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	metrics, err := client.ListApplicationMetrics("12345")

	require.NoError(t, err)
	assert.Empty(t, metrics)
}

// --- Alert Policy Tests ---

func TestListAlertPolicies_Success(t *testing.T) {
	data := loadTestData(t, "alert_policies_list.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	policies, err := client.ListAlertPolicies()

	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.Equal(t, 111, policies[0].ID)
	assert.Equal(t, "High Error Rate", policies[0].Name)
}

func TestListAlertPolicies_Empty(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{"policies": []}`))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	policies, err := client.ListAlertPolicies()

	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestGetAlertPolicy_Success(t *testing.T) {
	data := loadTestData(t, "alert_policy_graphql.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	policy, err := client.GetAlertPolicy("111")

	require.NoError(t, err)
	assert.Equal(t, 111, policy.ID)
	assert.Equal(t, "High Error Rate", policy.Name)
	assert.Equal(t, "PER_CONDITION_AND_TARGET", policy.IncidentPreference)
}

func TestGetAlertPolicy_MissingAccountID(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := newTestClientWithoutAccountID(t, "", server.URL, "")
	_, err := client.GetAlertPolicy("111")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

// --- Synthetics Tests ---

func TestListSyntheticMonitors_Success(t *testing.T) {
	data := loadTestData(t, "synthetic_monitors_list.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", "", server.URL)
	monitors, err := client.ListSyntheticMonitors()

	require.NoError(t, err)
	require.Len(t, monitors, 2)
	assert.Equal(t, "mon-123", monitors[0].ID)
	assert.Equal(t, "Homepage Check", monitors[0].Name)
	assert.Equal(t, "SIMPLE", monitors[0].Type)
	assert.Equal(t, 5, monitors[0].Frequency)
}

func TestListSyntheticMonitors_Empty(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{"monitors": []}`))
	defer server.Close()

	client := newTestClient(t, "", "", server.URL)
	monitors, err := client.ListSyntheticMonitors()

	require.NoError(t, err)
	assert.Empty(t, monitors)
}

func TestGetSyntheticMonitor_Success(t *testing.T) {
	data := loadTestData(t, "synthetic_monitor_single.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", "", server.URL)
	monitor, err := client.GetSyntheticMonitor("mon-123")

	require.NoError(t, err)
	assert.Equal(t, "mon-123", monitor.ID)
	assert.Equal(t, "Homepage Check", monitor.Name)
	assert.Equal(t, "https://example.com", monitor.URI)
}

// --- Deployment Tests ---

func TestListDeployments_Success(t *testing.T) {
	data := loadTestData(t, "deployments_list.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	deployments, err := client.ListDeployments("12345")

	require.NoError(t, err)
	require.Len(t, deployments, 2)
	assert.Equal(t, 1001, deployments[0].ID)
	assert.Equal(t, "v1.2.3", deployments[0].Revision)
	assert.Equal(t, "Bug fixes", deployments[0].Description)
}

func TestListDeployments_Empty(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{"deployments": []}`))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	deployments, err := client.ListDeployments("12345")

	require.NoError(t, err)
	assert.Empty(t, deployments)
}

func TestCreateDeployment_Success(t *testing.T) {
	data := loadTestData(t, "deployment_created.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	client := newTestClient(t, server.URL, "", "")
	deployment, err := client.CreateDeployment("12345", "v1.2.5", "Hotfix", "deploy-bot", "")

	require.NoError(t, err)
	assert.Equal(t, 1003, deployment.ID)
	assert.Equal(t, "v1.2.5", deployment.Revision)
	assert.Equal(t, "Hotfix", deployment.Description)
}

// --- NerdGraph Tests ---

func TestNerdGraphQuery_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": {"actor": {"user": {"name": "Test"}}}}`))
	}))
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	result, err := client.NerdGraphQuery(`{ actor { user { name } } }`, nil)

	require.NoError(t, err)
	assert.NotNil(t, result["actor"])
}

func TestNerdGraphQuery_GraphQLError(t *testing.T) {
	data := loadTestData(t, "graphql_error.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	_, err := client.NerdGraphQuery(`{ actor { user { name } } }`, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GraphQL error")
	assert.Contains(t, err.Error(), "Invalid API key")
}

// --- Dashboard Tests ---

func TestListDashboards_Success(t *testing.T) {
	data := loadTestData(t, "dashboards_list.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	dashboards, err := client.ListDashboards()

	require.NoError(t, err)
	require.Len(t, dashboards, 2)
	assert.Equal(t, "MXxEQVNIQk9BUkR8REFTSEJPQVJEfDEyMzQ1", dashboards[0].GUID)
	assert.Equal(t, "Application Dashboard", dashboards[0].Name)
	assert.Equal(t, 12345, dashboards[0].AccountID)
}

func TestListDashboards_MissingAccountID(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := newTestClientWithoutAccountID(t, "", server.URL, "")
	_, err := client.ListDashboards()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

func TestGetDashboard_Success(t *testing.T) {
	data := loadTestData(t, "dashboard_detail.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	dashboard, err := client.GetDashboard("MXxEQVNIQk9BUkR8REFTSEJPQVJEfDEyMzQ1")

	require.NoError(t, err)
	assert.Equal(t, "Application Dashboard", dashboard.Name)
	assert.Equal(t, "Main application metrics", dashboard.Description)
	assert.Equal(t, "PUBLIC_READ_WRITE", dashboard.Permissions)
	require.Len(t, dashboard.Pages, 1)
	assert.Equal(t, "Overview", dashboard.Pages[0].Name)
	require.Len(t, dashboard.Pages[0].Widgets, 1)
	assert.Equal(t, "Throughput", dashboard.Pages[0].Widgets[0].Title)
}

// --- User Tests ---

func TestListUsers_Success(t *testing.T) {
	data := loadTestData(t, "users_list.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	users, err := client.ListUsers()

	require.NoError(t, err)
	require.Len(t, users, 2)
	assert.Equal(t, "user-123", users[0].ID)
	assert.Equal(t, "John Doe", users[0].Name)
	assert.Equal(t, "john@example.com", users[0].Email)
	assert.Equal(t, "Full platform", users[0].Type)
	assert.Equal(t, "Default", users[0].AuthenticationDomain)
}

func TestGetUser_Success(t *testing.T) {
	data := loadTestData(t, "user_detail.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	user, err := client.GetUser("user-123")

	require.NoError(t, err)
	assert.Equal(t, "user-123", user.ID)
	assert.Equal(t, "John Doe", user.Name)
	assert.Equal(t, "john@example.com", user.Email)
	require.Len(t, user.Groups, 2)
	assert.Contains(t, user.Groups, "Admins")
	assert.Contains(t, user.Groups, "Developers")
}

func TestGetUser_NotFound(t *testing.T) {
	// Return a response with no matching user
	data := []byte(`{
		"data": {
			"actor": {
				"organization": {
					"userManagement": {
						"authenticationDomains": {
							"authenticationDomains": []
						}
					}
				}
			}
		}
	}`)
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	_, err := client.GetUser("nonexistent")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// --- Entity Search Tests ---

func TestSearchEntities_Success(t *testing.T) {
	data := loadTestData(t, "entity_search.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	entities, err := client.SearchEntities("name LIKE 'Test%'")

	require.NoError(t, err)
	require.Len(t, entities, 1)
	assert.Equal(t, "MXxBUE18QVBQTElDQVRJT058MTIzNDU", entities[0].GUID)
	assert.Equal(t, "Test Application", entities[0].Name)
	assert.Equal(t, "APPLICATION", entities[0].Type)
	assert.Equal(t, "APM", entities[0].Domain)
}

// --- NRQL Tests ---

func TestQueryNRQL_Success(t *testing.T) {
	data := loadTestData(t, "nrql_results.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	result, err := client.QueryNRQL("SELECT count(*) FROM Transaction FACET name")

	require.NoError(t, err)
	require.Len(t, result.Results, 2)
	assert.Equal(t, float64(1000), result.Results[0]["count"])
}

func TestQueryNRQL_MissingAccountID(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := newTestClientWithoutAccountID(t, "", server.URL, "")
	_, err := client.QueryNRQL("SELECT count(*) FROM Transaction")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

// --- Log Parsing Rules Tests ---

func TestListLogParsingRules_Success(t *testing.T) {
	data := loadTestData(t, "log_parsing_rules.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	rules, err := client.ListLogParsingRules()

	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "rule-123", rules[0].ID)
	assert.Equal(t, "Parse JSON logs", rules[0].Description)
	assert.True(t, rules[0].Enabled)
}

func TestListLogParsingRules_MissingAccountID(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := newTestClientWithoutAccountID(t, "", server.URL, "")
	_, err := client.ListLogParsingRules()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

func TestCreateLogParsingRule_Success(t *testing.T) {
	data := loadTestData(t, "log_parsing_rule_created.json")
	server := mockServerWithResponse(t, http.StatusOK, data)
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	rule, err := client.CreateLogParsingRule("New parsing rule", "%{TIMESTAMP_ISO8601:timestamp}", "SELECT * FROM Log WHERE level = 'error'", true, "")

	require.NoError(t, err)
	assert.Equal(t, "rule-456", rule.ID)
	assert.Equal(t, "New parsing rule", rule.Description)
	assert.True(t, rule.Enabled)
}

func TestCreateLogParsingRule_MissingAccountID(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := newTestClientWithoutAccountID(t, "", server.URL, "")
	_, err := client.CreateLogParsingRule("Test", "grok", "nrql", true, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

func TestDeleteLogParsingRule_Success(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{"data": {"logConfigurationsDeleteParsingRule": {"errors": []}}}`))
	defer server.Close()

	client := newTestClient(t, "", server.URL, "")
	err := client.DeleteLogParsingRule("rule-123")

	require.NoError(t, err)
}

func TestDeleteLogParsingRule_MissingAccountID(t *testing.T) {
	server := mockServerWithResponse(t, http.StatusOK, []byte(`{}`))
	defer server.Close()

	client := newTestClientWithoutAccountID(t, "", server.URL, "")
	err := client.DeleteLogParsingRule("rule-123")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

// --- Helper Function Tests ---

func TestRequireAccountID_WithAccountID(t *testing.T) {
	client := &Client{AccountID: "12345"}
	err := client.RequireAccountID()
	require.NoError(t, err)
}

func TestRequireAccountID_WithoutAccountID(t *testing.T) {
	client := &Client{AccountID: ""}
	err := client.RequireAccountID()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

func TestGetAccountIDInt_Valid(t *testing.T) {
	client := &Client{AccountID: "12345"}
	id, err := client.GetAccountIDInt()
	require.NoError(t, err)
	assert.Equal(t, 12345, id)
}

func TestGetAccountIDInt_Empty(t *testing.T) {
	client := &Client{AccountID: ""}
	_, err := client.GetAccountIDInt()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID required")
}

func TestGetAccountIDInt_Invalid(t *testing.T) {
	client := &Client{AccountID: "not-a-number"}
	_, err := client.GetAccountIDInt()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid account ID")
}

func TestSafeString_String(t *testing.T) {
	result := safeString("hello")
	assert.Equal(t, "hello", result)
}

func TestSafeString_Nil(t *testing.T) {
	result := safeString(nil)
	assert.Equal(t, "", result)
}

func TestSafeString_NonString(t *testing.T) {
	result := safeString(12345)
	assert.Equal(t, "", result)
}
