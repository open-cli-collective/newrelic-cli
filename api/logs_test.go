package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListLogParsingRules(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "log_parsing_rules.json"))

	client := NewTestClient(server)
	rules, err := client.ListLogParsingRules()

	require.NoError(t, err)
	// Should only have 2 rules (deleted one is filtered out)
	require.Len(t, rules, 2)

	// Verify first rule
	assert.Equal(t, "rule-001", rules[0].ID)
	assert.Equal(t, "Parse Apache access logs", rules[0].Description)
	assert.True(t, rules[0].Enabled)
	assert.Equal(t, "%{COMBINEDAPACHELOG}", rules[0].Grok)

	// Verify second rule
	assert.Equal(t, "rule-002", rules[1].ID)
	assert.Equal(t, "Parse JSON application logs", rules[1].Description)

	// Verify GraphQL endpoint was used
	server.AssertLastPath(t, "/graphql")
}

func TestListLogParsingRules_FiltersDeleted(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	// Response with only a deleted rule
	response := `{
		"data": {
			"actor": {
				"account": {
					"logConfigurations": {
						"parsingRules": [
							{
								"id": "deleted-rule",
								"description": "This is deleted",
								"deleted": true
							}
						]
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	rules, err := client.ListLogParsingRules()

	require.NoError(t, err)
	assert.Empty(t, rules)
}

func TestListLogParsingRules_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	_, err := client.ListLogParsingRules()

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestCreateLogParsingRule(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "log_rule_created.json"))

	client := NewTestClient(server)
	rule, err := client.CreateLogParsingRule(
		"Newly created rule",
		"%{IP:client_ip}",
		"SELECT * FROM Log",
		true,
		"host:webserver",
	)

	require.NoError(t, err)
	require.NotNil(t, rule)

	assert.Equal(t, "rule-new", rule.ID)
	assert.Equal(t, "Newly created rule", rule.Description)
	assert.True(t, rule.Enabled)

	// Verify request
	server.AssertLastPath(t, "/graphql")
	server.AssertLastMethod(t, "POST")
}

func TestCreateLogParsingRule_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"logConfigurationsCreateParsingRule": {
				"rule": null,
				"errors": [
					{"message": "Invalid grok pattern", "type": "VALIDATION_ERROR"}
				]
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.CreateLogParsingRule("Test", "invalid{", "SELECT *", true, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid grok pattern")
}

func TestCreateLogParsingRule_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	_, err := client.CreateLogParsingRule("Test", "pattern", "nrql", true, "")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestDeleteLogParsingRule(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"logConfigurationsDeleteParsingRule": {
				"errors": []
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	err := client.DeleteLogParsingRule("rule-001")

	require.NoError(t, err)

	// Verify request
	server.AssertLastPath(t, "/graphql")
	server.AssertLastMethod(t, "POST")

	// Verify rule ID was in the mutation
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "rule-001")
}

func TestDeleteLogParsingRule_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"logConfigurationsDeleteParsingRule": {
				"errors": [
					{"message": "Rule not found", "type": "NOT_FOUND"}
				]
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	err := client.DeleteLogParsingRule("nonexistent")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Rule not found")
}

func TestDeleteLogParsingRule_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	err := client.DeleteLogParsingRule("rule-001")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestUpdateLogParsingRule(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	// Set up handler to return different responses for list and update requests
	requestCount := 0
	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			// First request is to list rules (to get existing values)
			w.Write(LoadTestFixture(t, "log_parsing_rules.json"))
		} else {
			// Second request is the actual update
			w.Write(LoadTestFixture(t, "log_rule_updated.json"))
		}
	})

	client := NewTestClient(server)
	description := "Updated description"
	enabled := false
	rule, err := client.UpdateLogParsingRule("rule-001", LogParsingRuleUpdate{
		Description: &description,
		Enabled:     &enabled,
	})

	require.NoError(t, err)
	require.NotNil(t, rule)

	assert.Equal(t, "rule-001", rule.ID)
	assert.Equal(t, "Updated description", rule.Description)
	assert.False(t, rule.Enabled)

	// Verify two requests were made (list + update)
	assert.Equal(t, 2, requestCount)
}

func TestUpdateLogParsingRule_PartialUpdate(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	// Set up handler to return different responses for list and update requests
	requestCount := 0
	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			// First request is to list rules
			w.Write(LoadTestFixture(t, "log_parsing_rules.json"))
		} else {
			// Second request is the actual update
			w.Write(LoadTestFixture(t, "log_rule_updated.json"))
		}
	})

	client := NewTestClient(server)
	// Only update grok pattern
	grok := "%{IP:client_ip} %{WORD:method}"
	_, err := client.UpdateLogParsingRule("rule-001", LogParsingRuleUpdate{
		Grok: &grok,
	})

	require.NoError(t, err)

	// Verify the update request contains grok
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "grok")
}

func TestUpdateLogParsingRule_RuleNotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	// Return rules list that doesn't include the requested rule
	server.SetResponse(http.StatusOK, LoadTestFixture(t, "log_parsing_rules.json"))

	client := NewTestClient(server)
	description := "Test"
	_, err := client.UpdateLogParsingRule("nonexistent-rule", LogParsingRuleUpdate{
		Description: &description,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule not found")
}

func TestUpdateLogParsingRule_UpdateError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	// Set up handler to return rules list first, then an error on update
	requestCount := 0
	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			// First request is to list rules
			w.Write(LoadTestFixture(t, "log_parsing_rules.json"))
		} else {
			// Second request returns an error
			w.Write([]byte(`{
				"data": {
					"logConfigurationsUpdateParsingRule": {
						"rule": null,
						"errors": [
							{"message": "Invalid grok pattern", "type": "VALIDATION_ERROR"}
						]
					}
				}
			}`))
		}
	})

	client := NewTestClient(server)
	grok := "invalid{"
	_, err := client.UpdateLogParsingRule("rule-001", LogParsingRuleUpdate{
		Grok: &grok,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid grok pattern")
}

func TestUpdateLogParsingRule_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	description := "Test"
	_, err := client.UpdateLogParsingRule("rule-001", LogParsingRuleUpdate{
		Description: &description,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}
