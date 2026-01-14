package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWithConfig(t *testing.T) {
	t.Run("US region", func(t *testing.T) {
		cfg := ClientConfig{
			APIKey:    "test-key",
			AccountID: "12345",
			Region:    "US",
		}
		client := NewWithConfig(cfg)

		assert.Equal(t, APIKey("test-key"), client.APIKey)
		assert.Equal(t, AccountID("12345"), client.AccountID)
		assert.Equal(t, "US", client.Region)
		assert.Equal(t, "https://api.newrelic.com/v2", client.BaseURL)
		assert.Equal(t, "https://api.newrelic.com/graphql", client.NerdGraphURL)
		assert.Equal(t, "https://synthetics.newrelic.com/synthetics/api/v3", client.SyntheticsURL)
	})

	t.Run("EU region", func(t *testing.T) {
		cfg := ClientConfig{
			APIKey:    "test-key",
			AccountID: "12345",
			Region:    "EU",
		}
		client := NewWithConfig(cfg)

		assert.Equal(t, "https://api.eu.newrelic.com/v2", client.BaseURL)
		assert.Equal(t, "https://api.eu.newrelic.com/graphql", client.NerdGraphURL)
		assert.Equal(t, "https://synthetics.eu.newrelic.com/synthetics/api/v3", client.SyntheticsURL)
	})
}

func TestClient_RequireAccountID(t *testing.T) {
	t.Run("with account ID", func(t *testing.T) {
		client := &Client{AccountID: "12345"}
		assert.NoError(t, client.RequireAccountID())
	})

	t.Run("without account ID", func(t *testing.T) {
		client := &Client{}
		err := client.RequireAccountID()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAccountIDRequired)
	})
}

func TestClient_GetAccountIDInt(t *testing.T) {
	t.Run("valid account ID", func(t *testing.T) {
		client := &Client{AccountID: "12345"}
		id, err := client.GetAccountIDInt()
		assert.NoError(t, err)
		assert.Equal(t, 12345, id)
	})

	t.Run("invalid account ID", func(t *testing.T) {
		client := &Client{AccountID: "not-a-number"}
		_, err := client.GetAccountIDInt()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid account ID")
	})

	t.Run("empty account ID", func(t *testing.T) {
		client := &Client{}
		_, err := client.GetAccountIDInt()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAccountIDRequired)
	})
}

func TestSafeString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"string value", "hello", "hello"},
		{"nil value", nil, ""},
		{"number value", 123, ""},
		{"bool value", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSafeInt(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int
	}{
		{"float64 value", float64(42), 42},
		{"nil value", nil, 0},
		{"string value", "123", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeInt(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSafeMap(t *testing.T) {
	t.Run("valid map", func(t *testing.T) {
		input := map[string]interface{}{"key": "value"}
		result, ok := safeMap(input)
		assert.True(t, ok)
		assert.Equal(t, input, result)
	})

	t.Run("nil value", func(t *testing.T) {
		_, ok := safeMap(nil)
		assert.False(t, ok)
	})

	t.Run("wrong type", func(t *testing.T) {
		_, ok := safeMap("not a map")
		assert.False(t, ok)
	})
}

func TestSafeSlice(t *testing.T) {
	t.Run("valid slice", func(t *testing.T) {
		input := []interface{}{"a", "b", "c"}
		result, ok := safeSlice(input)
		assert.True(t, ok)
		assert.Equal(t, input, result)
	})

	t.Run("nil value", func(t *testing.T) {
		_, ok := safeSlice(nil)
		assert.False(t, ok)
	})

	t.Run("wrong type", func(t *testing.T) {
		_, ok := safeSlice("not a slice")
		assert.False(t, ok)
	})
}

// --- HTTP Request Tests ---

func TestDoRequest_Success(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	expected := map[string]string{"message": "success"}
	server.SetResponse(http.StatusOK, expected)

	client := NewTestClient(server)
	data, err := client.doRequest("GET", server.URL+"/test", nil)

	require.NoError(t, err)
	assert.NotNil(t, data)

	var result map[string]string
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	assert.Equal(t, "success", result["message"])

	// Verify request was recorded
	server.AssertRequestCount(t, 1)
	server.AssertLastPath(t, "/test")
	server.AssertLastMethod(t, "GET")
	server.AssertLastHeader(t, "Api-Key", "test-api-key")
}

func TestDoRequest_WithBody(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{"status": "created"}`)

	client := NewTestClient(server)
	body := map[string]string{"name": "test"}
	_, err := client.doRequest("POST", server.URL+"/create", body)

	require.NoError(t, err)
	server.AssertLastMethod(t, "POST")

	// Verify body was sent
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), `"name":"test"`)
}

func TestDoRequest_Error401(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "invalid api key"}`)

	client := NewTestClient(server)
	_, err := client.doRequest("GET", server.URL+"/protected", nil)

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 401, apiErr.StatusCode)
}

func TestDoRequest_Error404(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusNotFound, `{"error": "not found"}`)

	client := NewTestClient(server)
	_, err := client.doRequest("GET", server.URL+"/missing", nil)

	require.Error(t, err)
	assert.True(t, IsNotFound(err))

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 404, apiErr.StatusCode)
}

func TestDoRequest_Error500(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusInternalServerError, `{"error": "server error"}`)

	client := NewTestClient(server)
	_, err := client.doRequest("GET", server.URL+"/broken", nil)

	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 500, apiErr.StatusCode)
}

func TestNerdGraphQuery_Success(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := map[string]interface{}{
		"data": map[string]interface{}{
			"actor": map[string]interface{}{
				"name": "Test User",
			},
		},
	}
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	result, err := client.NerdGraphQuery("{ actor { name } }", nil)

	require.NoError(t, err)
	require.NotNil(t, result)

	actor, ok := safeMap(result["actor"])
	require.True(t, ok)
	assert.Equal(t, "Test User", actor["name"])

	// Verify GraphQL endpoint was used
	server.AssertLastPath(t, "/graphql")
	server.AssertLastMethod(t, "POST")
}

func TestNerdGraphQuery_WithVariables(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{"data": {"account": {"id": 12345}}}`)

	client := NewTestClient(server)
	variables := map[string]interface{}{"accountId": 12345}
	_, err := client.NerdGraphQuery("query($accountId: Int!) { account(id: $accountId) { id } }", variables)

	require.NoError(t, err)

	// Verify variables were sent
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), `"variables"`)
	assert.Contains(t, string(req.Body), `"accountId"`)
}

func TestNerdGraphQuery_GraphQLError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "graphql_error.json"))

	client := NewTestClient(server)
	_, err := client.NerdGraphQuery("{ unknownField }", nil)

	require.Error(t, err)

	var gqlErr *GraphQLError
	require.ErrorAs(t, err, &gqlErr)
	assert.Contains(t, gqlErr.Message, "unknownField")
}

func TestNerdGraphQuery_HTTPError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "unauthorized"}`)

	client := NewTestClient(server)
	_, err := client.NerdGraphQuery("{ actor { name } }", nil)

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}
