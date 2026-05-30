package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryNRQL(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "nrql_results.json"))

	client := NewTestClient(server)
	result, err := client.QueryNRQL("SELECT count(*) FROM Transaction FACET name")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Results, 3)

	assert.Equal(t, float64(1500), result.Results[0]["count"])
	assert.Equal(t, "WebTransaction/Controller/api/v1/users", result.Results[0]["facet"])

	server.AssertLastPath(t, "/graphql")
	server.AssertLastMethod(t, "POST")

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "nrql")
}

func TestQueryNRQL_EmptyResults(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"account": {
					"nrql": {
						"results": []
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	result, err := client.QueryNRQL("SELECT count(*) FROM Transaction WHERE 1=0")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Results)
}

func TestQueryNRQL_NoAccountID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	client.AccountID = ""

	_, err := client.QueryNRQL("SELECT count(*) FROM Transaction")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountIDRequired)
}

func TestQueryNRQL_GraphQLError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "graphql_error.json"))

	client := NewTestClient(server)
	_, err := client.QueryNRQL("INVALID QUERY")

	require.Error(t, err)
}

func TestQueryNRQL_HTTPError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "unauthorized"}`)

	client := NewTestClient(server)
	_, err := client.QueryNRQL("SELECT count(*) FROM Transaction")

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestQueryNRQL_InvalidResponse(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.QueryNRQL("SELECT count(*) FROM Transaction")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response format")
}
