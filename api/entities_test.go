package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchEntities(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "entity_search.json"))

	client := NewTestClient(server)
	entities, err := client.SearchEntities("name LIKE 'My%'")

	require.NoError(t, err)
	require.Len(t, entities, 2)

	// Verify first entity (APM application)
	assert.Equal(t, EntityGUID("MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg="), entities[0].GUID)
	assert.Equal(t, "My Application", entities[0].Name)
	assert.Equal(t, "APPLICATION", entities[0].Type)
	assert.Equal(t, "APM_APPLICATION_ENTITY", entities[0].EntityType)
	assert.Equal(t, "APM", entities[0].Domain)
	assert.Equal(t, 12345, entities[0].AccountID)

	// Verify second entity (Infrastructure host)
	assert.Equal(t, "web-server-01", entities[1].Name)
	assert.Equal(t, "HOST", entities[1].Type)
	assert.Equal(t, "INFRA", entities[1].Domain)

	// Verify GraphQL endpoint and query variable
	server.AssertLastPath(t, "/graphql")
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "entitySearch")
}

func TestSearchEntities_Empty(t *testing.T) {
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
	entities, err := client.SearchEntities("name = 'nonexistent'")

	require.NoError(t, err)
	assert.Empty(t, entities)
}

func TestSearchEntities_ByType(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "entity_search.json"))

	client := NewTestClient(server)
	_, err := client.SearchEntities("type = 'APPLICATION'")

	require.NoError(t, err)

	// Verify query was sent correctly
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "APPLICATION")
}

func TestSearchEntities_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "unauthorized"}`)

	client := NewTestClient(server)
	_, err := client.SearchEntities("name LIKE '%'")

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestSearchEntities_GraphQLError(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "graphql_error.json"))

	client := NewTestClient(server)
	_, err := client.SearchEntities("invalid query syntax")

	require.Error(t, err)
}

func TestSearchEntities_InvalidResponse(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.SearchEntities("name LIKE '%'")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response format")
}
