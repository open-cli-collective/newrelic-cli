package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListDeployments(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "deployments_list.json"))

	client := NewTestClient(server)
	deployments, err := client.ListDeployments("12345678")

	require.NoError(t, err)
	require.Len(t, deployments, 2)

	assert.Equal(t, 9001, deployments[0].ID)
	assert.Equal(t, "v1.2.3", deployments[0].Revision)
	assert.Equal(t, "Feature release: new dashboard", deployments[0].Description)
	assert.Equal(t, "deploy-bot", deployments[0].User)

	server.AssertLastPath(t, "/applications/12345678/deployments.json")
}

func TestListDeployments_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{"deployments": []}`)

	client := NewTestClient(server)
	deployments, err := client.ListDeployments("12345678")

	require.NoError(t, err)
	assert.Empty(t, deployments)
}

func TestListDeployments_AppNotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusNotFound, `{"error": "application not found"}`)

	client := NewTestClient(server)
	_, err := client.ListDeployments("99999")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestCreateDeployment(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusCreated, LoadTestFixture(t, "deployment_created.json"))

	client := NewTestClient(server)
	deployment, err := client.CreateDeployment("12345678", "v1.2.4", "New deployment", "test-user", "")

	require.NoError(t, err)
	require.NotNil(t, deployment)

	assert.Equal(t, 9002, deployment.ID)
	assert.Equal(t, "v1.2.4", deployment.Revision)

	server.AssertLastPath(t, "/applications/12345678/deployments.json")
	server.AssertLastMethod(t, "POST")

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), `"revision":"v1.2.4"`)
	assert.Contains(t, string(req.Body), `"description":"New deployment"`)
}

func TestCreateDeployment_MinimalFields(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusCreated, `{"deployment": {"id": 1, "revision": "v1.0.0", "timestamp": "2024-01-01T00:00:00Z"}}`)

	client := NewTestClient(server)
	deployment, err := client.CreateDeployment("12345678", "v1.0.0", "", "", "")

	require.NoError(t, err)
	require.NotNil(t, deployment)
	assert.Equal(t, "v1.0.0", deployment.Revision)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), `"revision":"v1.0.0"`)
	assert.NotContains(t, string(req.Body), `"description"`)
}

func TestCreateDeployment_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusBadRequest, `{"error": "invalid revision"}`)

	client := NewTestClient(server)
	_, err := client.CreateDeployment("12345678", "", "", "", "")

	require.Error(t, err)
}
