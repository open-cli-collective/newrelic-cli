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

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "deployments_search.json"))

	client := NewTestClient(server)
	deployments, err := client.ListDeployments(EntityGUID(testAppGUID), 0, 0, 0)

	require.NoError(t, err)
	require.Len(t, deployments, 2)

	assert.Equal(t, "dep-001", deployments[0].DeploymentID)
	assert.Equal(t, "v1.2.3", deployments[0].Version)
	assert.Equal(t, "Feature release: new dashboard", deployments[0].Description)
	assert.Equal(t, "deploy-bot", deployments[0].User)
	assert.Equal(t, "abc1234", deployments[0].Commit)
	assert.Equal(t, int64(1704067200000), deployments[0].TimestampMs)

	server.AssertLastPath(t, "/graphql")
	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "deploymentSearch")
	// No filter argument when no bounds are given.
	assert.NotContains(t, string(req.Body), "timeWindow")
}

func TestListDeployments_WithFilter(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "deployments_search.json"))

	client := NewTestClient(server)
	_, err := client.ListDeployments(EntityGUID(testAppGUID), 1703980800000, 1704067200000, 5)

	require.NoError(t, err)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "startTime")
	assert.Contains(t, string(req.Body), "endTime")
	assert.Contains(t, string(req.Body), `"limit":5`)
}

func TestListDeployments_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entity": {"deploymentSearch": {"results": []}}}}
	}`)

	client := NewTestClient(server)
	deployments, err := client.ListDeployments(EntityGUID(testAppGUID), 0, 0, 0)

	require.NoError(t, err)
	assert.Empty(t, deployments)
}

func TestListDeployments_EntityNotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"actor": {"entity": null}}
	}`)

	client := NewTestClient(server)
	_, err := client.ListDeployments(EntityGUID(testAppGUID), 0, 0, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "entity not found")
}

func TestCreateDeployment(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "deployment_ct_created.json"))

	client := NewTestClient(server)
	deployment, err := client.CreateDeployment(DeploymentInput{
		EntityGUID:  EntityGUID(testAppGUID),
		Version:     "v1.2.4",
		Description: "New deployment",
		User:        "test-user",
		Commit:      "abc1234",
	})

	require.NoError(t, err)
	require.NotNil(t, deployment)

	assert.Equal(t, "dep-003", deployment.DeploymentID)
	assert.Equal(t, "v1.2.4", deployment.Version)
	assert.Equal(t, int64(1704153600000), deployment.TimestampMs)

	server.AssertLastPath(t, "/graphql")
	server.AssertLastMethod(t, "POST")

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "changeTrackingCreateDeployment")
	assert.Contains(t, string(req.Body), `"version":"v1.2.4"`)
	assert.Contains(t, string(req.Body), `"description":"New deployment"`)
	assert.Contains(t, string(req.Body), `"commit":"abc1234"`)
}

func TestCreateDeployment_MinimalFields(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, `{
		"data": {"changeTrackingCreateDeployment": {
			"deploymentId": "dep-004",
			"entityGuid": "`+testAppGUID+`",
			"version": "v1.0.0",
			"timestamp": 1704153600000
		}}
	}`)

	client := NewTestClient(server)
	deployment, err := client.CreateDeployment(DeploymentInput{
		EntityGUID: EntityGUID(testAppGUID),
		Version:    "v1.0.0",
	})

	require.NoError(t, err)
	require.NotNil(t, deployment)
	assert.Equal(t, "v1.0.0", deployment.Version)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), `"version":"v1.0.0"`)
	assert.NotContains(t, string(req.Body), `"description"`)
}

func TestCreateDeployment_MissingFields(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)

	_, err := client.CreateDeployment(DeploymentInput{Version: "v1.0.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entity GUID is required")

	_, err = client.CreateDeployment(DeploymentInput{EntityGUID: EntityGUID(testAppGUID)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version is required")

	server.AssertRequestCount(t, 0)
}

func TestListDeploymentsREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "deployments_list.json"))

	client := NewTestClient(server)
	deployments, err := client.ListDeploymentsREST("12345678")

	require.NoError(t, err)
	require.Len(t, deployments, 2)

	assert.Equal(t, 9001, deployments[0].ID)
	assert.Equal(t, "v1.2.3", deployments[0].Revision)

	server.AssertLastPath(t, "/applications/12345678/deployments.json")
}

func TestCreateDeploymentREST(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusCreated, LoadTestFixture(t, "deployment_created.json"))

	client := NewTestClient(server)
	deployment, err := client.CreateDeploymentREST("12345678", "v1.2.4", "New deployment", "test-user", "")

	require.NoError(t, err)
	require.NotNil(t, deployment)

	assert.Equal(t, 9002, deployment.ID)
	assert.Equal(t, "v1.2.4", deployment.Revision)

	server.AssertLastPath(t, "/applications/12345678/deployments.json")
	server.AssertLastMethod(t, "POST")
}
