package api

import (
	"encoding/json"
	"fmt"
)

// changeTrackingDeploymentFromMap maps a NerdGraph change tracking payload to
// a ChangeTrackingDeployment.
func changeTrackingDeploymentFromMap(m map[string]interface{}) ChangeTrackingDeployment {
	return ChangeTrackingDeployment{
		DeploymentID: safeString(m["deploymentId"]),
		EntityGUID:   EntityGUID(safeString(m["entityGuid"])),
		Version:      safeString(m["version"]),
		Description:  safeString(m["description"]),
		User:         safeString(m["user"]),
		Changelog:    safeString(m["changelog"]),
		Commit:       safeString(m["commit"]),
		TimestampMs:  safeInt64(m["timestamp"]),
	}
}

// ListDeployments returns the deployments recorded for an entity via the
// NerdGraph change tracking API. startMs/endMs bound the search window in
// epoch milliseconds; pass 0 to use the API's default window. limit caps the
// number of results server-side; pass 0 for the API default.
func (c *Client) ListDeployments(guid EntityGUID, startMs, endMs int64, limit int) ([]ChangeTrackingDeployment, error) {
	query := `
	query($guid: EntityGuid!, $filter: ChangeTrackingSearchFilter) {
		actor {
			entity(guid: $guid) {
				deploymentSearch(filter: $filter) {
					results {
						deploymentId
						entityGuid
						version
						description
						user
						changelog
						commit
						timestamp
					}
				}
			}
		}
	}`

	filter := map[string]interface{}{}
	timeWindow := map[string]interface{}{}
	if startMs > 0 {
		timeWindow["startTime"] = startMs
	}
	if endMs > 0 {
		timeWindow["endTime"] = endMs
	}
	if len(timeWindow) > 0 {
		filter["timeWindow"] = timeWindow
	}
	if limit > 0 {
		filter["limit"] = limit
	}

	variables := map[string]interface{}{
		"guid": guid.String(),
	}
	if len(filter) > 0 {
		variables["filter"] = filter
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	entity, ok := safeMap(actor["entity"])
	if !ok || entity == nil {
		return nil, fmt.Errorf("entity not found: %s", guid)
	}
	search, ok := safeMap(entity["deploymentSearch"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing deploymentSearch"}
	}
	results, ok := safeSlice(search["results"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing results"}
	}

	deployments := make([]ChangeTrackingDeployment, 0, len(results))
	for _, r := range results {
		if m, ok := safeMap(r); ok {
			deployments = append(deployments, changeTrackingDeploymentFromMap(m))
		}
	}
	return deployments, nil
}

// CreateDeployment records a deployment via the NerdGraph
// changeTrackingCreateDeployment mutation, the supported replacement for
// REST v2 deployment markers.
func (c *Client) CreateDeployment(input DeploymentInput) (*ChangeTrackingDeployment, error) {
	if input.EntityGUID == "" {
		return nil, fmt.Errorf("entity GUID is required")
	}
	if input.Version == "" {
		return nil, fmt.Errorf("version is required")
	}

	mutation := `
	mutation($deployment: ChangeTrackingDeploymentInput!) {
		changeTrackingCreateDeployment(deployment: $deployment) {
			deploymentId
			entityGuid
			version
			description
			user
			changelog
			commit
			timestamp
		}
	}`

	deployment := map[string]interface{}{
		"entityGuid": input.EntityGUID.String(),
		"version":    input.Version,
	}
	if input.Description != "" {
		deployment["description"] = input.Description
	}
	if input.User != "" {
		deployment["user"] = input.User
	}
	if input.Changelog != "" {
		deployment["changelog"] = input.Changelog
	}
	if input.Commit != "" {
		deployment["commit"] = input.Commit
	}

	result, err := c.NerdGraphQuery(mutation, map[string]interface{}{"deployment": deployment})
	if err != nil {
		return nil, err
	}

	created, ok := safeMap(result["changeTrackingCreateDeployment"])
	if !ok || created == nil {
		return nil, &ResponseError{Message: "unexpected response format: missing changeTrackingCreateDeployment"}
	}

	d := changeTrackingDeploymentFromMap(created)
	return &d, nil
}

// ListDeploymentsREST returns deployment markers for an application via the
// REST v2 API.
//
// Deprecated: New Relic is replacing the REST v2 API with NerdGraph and does
// only minimal maintenance on it; see
// https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/.
// Use ListDeployments, which reads the NerdGraph change tracking API
// (https://docs.newrelic.com/docs/change-tracking/change-tracking-introduction/).
func (c *Client) ListDeploymentsREST(appID string) ([]Deployment, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+"/deployments.json", nil)
	if err != nil {
		return nil, err
	}

	var resp DeploymentsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Deployments, nil
}

// CreateDeploymentREST creates a deployment marker via the REST v2 API.
//
// Deprecated: New Relic is replacing the REST v2 API with NerdGraph and does
// only minimal maintenance on it; REST v2 deployment markers also do not feed
// the change tracking experience. See
// https://docs.newrelic.com/docs/change-tracking/change-tracking-introduction/.
// Use CreateDeployment, which calls changeTrackingCreateDeployment.
func (c *Client) CreateDeploymentREST(appID string, revision, description, user, changelog string) (*Deployment, error) {
	deployment := map[string]interface{}{
		"revision": revision,
	}
	if description != "" {
		deployment["description"] = description
	}
	if user != "" {
		deployment["user"] = user
	}
	if changelog != "" {
		deployment["changelog"] = changelog
	}

	body := map[string]interface{}{
		"deployment": deployment,
	}

	data, err := c.doRequest("POST", c.BaseURL+"/applications/"+appID+"/deployments.json", body)
	if err != nil {
		return nil, err
	}

	var resp DeploymentResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &resp.Deployment, nil
}
