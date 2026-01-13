package api

import "encoding/json"

// ListDeployments returns all deployments for an application
func (c *Client) ListDeployments(appID string) ([]Deployment, error) {
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

// CreateDeployment creates a new deployment marker for an application
func (c *Client) CreateDeployment(appID string, revision, description, user, changelog string) (*Deployment, error) {
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
