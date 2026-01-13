package api

import "encoding/json"

// ListApplications returns all APM applications
func (c *Client) ListApplications() ([]Application, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications.json", nil)
	if err != nil {
		return nil, err
	}

	var resp ApplicationsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Applications, nil
}

// GetApplication returns a specific application by ID
func (c *Client) GetApplication(appID string) (*Application, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+".json", nil)
	if err != nil {
		return nil, err
	}

	var resp ApplicationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &resp.Application, nil
}

// ListApplicationMetrics returns available metrics for an application
func (c *Client) ListApplicationMetrics(appID string) ([]Metric, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+"/metrics.json", nil)
	if err != nil {
		return nil, err
	}

	var resp MetricsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Metrics, nil
}
