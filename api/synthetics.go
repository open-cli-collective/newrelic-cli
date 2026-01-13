package api

import "encoding/json"

// ListSyntheticMonitors returns all synthetic monitors
func (c *Client) ListSyntheticMonitors() ([]SyntheticMonitor, error) {
	data, err := c.doRequest("GET", c.SyntheticsURL+"/monitors.json", nil)
	if err != nil {
		return nil, err
	}

	var resp SyntheticsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Monitors, nil
}

// GetSyntheticMonitor returns a specific synthetic monitor by ID
func (c *Client) GetSyntheticMonitor(monitorID string) (*SyntheticMonitor, error) {
	data, err := c.doRequest("GET", c.SyntheticsURL+"/monitors/"+monitorID, nil)
	if err != nil {
		return nil, err
	}

	var monitor SyntheticMonitor
	if err := json.Unmarshal(data, &monitor); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &monitor, nil
}
