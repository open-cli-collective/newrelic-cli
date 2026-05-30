package api

import "encoding/json"

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

type SyntheticMonitorInput struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Frequency int      `json:"frequency"`
	Status    string   `json:"status"`
	URI       string   `json:"uri,omitempty"`
	Locations []string `json:"locations,omitempty"`
	Script    string   `json:"script,omitempty"`
}

func (c *Client) CreateSyntheticMonitor(input *SyntheticMonitorInput) (*SyntheticMonitor, error) {
	body := map[string]interface{}{
		"name":      input.Name,
		"type":      input.Type,
		"frequency": input.Frequency,
		"status":    input.Status,
	}

	if input.URI != "" {
		body["uri"] = input.URI
	}
	if len(input.Locations) > 0 {
		body["locations"] = input.Locations
	}

	data, err := c.doRequest("POST", c.SyntheticsURL+"/monitors", body)
	if err != nil {
		return nil, err
	}

	var monitor SyntheticMonitor
	if err := json.Unmarshal(data, &monitor); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &monitor, nil
}

func (c *Client) UpdateSyntheticMonitor(monitorID string, input *SyntheticMonitorInput) (*SyntheticMonitor, error) {
	body := map[string]interface{}{
		"name":      input.Name,
		"frequency": input.Frequency,
		"status":    input.Status,
	}

	if input.URI != "" {
		body["uri"] = input.URI
	}
	if len(input.Locations) > 0 {
		body["locations"] = input.Locations
	}

	data, err := c.doRequest("PUT", c.SyntheticsURL+"/monitors/"+monitorID, body)
	if err != nil {
		return nil, err
	}

	var monitor SyntheticMonitor
	if err := json.Unmarshal(data, &monitor); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &monitor, nil
}

func (c *Client) DeleteSyntheticMonitor(monitorID string) error {
	_, err := c.doRequest("DELETE", c.SyntheticsURL+"/monitors/"+monitorID, nil)
	return err
}
