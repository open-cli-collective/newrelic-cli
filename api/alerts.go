package api

import (
	"encoding/json"
	"fmt"
)

// ListAlertPolicies returns all alert policies
func (c *Client) ListAlertPolicies() ([]AlertPolicy, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/alerts_policies.json", nil)
	if err != nil {
		return nil, err
	}

	var resp AlertPoliciesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Policies, nil
}

// GetAlertPolicy returns a specific alert policy by ID
func (c *Client) GetAlertPolicy(policyID string) (*AlertPolicy, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
	}

	query := `
	query($accountId: Int!, $policyId: ID!) {
		actor {
			account(id: $accountId) {
				alerts {
					policy(id: $policyId) {
						id
						name
						incidentPreference
					}
				}
			}
		}
	}`

	accountID, _ := c.GetAccountIDInt()
	variables := map[string]interface{}{
		"accountId": accountID,
		"policyId":  policyID,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	// Navigate the nested response safely
	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	account, ok := safeMap(actor["account"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing account"}
	}
	alerts, ok := safeMap(account["alerts"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing alerts"}
	}
	policy, ok := safeMap(alerts["policy"])
	if !ok || policy == nil {
		return nil, fmt.Errorf("policy not found")
	}

	return &AlertPolicy{
		ID:                 safeInt(policy["id"]),
		Name:               safeString(policy["name"]),
		IncidentPreference: safeString(policy["incidentPreference"]),
	}, nil
}
