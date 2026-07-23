package api

import (
	"encoding/json"
	"fmt"
)

// ListAlertPolicies returns all alert policies via the NerdGraph
// policiesSearch query, following pagination cursors. Requires a configured
// account ID.
func (c *Client) ListAlertPolicies() ([]AlertPolicy, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
	}

	query := `
	query($accountId: Int!, $cursor: String) {
		actor {
			account(id: $accountId) {
				alerts {
					policiesSearch(cursor: $cursor) {
						nextCursor
						policies {
							id
							name
							incidentPreference
						}
					}
				}
			}
		}
	}`

	accountID, err := c.GetAccountIDInt()
	if err != nil {
		return nil, err
	}

	var all []AlertPolicy
	var cursor interface{}

	for {
		variables := map[string]interface{}{
			"accountId": accountID,
			"cursor":    cursor,
		}

		result, err := c.NerdGraphQuery(query, variables)
		if err != nil {
			return nil, err
		}

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
		policiesSearch, ok := safeMap(alerts["policiesSearch"])
		if !ok {
			return nil, &ResponseError{Message: "unexpected response format: missing policiesSearch"}
		}
		policiesData, ok := safeSlice(policiesSearch["policies"])
		if !ok {
			return nil, &ResponseError{Message: "unexpected response format: missing policies"}
		}

		for _, p := range policiesData {
			policy, ok := safeMap(p)
			if !ok {
				continue
			}
			all = append(all, AlertPolicy{
				ID:                 safeIDInt(policy["id"]),
				Name:               safeString(policy["name"]),
				IncidentPreference: safeString(policy["incidentPreference"]),
			})
		}

		next := safeString(policiesSearch["nextCursor"])
		if next == "" {
			return all, nil
		}
		cursor = next
	}
}

// GetAlertPolicy returns one alert policy by ID via NerdGraph. Requires a
// configured account ID.
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

	accountID, err := c.GetAccountIDInt()
	if err != nil {
		return nil, err
	}
	variables := map[string]interface{}{
		"accountId": accountID,
		"policyId":  policyID,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

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
		ID:                 safeIDInt(policy["id"]),
		Name:               safeString(policy["name"]),
		IncidentPreference: safeString(policy["incidentPreference"]),
	}, nil
}

// ListAlertPoliciesREST returns all alert policies via the REST v2 API.
//
// Deprecated: New Relic is replacing the REST v2 API with NerdGraph and does
// only minimal maintenance on it; see
// https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/.
// Use ListAlertPolicies, which is NerdGraph-backed.
func (c *Client) ListAlertPoliciesREST() ([]AlertPolicy, error) {
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
