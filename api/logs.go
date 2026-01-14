package api

import "fmt"

// ListLogParsingRules returns all log parsing rules for the account
func (c *Client) ListLogParsingRules() ([]LogParsingRule, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
	}

	query := `
	query($accountId: Int!) {
		actor {
			account(id: $accountId) {
				logConfigurations {
					parsingRules {
						id
						description
						enabled
						grok
						lucene
						nrql
						updatedAt
						deleted
					}
				}
			}
		}
	}`

	accountID, _ := c.GetAccountIDInt()
	variables := map[string]interface{}{
		"accountId": accountID,
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
	logConfigs, ok := safeMap(account["logConfigurations"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing logConfigurations"}
	}
	rulesData, ok := safeSlice(logConfigs["parsingRules"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing parsingRules"}
	}

	var rules []LogParsingRule
	for _, r := range rulesData {
		rule, ok := safeMap(r)
		if !ok {
			continue
		}
		// Skip deleted rules
		if deleted, ok := rule["deleted"].(bool); ok && deleted {
			continue
		}
		rules = append(rules, LogParsingRule{
			ID:          safeString(rule["id"]),
			Description: safeString(rule["description"]),
			Enabled:     rule["enabled"] == true,
			Grok:        safeString(rule["grok"]),
			Lucene:      safeString(rule["lucene"]),
			NRQL:        safeString(rule["nrql"]),
			UpdatedAt:   safeString(rule["updatedAt"]),
		})
	}

	return rules, nil
}

// CreateLogParsingRule creates a new log parsing rule
func (c *Client) CreateLogParsingRule(description, grok, nrql string, enabled bool, lucene string) (*LogParsingRule, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
	}

	mutation := `
	mutation($accountId: Int!, $rule: LogConfigurationsParsingRuleConfiguration!) {
		logConfigurationsCreateParsingRule(accountId: $accountId, rule: $rule) {
			rule {
				id
				description
				enabled
				grok
				lucene
				nrql
				updatedAt
			}
			errors { message type }
		}
	}`

	accountID, _ := c.GetAccountIDInt()
	variables := map[string]interface{}{
		"accountId": accountID,
		"rule": map[string]interface{}{
			"description": description,
			"enabled":     enabled,
			"grok":        grok,
			"lucene":      lucene,
			"nrql":        nrql,
		},
	}

	result, err := c.NerdGraphQuery(mutation, variables)
	if err != nil {
		return nil, err
	}

	createResult, ok := safeMap(result["logConfigurationsCreateParsingRule"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	if errors, ok := safeSlice(createResult["errors"]); ok && len(errors) > 0 {
		errMap, _ := safeMap(errors[0])
		return nil, fmt.Errorf("failed to create rule: %s", safeString(errMap["message"]))
	}

	rule, ok := safeMap(createResult["rule"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing rule"}
	}

	return &LogParsingRule{
		ID:          safeString(rule["id"]),
		Description: safeString(rule["description"]),
		Enabled:     rule["enabled"] == true,
		Grok:        safeString(rule["grok"]),
		Lucene:      safeString(rule["lucene"]),
		NRQL:        safeString(rule["nrql"]),
		UpdatedAt:   safeString(rule["updatedAt"]),
	}, nil
}

// GetLogParsingRule returns a specific log parsing rule by ID
func (c *Client) GetLogParsingRule(ruleID string) (*LogParsingRule, error) {
	rules, err := c.ListLogParsingRules()
	if err != nil {
		return nil, err
	}

	for _, r := range rules {
		if r.ID == ruleID {
			return &r, nil
		}
	}

	return nil, fmt.Errorf("rule not found: %s", ruleID)
}

// LogParsingRuleUpdate contains the fields that can be updated on a log parsing rule.
// All fields are optional - only non-nil values will be included in the update.
type LogParsingRuleUpdate struct {
	Description *string
	Enabled     *bool
	Grok        *string
	Lucene      *string
	NRQL        *string
}

// UpdateLogParsingRule updates an existing log parsing rule.
// The NerdGraph API requires all fields to be provided, so this function
// fetches the existing rule first and merges the updates.
func (c *Client) UpdateLogParsingRule(ruleID string, update LogParsingRuleUpdate) (*LogParsingRule, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
	}

	// Fetch existing rule to get current values
	existing, err := c.GetLogParsingRule(ruleID)
	if err != nil {
		return nil, err
	}

	// Merge updates with existing values
	description := existing.Description
	if update.Description != nil {
		description = *update.Description
	}
	enabled := existing.Enabled
	if update.Enabled != nil {
		enabled = *update.Enabled
	}
	grok := existing.Grok
	if update.Grok != nil {
		grok = *update.Grok
	}
	lucene := existing.Lucene
	if update.Lucene != nil {
		lucene = *update.Lucene
	}
	nrql := existing.NRQL
	if update.NRQL != nil {
		nrql = *update.NRQL
	}

	mutation := `
	mutation($accountId: Int!, $rule: LogConfigurationsParsingRuleConfiguration!, $id: ID!) {
		logConfigurationsUpdateParsingRule(accountId: $accountId, rule: $rule, id: $id) {
			rule {
				id
				description
				enabled
				grok
				lucene
				nrql
				updatedAt
			}
			errors { message type }
		}
	}`

	accountID, _ := c.GetAccountIDInt()
	variables := map[string]interface{}{
		"accountId": accountID,
		"rule": map[string]interface{}{
			"description": description,
			"enabled":     enabled,
			"grok":        grok,
			"lucene":      lucene,
			"nrql":        nrql,
		},
		"id": ruleID,
	}

	result, err := c.NerdGraphQuery(mutation, variables)
	if err != nil {
		return nil, err
	}

	updateResult, ok := safeMap(result["logConfigurationsUpdateParsingRule"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	if errors, ok := safeSlice(updateResult["errors"]); ok && len(errors) > 0 {
		errMap, _ := safeMap(errors[0])
		return nil, fmt.Errorf("failed to update rule: %s", safeString(errMap["message"]))
	}

	rule, ok := safeMap(updateResult["rule"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing rule"}
	}

	return &LogParsingRule{
		ID:          safeString(rule["id"]),
		Description: safeString(rule["description"]),
		Enabled:     rule["enabled"] == true,
		Grok:        safeString(rule["grok"]),
		Lucene:      safeString(rule["lucene"]),
		NRQL:        safeString(rule["nrql"]),
		UpdatedAt:   safeString(rule["updatedAt"]),
	}, nil
}

// DeleteLogParsingRule deletes a log parsing rule
func (c *Client) DeleteLogParsingRule(ruleID string) error {
	if err := c.RequireAccountID(); err != nil {
		return err
	}

	mutation := fmt.Sprintf(`
	mutation {
		logConfigurationsDeleteParsingRule(accountId: %s, id: "%s") {
			errors { message type }
		}
	}`, c.AccountID, ruleID)

	result, err := c.NerdGraphQuery(mutation, nil)
	if err != nil {
		return err
	}

	deleteResult, ok := safeMap(result["logConfigurationsDeleteParsingRule"])
	if !ok {
		return &ResponseError{Message: "unexpected response format"}
	}
	if errors, ok := safeSlice(deleteResult["errors"]); ok && len(errors) > 0 {
		errMap, _ := safeMap(errors[0])
		return fmt.Errorf("failed to delete rule: %s", safeString(errMap["message"]))
	}

	return nil
}
