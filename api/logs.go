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
