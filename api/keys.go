// Package api - keys.go provides methods for managing New Relic API keys
// via the NerdGraph apiAccess API (keySearch, apiAccessCreateKeys,
// apiAccessUpdateKeys, apiAccessDeleteKeys).
package api

import "fmt"

// apiAccessKeyFields is the common set of GraphQL fields for API access keys
const apiAccessKeyFields = `
	id
	name
	notes
	type
	key
	... on ApiAccessIngestKey {
		ingestType
	}
`

// SearchAPIKeys searches for API keys with optional type and account filters
func (c *Client) SearchAPIKeys(keyTypes []string, accountID int) ([]ApiAccessKey, error) {
	// Build the types array
	typesStr := "USER, INGEST"
	if len(keyTypes) > 0 {
		typesStr = ""
		for i, t := range keyTypes {
			if i > 0 {
				typesStr += ", "
			}
			typesStr += t
		}
	}

	// Build scope clause
	scopeClause := ""
	if accountID > 0 {
		scopeClause = fmt.Sprintf(", scope: {accountIds: %d}", accountID)
	}

	query := fmt.Sprintf(`
	{
		actor {
			apiAccess {
				keySearch(query: {types: [%s]%s}) {
					keys {
						%s
					}
				}
			}
		}
	}`, typesStr, scopeClause, apiAccessKeyFields)

	result, err := c.NerdGraphQuery(query, nil)
	if err != nil {
		return nil, err
	}

	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	apiAccess, ok := safeMap(actor["apiAccess"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing apiAccess"}
	}
	keySearch, ok := safeMap(apiAccess["keySearch"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing keySearch"}
	}
	keysData, ok := safeSlice(keySearch["keys"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing keys"}
	}

	var keys []ApiAccessKey
	for _, k := range keysData {
		keys = append(keys, parseApiAccessKey(k))
	}

	return keys, nil
}

// GetAPIAccessKey retrieves a specific API key by ID and type
func (c *Client) GetAPIAccessKey(keyID string, keyType string) (*ApiAccessKey, error) {
	query := fmt.Sprintf(`
	{
		actor {
			apiAccess {
				key(id: "%s", keyType: %s) {
					%s
				}
			}
		}
	}`, keyID, keyType, apiAccessKeyFields)

	result, err := c.NerdGraphQuery(query, nil)
	if err != nil {
		return nil, err
	}

	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	apiAccess, ok := safeMap(actor["apiAccess"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing apiAccess"}
	}
	keyData, ok := safeMap(apiAccess["key"])
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	key := parseApiAccessKey(keyData)
	return &key, nil
}

// FindAPIAccessKey retrieves a key by ID, trying USER then INGEST type
func (c *Client) FindAPIAccessKey(keyID string) (*ApiAccessKey, error) {
	key, err := c.GetAPIAccessKey(keyID, "USER")
	if err == nil {
		return key, nil
	}
	return c.GetAPIAccessKey(keyID, "INGEST")
}

// GetCurrentUserID returns the current user's ID from NerdGraph
func (c *Client) GetCurrentUserID() (int, error) {
	query := `{ actor { user { id } } }`

	result, err := c.NerdGraphQuery(query, nil)
	if err != nil {
		return 0, err
	}

	actor, ok := safeMap(result["actor"])
	if !ok {
		return 0, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	user, ok := safeMap(actor["user"])
	if !ok {
		return 0, &ResponseError{Message: "unexpected response format: missing user"}
	}

	return safeInt(user["id"]), nil
}

// CreateUserAPIKey creates a new user API key
func (c *Client) CreateUserAPIKey(accountID, userID int, name, notes string) (*ApiAccessKey, error) {
	mutation := fmt.Sprintf(`
	mutation {
		apiAccessCreateKeys(keys: {user: [{accountId: %d, userId: %d, name: "%s", notes: "%s"}]}) {
			createdKeys {
				%s
			}
			errors {
				message
				type
			}
		}
	}`, accountID, userID, escapeGraphQL(name), escapeGraphQL(notes), apiAccessKeyFields)

	return c.execCreateKeys(mutation)
}

// CreateIngestAPIKey creates a new ingest API key (LICENSE or BROWSER)
func (c *Client) CreateIngestAPIKey(accountID int, ingestType, name, notes string) (*ApiAccessKey, error) {
	mutation := fmt.Sprintf(`
	mutation {
		apiAccessCreateKeys(keys: {ingest: [{accountId: %d, ingestType: %s, name: "%s", notes: "%s"}]}) {
			createdKeys {
				%s
			}
			errors {
				message
				type
			}
		}
	}`, accountID, ingestType, escapeGraphQL(name), escapeGraphQL(notes), apiAccessKeyFields)

	return c.execCreateKeys(mutation)
}

func (c *Client) execCreateKeys(mutation string) (*ApiAccessKey, error) {
	result, err := c.NerdGraphQuery(mutation, nil)
	if err != nil {
		return nil, err
	}

	createResult, ok := safeMap(result["apiAccessCreateKeys"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	if errors, ok := safeSlice(createResult["errors"]); ok && len(errors) > 0 {
		errMap, _ := safeMap(errors[0])
		return nil, fmt.Errorf("failed to create key: %s", safeString(errMap["message"]))
	}

	createdKeys, ok := safeSlice(createResult["createdKeys"])
	if !ok || len(createdKeys) == 0 {
		return nil, &ResponseError{Message: "unexpected response format: no created keys returned"}
	}

	key := parseApiAccessKey(createdKeys[0])
	return &key, nil
}

// UpdateAPIAccessKey updates an existing API key's name and/or notes
func (c *Client) UpdateAPIAccessKey(keyID string, keyType string, update ApiAccessKeyUpdate) (*ApiAccessKey, error) {
	// Build the update fields
	fields := fmt.Sprintf(`keyId: "%s"`, keyID)
	if update.Name != nil {
		fields += fmt.Sprintf(`, name: "%s"`, escapeGraphQL(*update.Name))
	}
	if update.Notes != nil {
		fields += fmt.Sprintf(`, notes: "%s"`, escapeGraphQL(*update.Notes))
	}

	// Use the appropriate key type bucket
	var keyBucket string
	switch keyType {
	case "USER":
		keyBucket = "user"
	case "INGEST":
		keyBucket = "ingest"
	default:
		return nil, fmt.Errorf("invalid key type: %s (must be USER or INGEST)", keyType)
	}

	mutation := fmt.Sprintf(`
	mutation {
		apiAccessUpdateKeys(keys: {%s: [{%s}]}) {
			updatedKeys {
				%s
			}
			errors {
				message
			}
		}
	}`, keyBucket, fields, apiAccessKeyFields)

	result, err := c.NerdGraphQuery(mutation, nil)
	if err != nil {
		return nil, err
	}

	updateResult, ok := safeMap(result["apiAccessUpdateKeys"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	if errors, ok := safeSlice(updateResult["errors"]); ok && len(errors) > 0 {
		errMap, _ := safeMap(errors[0])
		return nil, fmt.Errorf("failed to update key: %s", safeString(errMap["message"]))
	}

	updatedKeys, ok := safeSlice(updateResult["updatedKeys"])
	if !ok || len(updatedKeys) == 0 {
		return nil, &ResponseError{Message: "unexpected response format: no updated keys returned"}
	}

	key := parseApiAccessKey(updatedKeys[0])
	return &key, nil
}

// DeleteAPIAccessKeys deletes API keys by their IDs, separated by type
func (c *Client) DeleteAPIAccessKeys(userKeyIDs, ingestKeyIDs []string) ([]string, error) {
	// Build the keys argument
	parts := []string{}
	if len(userKeyIDs) > 0 {
		ids := formatStringSlice(userKeyIDs)
		parts = append(parts, fmt.Sprintf("userKeyIds: [%s]", ids))
	}
	if len(ingestKeyIDs) > 0 {
		ids := formatStringSlice(ingestKeyIDs)
		parts = append(parts, fmt.Sprintf("ingestKeyIds: [%s]", ids))
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("no key IDs provided")
	}

	keysArg := ""
	for i, p := range parts {
		if i > 0 {
			keysArg += ", "
		}
		keysArg += p
	}

	mutation := fmt.Sprintf(`
	mutation {
		apiAccessDeleteKeys(keys: {%s}) {
			deletedKeys {
				id
			}
			errors {
				message
			}
		}
	}`, keysArg)

	result, err := c.NerdGraphQuery(mutation, nil)
	if err != nil {
		return nil, err
	}

	deleteResult, ok := safeMap(result["apiAccessDeleteKeys"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	if errors, ok := safeSlice(deleteResult["errors"]); ok && len(errors) > 0 {
		errMap, _ := safeMap(errors[0])
		return nil, fmt.Errorf("failed to delete keys: %s", safeString(errMap["message"]))
	}

	deletedKeys, ok := safeSlice(deleteResult["deletedKeys"])
	if !ok {
		return nil, nil
	}

	var deletedIDs []string
	for _, k := range deletedKeys {
		km, ok := safeMap(k)
		if ok {
			deletedIDs = append(deletedIDs, safeString(km["id"]))
		}
	}

	return deletedIDs, nil
}

// parseApiAccessKey converts a NerdGraph response map to an ApiAccessKey
func parseApiAccessKey(v interface{}) ApiAccessKey {
	m, ok := safeMap(v)
	if !ok {
		return ApiAccessKey{}
	}
	return ApiAccessKey{
		ID:         safeString(m["id"]),
		Name:       safeString(m["name"]),
		Notes:      safeString(m["notes"]),
		Type:       safeString(m["type"]),
		Key:        safeString(m["key"]),
		IngestType: safeString(m["ingestType"]),
	}
}

// escapeGraphQL escapes special characters for GraphQL string values
func escapeGraphQL(s string) string {
	result := ""
	for _, c := range s {
		switch c {
		case '"':
			result += `\"`
		case '\\':
			result += `\\`
		case '\n':
			result += `\n`
		case '\r':
			result += `\r`
		case '\t':
			result += `\t`
		default:
			result += string(c)
		}
	}
	return result
}

// formatStringSlice formats a string slice as GraphQL string array items
func formatStringSlice(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf(`"%s"`, s)
	}
	return result
}
