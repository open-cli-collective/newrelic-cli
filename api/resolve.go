package api

import (
	"fmt"
)

// ResolveAppID resolves an application identifier to a numeric app ID.
// It accepts:
// - A numeric app ID (returned as-is)
// - An entity GUID (extracts the app ID)
// - An application name (looks up via entity search)
func (c *Client) ResolveAppID(identifier string) (string, error) {
	// Check if it's already a numeric ID
	if isNumeric(identifier) {
		return identifier, nil
	}

	// Check if it looks like a base64-encoded GUID
	if IsValidEntityGUID(identifier) {
		guid := EntityGUID(identifier)
		appID, err := guid.AppID()
		if err == nil {
			return appID, nil
		}
		// If GUID parsing fails, fall through to name search
	}

	// Try to resolve as an application name
	return c.resolveAppName(identifier)
}

// resolveAppName looks up an application by name and returns its ID
func (c *Client) resolveAppName(name string) (string, error) {
	// Search for APM applications with the exact name
	query := fmt.Sprintf("name = '%s' AND domain = 'APM' AND type = 'APPLICATION'", name)
	entities, err := c.SearchEntities(query)
	if err != nil {
		return "", fmt.Errorf("failed to search for application: %w", err)
	}

	if len(entities) == 0 {
		return "", fmt.Errorf("no APM application found with name: %s", name)
	}

	if len(entities) > 1 {
		return "", fmt.Errorf("multiple applications found with name '%s', please use --guid or app ID", name)
	}

	// Extract app ID from the entity GUID
	entity := entities[0]
	appID, err := entity.GUID.AppID()
	if err != nil {
		return "", fmt.Errorf("failed to extract app ID from entity: %w", err)
	}

	return appID, nil
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
