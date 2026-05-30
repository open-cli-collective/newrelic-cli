package api

import (
	"fmt"
)

func (c *Client) ResolveAppID(identifier string) (string, error) {
	if isNumeric(identifier) {
		return identifier, nil
	}

	if IsValidEntityGUID(identifier) {
		guid := EntityGUID(identifier)
		appID, err := guid.AppID()
		if err == nil {
			return appID, nil
		}
	}

	return c.resolveAppName(identifier)
}

func (c *Client) resolveAppName(name string) (string, error) {
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

	entity := entities[0]
	appID, err := entity.GUID.AppID()
	if err != nil {
		return "", fmt.Errorf("failed to extract app ID from entity: %w", err)
	}

	return appID, nil
}

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
