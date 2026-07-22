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

// ResolveAppGUID resolves an application identifier — a numeric application
// ID, an application name, or an entity GUID — to the entity GUID that
// NerdGraph mutations and entity queries require.
func (c *Client) ResolveAppGUID(identifier string) (EntityGUID, error) {
	if IsValidEntityGUID(identifier) {
		guid := EntityGUID(identifier)
		if _, err := guid.AppID(); err == nil {
			return guid, nil
		}
	}

	if isNumeric(identifier) {
		entities, err := c.searchEntitiesRaw("domain = 'APM' AND type = 'APPLICATION'", apmApplicationFragment)
		if err != nil {
			return "", fmt.Errorf("failed to search for application: %w", err)
		}
		for _, entity := range entities {
			if fmt.Sprintf("%d", safeInt(entity["applicationId"])) == identifier {
				return EntityGUID(safeString(entity["guid"])), nil
			}
		}
		return "", fmt.Errorf("no APM application found with ID: %s", identifier)
	}

	query := fmt.Sprintf("name = '%s' AND domain = 'APM' AND type = 'APPLICATION'", identifier)
	entities, err := c.SearchEntities(query)
	if err != nil {
		return "", fmt.Errorf("failed to search for application: %w", err)
	}
	if len(entities) == 0 {
		return "", fmt.Errorf("no APM application found with name: %s", identifier)
	}
	if len(entities) > 1 {
		return "", fmt.Errorf("multiple applications found with name '%s', please use --guid or app ID", identifier)
	}
	return entities[0].GUID, nil
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
