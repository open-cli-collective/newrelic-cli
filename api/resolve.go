package api

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseGUID extracts components from a New Relic entity GUID.
// GUIDs are base64-encoded strings with format: {accountId}|{domain}|{type}|{entityId}
// For APM applications, the entityId is the numeric app ID.
func ParseGUID(guid string) (accountID, domain, entityType, entityID string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(guid)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid GUID format: %w", err)
	}

	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return "", "", "", "", fmt.Errorf("invalid GUID format: expected 4 parts, got %d", len(parts))
	}

	return parts[0], parts[1], parts[2], parts[3], nil
}

// ExtractAppIDFromGUID extracts the numeric application ID from an entity GUID.
// Returns an error if the GUID is not for an APM application.
func ExtractAppIDFromGUID(guid string) (string, error) {
	_, domain, entityType, entityID, err := ParseGUID(guid)
	if err != nil {
		return "", err
	}

	if domain != "APM" || entityType != "APPLICATION" {
		return "", fmt.Errorf("GUID is not for an APM application (domain=%s, type=%s)", domain, entityType)
	}

	return entityID, nil
}

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
	if looksLikeGUID(identifier) {
		appID, err := ExtractAppIDFromGUID(identifier)
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
	appID, err := ExtractAppIDFromGUID(entity.GUID)
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

// base64Chars contains all valid base64 characters
const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

// looksLikeGUID checks if a string could be a base64-encoded GUID
func looksLikeGUID(s string) bool {
	// GUIDs are typically 40+ characters and contain only base64 characters
	if len(s) < 40 {
		return false
	}

	for _, c := range s {
		if !strings.ContainsRune(base64Chars, c) {
			return false
		}
	}
	return true
}
