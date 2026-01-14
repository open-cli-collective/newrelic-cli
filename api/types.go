package api

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// EntityGUID is a New Relic entity identifier.
// Unlike standard UUIDs, Entity GUIDs are base64-encoded strings
// with the format: version|domain|type|id
//
// Example: MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg= decodes to 1|APM|APPLICATION|12345678
type EntityGUID string

// String returns the GUID as a string
func (g EntityGUID) String() string {
	return string(g)
}

// Parse decodes the GUID and returns its components.
// Returns version, domain, entityType, entityID, and any error.
func (g EntityGUID) Parse() (version, domain, entityType, entityID string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(string(g))
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid GUID format: %w", err)
	}

	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return "", "", "", "", fmt.Errorf("invalid GUID format: expected 4 parts, got %d", len(parts))
	}

	return parts[0], parts[1], parts[2], parts[3], nil
}

// Validate checks if the GUID has valid base64 encoding and structure.
func (g EntityGUID) Validate() error {
	_, _, _, _, err := g.Parse()
	return err
}

// Domain returns the entity domain (APM, VIZ, INFRA, etc.)
func (g EntityGUID) Domain() (string, error) {
	_, domain, _, _, err := g.Parse()
	return domain, err
}

// EntityType returns the entity type (APPLICATION, DASHBOARD, HOST, etc.)
func (g EntityGUID) EntityType() (string, error) {
	_, _, entityType, _, err := g.Parse()
	return entityType, err
}

// EntityID returns the entity's numeric identifier.
func (g EntityGUID) EntityID() (string, error) {
	_, _, _, entityID, err := g.Parse()
	return entityID, err
}

// AppID extracts the numeric application ID from an APM application GUID.
// Returns an error if the GUID is not for an APM application.
func (g EntityGUID) AppID() (string, error) {
	_, domain, entityType, entityID, err := g.Parse()
	if err != nil {
		return "", err
	}

	if domain != "APM" || entityType != "APPLICATION" {
		return "", fmt.Errorf("GUID is not for an APM application (domain=%s, type=%s)", domain, entityType)
	}

	return entityID, nil
}

// IsValidEntityGUID checks if a string could be a valid base64-encoded entity GUID.
// This is a quick heuristic check, not a full validation.
func IsValidEntityGUID(s string) bool {
	// GUIDs are typically 40+ characters and contain only base64 characters
	if len(s) < 40 {
		return false
	}

	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, c := range s {
		if !strings.ContainsRune(base64Chars, c) {
			return false
		}
	}
	return true
}

// APIKey is a New Relic User API key.
// Valid keys start with "NRAK-" and are typically 40+ characters.
type APIKey string

// NewAPIKey creates an APIKey after validation.
// Returns the key, a warning (if the key doesn't have NRAK- prefix), and any error.
func NewAPIKey(s string) (APIKey, string, error) {
	if s == "" {
		return "", "", fmt.Errorf("API key cannot be empty")
	}
	if len(s) < 16 {
		return "", "", fmt.Errorf("API key too short: minimum 16 characters")
	}

	var warning string
	if !strings.HasPrefix(s, "NRAK-") {
		warning = "API key does not start with 'NRAK-' (expected for User API keys)"
	}

	return APIKey(s), warning, nil
}

// String returns the API key as a string.
func (k APIKey) String() string {
	return string(k)
}

// Validate checks if the API key has a valid format.
// Returns a warning (if the key doesn't have NRAK- prefix) and any error.
func (k APIKey) Validate() (warning string, err error) {
	if k == "" {
		return "", fmt.Errorf("API key cannot be empty")
	}
	if len(k) < 16 {
		return "", fmt.Errorf("API key too short: minimum 16 characters")
	}
	if !k.HasNRAKPrefix() {
		return "API key does not start with 'NRAK-' (expected for User API keys)", nil
	}
	return "", nil
}

// HasNRAKPrefix returns true if the API key starts with "NRAK-".
func (k APIKey) HasNRAKPrefix() bool {
	return strings.HasPrefix(string(k), "NRAK-")
}

// AccountID is a New Relic account identifier.
// Internally stored as a string but always represents a positive integer.
type AccountID string

// NewAccountID creates an AccountID after validation.
// Returns an error if the value is not a valid positive integer.
func NewAccountID(s string) (AccountID, error) {
	if s == "" {
		return "", fmt.Errorf("account ID cannot be empty")
	}

	num, err := strconv.Atoi(s)
	if err != nil {
		return "", fmt.Errorf("invalid account ID %q: must be numeric", s)
	}

	if num <= 0 {
		return "", fmt.Errorf("invalid account ID %q: must be a positive number", s)
	}

	return AccountID(s), nil
}

// String returns the account ID as a string.
func (a AccountID) String() string {
	return string(a)
}

// Int returns the account ID as an integer.
// This assumes the AccountID was created via NewAccountID and is valid.
// For unchecked AccountID values, use Validate() first.
func (a AccountID) Int() int {
	num, _ := strconv.Atoi(string(a))
	return num
}

// Validate checks if the account ID is a valid positive integer.
func (a AccountID) Validate() error {
	if a == "" {
		return fmt.Errorf("account ID cannot be empty")
	}

	num, err := strconv.Atoi(string(a))
	if err != nil {
		return fmt.Errorf("invalid account ID %q: must be numeric", string(a))
	}

	if num <= 0 {
		return fmt.Errorf("invalid account ID %q: must be a positive number", string(a))
	}

	return nil
}

// IsEmpty returns true if the account ID is empty.
func (a AccountID) IsEmpty() bool {
	return a == ""
}

// Application represents a New Relic APM application
type Application struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Language       string `json:"language"`
	HealthStatus   string `json:"health_status"`
	Reporting      bool   `json:"reporting"`
	LastReportedAt string `json:"last_reported_at"`
}

// ApplicationsResponse is the API response for listing applications
type ApplicationsResponse struct {
	Applications []Application `json:"applications"`
}

// ApplicationResponse is the API response for getting a single application
type ApplicationResponse struct {
	Application Application `json:"application"`
}

// Metric represents an application metric
type Metric struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// MetricsResponse is the API response for listing metrics
type MetricsResponse struct {
	Metrics []Metric `json:"metrics"`
}

// AlertPolicy represents an alert policy
type AlertPolicy struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	IncidentPreference string `json:"incident_preference"`
}

// AlertPoliciesResponse is the API response for listing alert policies
type AlertPoliciesResponse struct {
	Policies []AlertPolicy `json:"policies"`
}

// Dashboard represents a New Relic dashboard
type Dashboard struct {
	GUID        EntityGUID `json:"guid"`
	Name        string     `json:"name"`
	AccountID   int        `json:"accountId"`
	Description string     `json:"description,omitempty"`
}

// DashboardPage represents a page within a dashboard
type DashboardPage struct {
	GUID    EntityGUID        `json:"guid"`
	Name    string            `json:"name"`
	Widgets []DashboardWidget `json:"widgets"`
}

// DashboardWidget represents a widget on a dashboard page
type DashboardWidget struct {
	ID            string                 `json:"id"`
	Title         string                 `json:"title"`
	Visualization map[string]interface{} `json:"visualization"`
	Configuration map[string]interface{} `json:"rawConfiguration"`
}

// DashboardDetail represents detailed dashboard information
type DashboardDetail struct {
	GUID        EntityGUID      `json:"guid"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Permissions string          `json:"permissions"`
	Pages       []DashboardPage `json:"pages"`
}

// User represents a New Relic user
type User struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Email                string   `json:"email"`
	Type                 string   `json:"type"`
	Groups               []string `json:"groups,omitempty"`
	AuthenticationDomain string   `json:"authentication_domain,omitempty"`
}

// Entity represents a New Relic entity
type Entity struct {
	GUID       EntityGUID        `json:"guid"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	EntityType string            `json:"entityType"`
	Domain     string            `json:"domain"`
	AccountID  int               `json:"accountId"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// SyntheticMonitor represents a synthetic monitor
type SyntheticMonitor struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Frequency int    `json:"frequency"`
	Status    string `json:"status"`
	URI       string `json:"uri,omitempty"`
}

// SyntheticsResponse is the API response for listing synthetic monitors
type SyntheticsResponse struct {
	Monitors []SyntheticMonitor `json:"monitors"`
}

// Deployment represents a deployment marker
type Deployment struct {
	ID          int    `json:"id"`
	Revision    string `json:"revision"`
	Description string `json:"description,omitempty"`
	User        string `json:"user,omitempty"`
	Timestamp   string `json:"timestamp"`
}

// DeploymentsResponse is the API response for listing deployments
type DeploymentsResponse struct {
	Deployments []Deployment `json:"deployments"`
}

// DeploymentResponse is the API response for creating a deployment
type DeploymentResponse struct {
	Deployment Deployment `json:"deployment"`
}

// NRQLResult represents the result of an NRQL query
type NRQLResult struct {
	Results []map[string]interface{} `json:"results"`
}

// LogParsingRule represents a log parsing rule
type LogParsingRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Grok        string `json:"grok"`
	Lucene      string `json:"lucene"`
	NRQL        string `json:"nrql"`
	UpdatedAt   string `json:"updatedAt"`
}

// NerdGraphRequest represents a GraphQL request
type NerdGraphRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// NerdGraphResponse represents a GraphQL response
type NerdGraphResponse struct {
	Data   map[string]interface{} `json:"data"`
	Errors []NerdGraphError       `json:"errors,omitempty"`
}

// NerdGraphError represents a GraphQL error
type NerdGraphError struct {
	Message string `json:"message"`
}
