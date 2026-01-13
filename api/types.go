package api

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
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	AccountID   int    `json:"accountId"`
	Description string `json:"description,omitempty"`
}

// DashboardPage represents a page within a dashboard
type DashboardPage struct {
	GUID    string            `json:"guid"`
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
	GUID        string          `json:"guid"`
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
	GUID       string            `json:"guid"`
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
