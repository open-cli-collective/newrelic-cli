package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/piekstra/newrelic-cli/internal/keychain"
)

// Client is the New Relic API client
type Client struct {
	APIKey       string
	AccountID    string
	Region       string
	BaseURL      string
	NerdGraphURL string
	SyntheticsURL string
	HTTPClient   *http.Client
}

// New creates a new New Relic client
func New() (*Client, error) {
	apiKey, err := keychain.GetAPIKey()
	if err != nil {
		return nil, err
	}

	accountID, _ := keychain.GetAccountID() // Optional
	region := keychain.GetRegion()

	c := &Client{
		APIKey:    apiKey,
		AccountID: accountID,
		Region:    region,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Set URLs based on region
	if region == "EU" {
		c.BaseURL = "https://api.eu.newrelic.com/v2"
		c.NerdGraphURL = "https://api.eu.newrelic.com/graphql"
		c.SyntheticsURL = "https://synthetics.eu.newrelic.com/synthetics/api/v3"
	} else {
		c.BaseURL = "https://api.newrelic.com/v2"
		c.NerdGraphURL = "https://api.newrelic.com/graphql"
		c.SyntheticsURL = "https://synthetics.newrelic.com/synthetics/api/v3"
	}

	return c, nil
}

// doRequest performs an HTTP request with authentication
func (c *Client) doRequest(method, url string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Api-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// --- Application Methods ---

type Application struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Language       string `json:"language"`
	HealthStatus   string `json:"health_status"`
	Reporting      bool   `json:"reporting"`
	LastReportedAt string `json:"last_reported_at"`
}

type ApplicationsResponse struct {
	Applications []Application `json:"applications"`
}

type ApplicationResponse struct {
	Application Application `json:"application"`
}

func (c *Client) ListApplications() ([]Application, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications.json", nil)
	if err != nil {
		return nil, err
	}

	var resp ApplicationsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Applications, nil
}

func (c *Client) GetApplication(appID string) (*Application, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+".json", nil)
	if err != nil {
		return nil, err
	}

	var resp ApplicationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp.Application, nil
}

// --- Metric Methods ---

type Metric struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type MetricsResponse struct {
	Metrics []Metric `json:"metrics"`
}

func (c *Client) ListApplicationMetrics(appID string) ([]Metric, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+"/metrics.json", nil)
	if err != nil {
		return nil, err
	}

	var resp MetricsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Metrics, nil
}

// --- Alert Policy Methods ---

type AlertPolicy struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	IncidentPreference string `json:"incident_preference"`
}

type AlertPoliciesResponse struct {
	Policies []AlertPolicy `json:"policies"`
}

func (c *Client) ListAlertPolicies() ([]AlertPolicy, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/alerts_policies.json", nil)
	if err != nil {
		return nil, err
	}

	var resp AlertPoliciesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Policies, nil
}

func (c *Client) GetAlertPolicy(policyID string) (*AlertPolicy, error) {
	if c.AccountID == "" {
		return nil, fmt.Errorf("account ID required for this operation")
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

	accountID, _ := strconv.Atoi(c.AccountID)
	variables := map[string]interface{}{
		"accountId": accountID,
		"policyId":  policyID,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	// Parse the nested response
	actor, ok := result["actor"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}
	account, ok := actor["account"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}
	alerts, ok := account["alerts"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}
	policy, ok := alerts["policy"].(map[string]interface{})
	if !ok || policy == nil {
		return nil, fmt.Errorf("policy not found")
	}

	return &AlertPolicy{
		ID:                 int(policy["id"].(float64)),
		Name:               policy["name"].(string),
		IncidentPreference: policy["incidentPreference"].(string),
	}, nil
}

// --- Dashboard Methods ---

type Dashboard struct {
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	AccountID   int    `json:"accountId"`
	Description string `json:"description,omitempty"`
}

type DashboardPage struct {
	GUID    string            `json:"guid"`
	Name    string            `json:"name"`
	Widgets []DashboardWidget `json:"widgets"`
}

type DashboardWidget struct {
	ID            string                 `json:"id"`
	Title         string                 `json:"title"`
	Visualization map[string]interface{} `json:"visualization"`
	Configuration map[string]interface{} `json:"rawConfiguration"`
}

type DashboardDetail struct {
	GUID        string          `json:"guid"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Permissions string          `json:"permissions"`
	Pages       []DashboardPage `json:"pages"`
}

func (c *Client) ListDashboards() ([]Dashboard, error) {
	if c.AccountID == "" {
		return nil, fmt.Errorf("account ID required for this operation")
	}

	query := `
	query($query: String!) {
		actor {
			entitySearch(query: $query) {
				results {
					entities {
						guid
						name
						accountId
						... on DashboardEntityOutline {
							dashboardParentGuid
						}
					}
				}
			}
		}
	}`

	variables := map[string]interface{}{
		"query": fmt.Sprintf("type = 'DASHBOARD' AND accountId = %s", c.AccountID),
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	// Parse the nested response
	actor := result["actor"].(map[string]interface{})
	entitySearch := actor["entitySearch"].(map[string]interface{})
	results := entitySearch["results"].(map[string]interface{})
	entities := results["entities"].([]interface{})

	dashboards := make([]Dashboard, 0, len(entities))
	for _, e := range entities {
		entity := e.(map[string]interface{})
		dashboards = append(dashboards, Dashboard{
			GUID:      entity["guid"].(string),
			Name:      entity["name"].(string),
			AccountID: int(entity["accountId"].(float64)),
		})
	}

	return dashboards, nil
}

func (c *Client) GetDashboard(guid string) (*DashboardDetail, error) {
	query := `
	query($guid: EntityGuid!) {
		actor {
			entity(guid: $guid) {
				... on DashboardEntity {
					guid
					name
					description
					permissions
					pages {
						guid
						name
						widgets {
							id
							title
							visualization { id }
							rawConfiguration
						}
					}
				}
			}
		}
	}`

	variables := map[string]interface{}{
		"guid": guid,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	actor := result["actor"].(map[string]interface{})
	entity := actor["entity"].(map[string]interface{})

	if entity == nil {
		return nil, fmt.Errorf("dashboard not found")
	}

	dashboard := &DashboardDetail{
		GUID:        entity["guid"].(string),
		Name:        entity["name"].(string),
		Permissions: entity["permissions"].(string),
	}

	if desc, ok := entity["description"].(string); ok {
		dashboard.Description = desc
	}

	// Parse pages
	if pages, ok := entity["pages"].([]interface{}); ok {
		for _, p := range pages {
			page := p.(map[string]interface{})
			dp := DashboardPage{
				GUID: page["guid"].(string),
				Name: page["name"].(string),
			}

			if widgets, ok := page["widgets"].([]interface{}); ok {
				for _, w := range widgets {
					widget := w.(map[string]interface{})
					dw := DashboardWidget{
						ID:    widget["id"].(string),
						Title: widget["title"].(string),
					}
					if viz, ok := widget["visualization"].(map[string]interface{}); ok {
						dw.Visualization = viz
					}
					if conf, ok := widget["rawConfiguration"].(map[string]interface{}); ok {
						dw.Configuration = conf
					}
					dp.Widgets = append(dp.Widgets, dw)
				}
			}
			dashboard.Pages = append(dashboard.Pages, dp)
		}
	}

	return dashboard, nil
}

// --- User Methods ---

type User struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Email                string   `json:"email"`
	Type                 string   `json:"type"`
	Groups               []string `json:"groups,omitempty"`
	AuthenticationDomain string   `json:"authentication_domain,omitempty"`
}

func (c *Client) ListUsers() ([]User, error) {
	query := `
	{
		actor {
			organization {
				userManagement {
					authenticationDomains {
						authenticationDomains {
							id
							name
							users {
								users {
									id
									name
									email
									type { displayName }
								}
							}
						}
					}
				}
			}
		}
	}`

	result, err := c.NerdGraphQuery(query, nil)
	if err != nil {
		return nil, err
	}

	// Navigate the nested structure
	actor := result["actor"].(map[string]interface{})
	org := actor["organization"].(map[string]interface{})
	userMgmt := org["userManagement"].(map[string]interface{})
	authDomains := userMgmt["authenticationDomains"].(map[string]interface{})
	domains := authDomains["authenticationDomains"].([]interface{})

	var users []User
	for _, d := range domains {
		domain := d.(map[string]interface{})
		domainName := domain["name"].(string)
		usersData := domain["users"].(map[string]interface{})
		usersList := usersData["users"].([]interface{})

		for _, u := range usersList {
			user := u.(map[string]interface{})
			userType := ""
			if t, ok := user["type"].(map[string]interface{}); ok {
				userType = t["displayName"].(string)
			}
			users = append(users, User{
				ID:                   user["id"].(string),
				Name:                 user["name"].(string),
				Email:                user["email"].(string),
				Type:                 userType,
				AuthenticationDomain: domainName,
			})
		}
	}

	return users, nil
}

func (c *Client) GetUser(userID string) (*User, error) {
	query := `
	{
		actor {
			organization {
				userManagement {
					authenticationDomains {
						authenticationDomains {
							name
							users {
								users {
									id
									name
									email
									type { displayName }
									groups { groups { displayName } }
								}
							}
						}
					}
				}
			}
		}
	}`

	result, err := c.NerdGraphQuery(query, nil)
	if err != nil {
		return nil, err
	}

	// Navigate and find the user
	actor := result["actor"].(map[string]interface{})
	org := actor["organization"].(map[string]interface{})
	userMgmt := org["userManagement"].(map[string]interface{})
	authDomains := userMgmt["authenticationDomains"].(map[string]interface{})
	domains := authDomains["authenticationDomains"].([]interface{})

	for _, d := range domains {
		domain := d.(map[string]interface{})
		domainName := domain["name"].(string)
		usersData := domain["users"].(map[string]interface{})
		usersList := usersData["users"].([]interface{})

		for _, u := range usersList {
			user := u.(map[string]interface{})
			if user["id"].(string) == userID {
				userType := ""
				if t, ok := user["type"].(map[string]interface{}); ok {
					userType = t["displayName"].(string)
				}

				var groups []string
				if g, ok := user["groups"].(map[string]interface{}); ok {
					if groupsList, ok := g["groups"].([]interface{}); ok {
						for _, grp := range groupsList {
							group := grp.(map[string]interface{})
							groups = append(groups, group["displayName"].(string))
						}
					}
				}

				return &User{
					ID:                   user["id"].(string),
					Name:                 user["name"].(string),
					Email:                user["email"].(string),
					Type:                 userType,
					Groups:               groups,
					AuthenticationDomain: domainName,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("user not found")
}

// --- Entity Search ---

type Entity struct {
	GUID       string            `json:"guid"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	EntityType string            `json:"entityType"`
	Domain     string            `json:"domain"`
	AccountID  int               `json:"accountId"`
	Tags       map[string]string `json:"tags,omitempty"`
}

func (c *Client) SearchEntities(queryStr string) ([]Entity, error) {
	query := `
	query($query: String!) {
		actor {
			entitySearch(query: $query) {
				results {
					entities {
						guid
						name
						type
						entityType
						domain
						accountId
						tags { key values }
					}
				}
			}
		}
	}`

	variables := map[string]interface{}{
		"query": queryStr,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	actor := result["actor"].(map[string]interface{})
	entitySearch := actor["entitySearch"].(map[string]interface{})
	results := entitySearch["results"].(map[string]interface{})
	entitiesData := results["entities"].([]interface{})

	entities := make([]Entity, 0, len(entitiesData))
	for _, e := range entitiesData {
		entity := e.(map[string]interface{})
		ent := Entity{
			GUID:       entity["guid"].(string),
			Name:       entity["name"].(string),
			AccountID:  int(entity["accountId"].(float64)),
		}
		if t, ok := entity["type"].(string); ok {
			ent.Type = t
		}
		if et, ok := entity["entityType"].(string); ok {
			ent.EntityType = et
		}
		if d, ok := entity["domain"].(string); ok {
			ent.Domain = d
		}
		entities = append(entities, ent)
	}

	return entities, nil
}

// --- Synthetics Methods ---

type SyntheticMonitor struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Frequency int    `json:"frequency"`
	Status    string `json:"status"`
	URI       string `json:"uri,omitempty"`
}

type SyntheticsResponse struct {
	Monitors []SyntheticMonitor `json:"monitors"`
}

func (c *Client) ListSyntheticMonitors() ([]SyntheticMonitor, error) {
	data, err := c.doRequest("GET", c.SyntheticsURL+"/monitors.json", nil)
	if err != nil {
		return nil, err
	}

	var resp SyntheticsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Monitors, nil
}

func (c *Client) GetSyntheticMonitor(monitorID string) (*SyntheticMonitor, error) {
	data, err := c.doRequest("GET", c.SyntheticsURL+"/monitors/"+monitorID, nil)
	if err != nil {
		return nil, err
	}

	var monitor SyntheticMonitor
	if err := json.Unmarshal(data, &monitor); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &monitor, nil
}

// --- Deployment Methods ---

type Deployment struct {
	ID          int    `json:"id"`
	Revision    string `json:"revision"`
	Description string `json:"description,omitempty"`
	User        string `json:"user,omitempty"`
	Timestamp   string `json:"timestamp"`
}

type DeploymentsResponse struct {
	Deployments []Deployment `json:"deployments"`
}

type DeploymentResponse struct {
	Deployment Deployment `json:"deployment"`
}

func (c *Client) ListDeployments(appID string) ([]Deployment, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+"/deployments.json", nil)
	if err != nil {
		return nil, err
	}

	var resp DeploymentsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Deployments, nil
}

func (c *Client) CreateDeployment(appID string, revision, description, user, changelog string) (*Deployment, error) {
	deployment := map[string]interface{}{
		"revision": revision,
	}
	if description != "" {
		deployment["description"] = description
	}
	if user != "" {
		deployment["user"] = user
	}
	if changelog != "" {
		deployment["changelog"] = changelog
	}

	body := map[string]interface{}{
		"deployment": deployment,
	}

	data, err := c.doRequest("POST", c.BaseURL+"/applications/"+appID+"/deployments.json", body)
	if err != nil {
		return nil, err
	}

	var resp DeploymentResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp.Deployment, nil
}

// --- NRQL Methods ---

type NRQLResult struct {
	Results []map[string]interface{} `json:"results"`
}

func (c *Client) QueryNRQL(nrql string) (*NRQLResult, error) {
	if c.AccountID == "" {
		return nil, fmt.Errorf("account ID required for NRQL queries")
	}

	query := `
	query($accountId: Int!, $nrql: Nrql!) {
		actor {
			account(id: $accountId) {
				nrql(query: $nrql) {
					results
				}
			}
		}
	}`

	accountID, _ := strconv.Atoi(c.AccountID)
	variables := map[string]interface{}{
		"accountId": accountID,
		"nrql":      nrql,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	actor := result["actor"].(map[string]interface{})
	account := actor["account"].(map[string]interface{})
	nrqlResult := account["nrql"].(map[string]interface{})
	results := nrqlResult["results"].([]interface{})

	nrqlResults := &NRQLResult{
		Results: make([]map[string]interface{}, len(results)),
	}
	for i, r := range results {
		nrqlResults.Results[i] = r.(map[string]interface{})
	}

	return nrqlResults, nil
}

// --- NerdGraph Methods ---

type NerdGraphRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type NerdGraphResponse struct {
	Data   map[string]interface{} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

func (c *Client) NerdGraphQuery(query string, variables map[string]interface{}) (map[string]interface{}, error) {
	reqBody := NerdGraphRequest{
		Query:     query,
		Variables: variables,
	}

	data, err := c.doRequest("POST", c.NerdGraphURL, reqBody)
	if err != nil {
		return nil, err
	}

	var resp NerdGraphResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", resp.Errors[0].Message)
	}

	return resp.Data, nil
}

// --- Log Parsing Methods ---

type LogParsingRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Grok        string `json:"grok"`
	Lucene      string `json:"lucene"`
	NRQL        string `json:"nrql"`
	UpdatedAt   string `json:"updatedAt"`
}

func (c *Client) ListLogParsingRules() ([]LogParsingRule, error) {
	if c.AccountID == "" {
		return nil, fmt.Errorf("account ID required for this operation")
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

	accountID, _ := strconv.Atoi(c.AccountID)
	variables := map[string]interface{}{
		"accountId": accountID,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	actor := result["actor"].(map[string]interface{})
	account := actor["account"].(map[string]interface{})
	logConfigs := account["logConfigurations"].(map[string]interface{})
	rulesData := logConfigs["parsingRules"].([]interface{})

	var rules []LogParsingRule
	for _, r := range rulesData {
		rule := r.(map[string]interface{})
		if deleted, ok := rule["deleted"].(bool); ok && deleted {
			continue
		}
		rules = append(rules, LogParsingRule{
			ID:          rule["id"].(string),
			Description: rule["description"].(string),
			Enabled:     rule["enabled"].(bool),
			Grok:        rule["grok"].(string),
			Lucene:      safeString(rule["lucene"]),
			NRQL:        rule["nrql"].(string),
			UpdatedAt:   rule["updatedAt"].(string),
		})
	}

	return rules, nil
}

func (c *Client) CreateLogParsingRule(description, grok, nrql string, enabled bool, lucene string) (*LogParsingRule, error) {
	if c.AccountID == "" {
		return nil, fmt.Errorf("account ID required for this operation")
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

	accountID, _ := strconv.Atoi(c.AccountID)
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

	createResult := result["logConfigurationsCreateParsingRule"].(map[string]interface{})
	if errors, ok := createResult["errors"].([]interface{}); ok && len(errors) > 0 {
		errMsg := errors[0].(map[string]interface{})["message"].(string)
		return nil, fmt.Errorf("failed to create rule: %s", errMsg)
	}

	rule := createResult["rule"].(map[string]interface{})
	return &LogParsingRule{
		ID:          rule["id"].(string),
		Description: rule["description"].(string),
		Enabled:     rule["enabled"].(bool),
		Grok:        rule["grok"].(string),
		Lucene:      safeString(rule["lucene"]),
		NRQL:        rule["nrql"].(string),
		UpdatedAt:   rule["updatedAt"].(string),
	}, nil
}

func (c *Client) DeleteLogParsingRule(ruleID string) error {
	if c.AccountID == "" {
		return fmt.Errorf("account ID required for this operation")
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

	deleteResult := result["logConfigurationsDeleteParsingRule"].(map[string]interface{})
	if errors, ok := deleteResult["errors"].([]interface{}); ok && len(errors) > 0 {
		errMsg := errors[0].(map[string]interface{})["message"].(string)
		return fmt.Errorf("failed to delete rule: %s", errMsg)
	}

	return nil
}

// Helper function
func safeString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// RequireAccountID validates that account ID is configured
func (c *Client) RequireAccountID() error {
	if c.AccountID == "" {
		return fmt.Errorf("account ID required - run 'newrelic-cli config set-account-id' or set NEWRELIC_ACCOUNT_ID")
	}
	return nil
}

// GetAccountIDInt returns the account ID as an integer
func (c *Client) GetAccountIDInt() (int, error) {
	if err := c.RequireAccountID(); err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(c.AccountID)
	if err != nil {
		return 0, fmt.Errorf("invalid account ID: %s", c.AccountID)
	}
	return id, nil
}
