package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// apmApplicationFragment selects the APM-specific fields used to build an
// Application from an entity search result.
const apmApplicationFragment = `... on ApmApplicationEntityOutline {
							applicationId
							language
							reporting
							alertSeverity
							lastReportingChangeAt
						}`

// applicationFromEntity maps a NerdGraph APM entity payload to an Application.
func applicationFromEntity(entity map[string]interface{}) Application {
	return Application{
		ID:             safeInt(entity["applicationId"]),
		GUID:           EntityGUID(safeString(entity["guid"])),
		Name:           safeString(entity["name"]),
		Language:       safeString(entity["language"]),
		HealthStatus:   safeString(entity["alertSeverity"]),
		Reporting:      entity["reporting"] == true,
		LastReportedAt: formatEpochMillis(safeInt64(entity["lastReportingChangeAt"])),
	}
}

// formatEpochMillis renders an epoch-milliseconds value as RFC 3339, or ""
// when unset.
func formatEpochMillis(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.Unix(0, ms*int64(time.Millisecond)).UTC().Format(time.RFC3339)
}

// ListApplications returns all APM applications, via NerdGraph entity search.
// HealthStatus carries the NerdGraph alertSeverity value
// (NOT_ALERTING, WARNING, CRITICAL, NOT_CONFIGURED).
func (c *Client) ListApplications() ([]Application, error) {
	entities, err := c.searchEntitiesRaw("domain = 'APM' AND type = 'APPLICATION'", apmApplicationFragment)
	if err != nil {
		return nil, err
	}

	apps := make([]Application, 0, len(entities))
	for _, entity := range entities {
		apps = append(apps, applicationFromEntity(entity))
	}
	return apps, nil
}

// GetApplication returns one APM application. The identifier may be a numeric
// application ID, an application name, or an entity GUID.
func (c *Client) GetApplication(identifier string) (*Application, error) {
	guid, err := c.ResolveAppGUID(identifier)
	if err != nil {
		return nil, err
	}

	query := `
	query($guid: EntityGuid!) {
		actor {
			entity(guid: $guid) {
				guid
				name
				... on ApmApplicationEntity {
					applicationId
					language
					reporting
					alertSeverity
					lastReportingChangeAt
				}
			}
		}
	}`

	result, err := c.NerdGraphQuery(query, map[string]interface{}{"guid": guid.String()})
	if err != nil {
		return nil, err
	}

	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	entity, ok := safeMap(actor["entity"])
	if !ok || entity == nil {
		return nil, fmt.Errorf("application not found: %s", identifier)
	}

	app := applicationFromEntity(entity)
	return &app, nil
}

// ListApplicationMetrics returns the metric names reported by an application
// over the past day, via NRQL (SELECT uniques(metricName) FROM Metric).
// Requires a configured account ID. The identifier may be a numeric
// application ID, an application name, or an entity GUID.
func (c *Client) ListApplicationMetrics(identifier string) ([]Metric, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
	}

	app, err := c.GetApplication(identifier)
	if err != nil {
		return nil, err
	}

	appName := strings.ReplaceAll(app.Name, `'`, `\'`)
	nrql := fmt.Sprintf(
		"SELECT uniques(metricName, 10000) FROM Metric WHERE appName = '%s' SINCE 1 day ago",
		appName,
	)

	result, err := c.QueryNRQL(nrql)
	if err != nil {
		return nil, err
	}

	if len(result.Results) == 0 {
		return nil, nil
	}

	names, ok := safeSlice(result.Results[0]["uniques.metricName"])
	if !ok {
		return nil, nil
	}

	metrics := make([]Metric, 0, len(names))
	for _, n := range names {
		if name, ok := n.(string); ok {
			metrics = append(metrics, Metric{Name: name})
		}
	}
	return metrics, nil
}

// ListApplicationsREST returns all APM applications via the REST v2 API.
//
// Deprecated: New Relic is replacing the REST v2 API with NerdGraph and does
// only minimal maintenance on it; see
// https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/.
// Use ListApplications, which is NerdGraph-backed.
func (c *Client) ListApplicationsREST() ([]Application, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications.json", nil)
	if err != nil {
		return nil, err
	}

	var resp ApplicationsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Applications, nil
}

// GetApplicationREST returns one APM application by numeric ID via the REST
// v2 API.
//
// Deprecated: New Relic is replacing the REST v2 API with NerdGraph and does
// only minimal maintenance on it; see
// https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/.
// Use GetApplication, which is NerdGraph-backed.
func (c *Client) GetApplicationREST(appID string) (*Application, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+".json", nil)
	if err != nil {
		return nil, err
	}

	var resp ApplicationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &resp.Application, nil
}

// ListApplicationMetricsREST returns metric names via the REST v2 API.
//
// Deprecated: New Relic is replacing the REST v2 API with NerdGraph and does
// only minimal maintenance on it; see
// https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/.
// Use ListApplicationMetrics, which queries FROM Metric via NRQL.
func (c *Client) ListApplicationMetricsREST(appID string) ([]Metric, error) {
	data, err := c.doRequest("GET", c.BaseURL+"/applications/"+appID+"/metrics.json", nil)
	if err != nil {
		return nil, err
	}

	var resp MetricsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Metrics, nil
}
