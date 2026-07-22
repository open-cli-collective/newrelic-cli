package api

import (
	"encoding/json"
	"fmt"
	"sort"
)

// syntheticsPeriodByMinutes maps a frequency in minutes to the NerdGraph
// SyntheticsMonitorPeriod enum.
var syntheticsPeriodByMinutes = map[int]string{
	1:    "EVERY_MINUTE",
	5:    "EVERY_5_MINUTES",
	10:   "EVERY_10_MINUTES",
	15:   "EVERY_15_MINUTES",
	30:   "EVERY_30_MINUTES",
	60:   "EVERY_HOUR",
	360:  "EVERY_6_HOURS",
	720:  "EVERY_12_HOURS",
	1440: "EVERY_DAY",
}

// syntheticsPeriodForMinutes converts a frequency in minutes to the
// SyntheticsMonitorPeriod enum value.
func syntheticsPeriodForMinutes(minutes int) (string, error) {
	if period, ok := syntheticsPeriodByMinutes[minutes]; ok {
		return period, nil
	}
	valid := make([]int, 0, len(syntheticsPeriodByMinutes))
	for m := range syntheticsPeriodByMinutes {
		valid = append(valid, m)
	}
	sort.Ints(valid)
	return "", fmt.Errorf("invalid frequency %d: valid values (minutes) are %v", minutes, valid)
}

// syntheticsMinutesForPeriod converts a SyntheticsMonitorPeriod enum value
// back to minutes, or 0 if unknown.
func syntheticsMinutesForPeriod(period string) int {
	for minutes, p := range syntheticsPeriodByMinutes {
		if p == period {
			return minutes
		}
	}
	return 0
}

// syntheticMonitorFields are the SyntheticMonitorEntity(Outline) fields used
// to build a SyntheticMonitor.
const syntheticMonitorFields = `monitorId
							monitorType
							period
							monitoredUrl
							monitorSummary {
								status
							}`

// monitorFromEntity maps a NerdGraph synthetic monitor entity payload to a
// SyntheticMonitor.
func monitorFromEntity(entity map[string]interface{}) SyntheticMonitor {
	status := ""
	if summary, ok := safeMap(entity["monitorSummary"]); ok {
		status = safeString(summary["status"])
	}
	return SyntheticMonitor{
		ID:        safeString(entity["monitorId"]),
		GUID:      EntityGUID(safeString(entity["guid"])),
		Name:      safeString(entity["name"]),
		Type:      safeString(entity["monitorType"]),
		Frequency: safeInt(entity["period"]),
		Status:    status,
		URI:       safeString(entity["monitoredUrl"]),
	}
}

// ListSyntheticMonitors returns all synthetic monitors, via NerdGraph entity
// search.
func (c *Client) ListSyntheticMonitors() ([]SyntheticMonitor, error) {
	entities, err := c.searchEntitiesRaw(
		"domain = 'SYNTH' AND type = 'MONITOR'",
		"... on SyntheticMonitorEntityOutline {\n"+syntheticMonitorFields+"\n}",
	)
	if err != nil {
		return nil, err
	}

	monitors := make([]SyntheticMonitor, 0, len(entities))
	for _, entity := range entities {
		monitors = append(monitors, monitorFromEntity(entity))
	}
	return monitors, nil
}

// findMonitorEntity resolves a monitor identifier — an entity GUID, a monitor
// ID (UUID), or a monitor name — to its entity payload.
func (c *Client) findMonitorEntity(identifier string) (map[string]interface{}, error) {
	if IsValidEntityGUID(identifier) {
		guid := EntityGUID(identifier)
		if domain, err := guid.Domain(); err == nil && domain == "SYNTH" {
			return c.getMonitorEntityByGUID(guid)
		}
	}

	entities, err := c.searchEntitiesRaw(
		"domain = 'SYNTH' AND type = 'MONITOR'",
		"... on SyntheticMonitorEntityOutline {\n"+syntheticMonitorFields+"\n}",
	)
	if err != nil {
		return nil, err
	}

	var nameMatches []map[string]interface{}
	for _, entity := range entities {
		if safeString(entity["monitorId"]) == identifier {
			return entity, nil
		}
		if safeString(entity["name"]) == identifier {
			nameMatches = append(nameMatches, entity)
		}
	}

	switch len(nameMatches) {
	case 0:
		return nil, fmt.Errorf("no synthetic monitor found matching: %s", identifier)
	case 1:
		return nameMatches[0], nil
	default:
		return nil, fmt.Errorf("multiple synthetic monitors named '%s', please use the monitor ID or GUID", identifier)
	}
}

// getMonitorEntityByGUID fetches a synthetic monitor entity by GUID.
func (c *Client) getMonitorEntityByGUID(guid EntityGUID) (map[string]interface{}, error) {
	query := `
	query($guid: EntityGuid!) {
		actor {
			entity(guid: $guid) {
				guid
				name
				... on SyntheticMonitorEntity {
					` + syntheticMonitorFields + `
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
		return nil, fmt.Errorf("synthetic monitor not found: %s", guid)
	}
	return entity, nil
}

// GetSyntheticMonitor returns one synthetic monitor. The identifier may be an
// entity GUID, a monitor ID (UUID), or a monitor name.
func (c *Client) GetSyntheticMonitor(identifier string) (*SyntheticMonitor, error) {
	entity, err := c.findMonitorEntity(identifier)
	if err != nil {
		return nil, err
	}
	monitor := monitorFromEntity(entity)
	return &monitor, nil
}

// SyntheticMonitorRuntime selects the synthetics runtime for browser and
// scripted monitors, e.g. {"runtimeType": "NODE_API",
// "runtimeTypeVersion": "16.10"}. When omitted the API chooses its default
// runtime for new monitors.
type SyntheticMonitorRuntime struct {
	RuntimeType        string `json:"runtimeType"`
	RuntimeTypeVersion string `json:"runtimeTypeVersion"`
	ScriptLanguage     string `json:"scriptLanguage,omitempty"`
}

type SyntheticMonitorInput struct {
	Name      string                   `json:"name"`
	Type      string                   `json:"type"`
	Frequency int                      `json:"frequency"`
	Status    string                   `json:"status"`
	URI       string                   `json:"uri,omitempty"`
	Locations []string                 `json:"locations,omitempty"`
	Script    string                   `json:"script,omitempty"`
	Runtime   *SyntheticMonitorRuntime `json:"runtime,omitempty"`
}

// syntheticsMutationSpec names the NerdGraph mutations and input types for
// one monitor type, plus which optional fields that type accepts.
type syntheticsMutationSpec struct {
	create      string
	createInput string
	update      string
	updateInput string
	usesURI     bool
	usesScript  bool
	usesRuntime bool
}

// syntheticsMutationByType maps a monitor type to its NerdGraph create and
// update mutation and input type names. Only the four monitor types the REST
// API supported are mapped; the newer types (CERT_CHECK, BROKEN_LINKS,
// STEP_MONITOR) have their own NerdGraph mutations and are not yet wrapped.
var syntheticsMutationByType = map[string]syntheticsMutationSpec{
	"SIMPLE": {
		create: "syntheticsCreateSimpleMonitor", createInput: "SyntheticsCreateSimpleMonitorInput",
		update: "syntheticsUpdateSimpleMonitor", updateInput: "SyntheticsUpdateSimpleMonitorInput",
		usesURI: true,
	},
	"BROWSER": {
		create: "syntheticsCreateSimpleBrowserMonitor", createInput: "SyntheticsCreateSimpleBrowserMonitorInput",
		update: "syntheticsUpdateSimpleBrowserMonitor", updateInput: "SyntheticsUpdateSimpleBrowserMonitorInput",
		usesURI: true, usesRuntime: true,
	},
	"SCRIPT_API": {
		create: "syntheticsCreateScriptApiMonitor", createInput: "SyntheticsCreateScriptApiMonitorInput",
		update: "syntheticsUpdateScriptApiMonitor", updateInput: "SyntheticsUpdateScriptApiMonitorInput",
		usesScript: true, usesRuntime: true,
	},
	"SCRIPT_BROWSER": {
		create: "syntheticsCreateScriptBrowserMonitor", createInput: "SyntheticsCreateScriptBrowserMonitorInput",
		update: "syntheticsUpdateScriptBrowserMonitor", updateInput: "SyntheticsUpdateScriptBrowserMonitorInput",
		usesScript: true, usesRuntime: true,
	},
}

// buildMonitorInput assembles the mutation's monitor input from a
// SyntheticMonitorInput. Zero-valued fields are omitted so update mutations
// leave them unchanged.
func buildMonitorInput(input *SyntheticMonitorInput, spec syntheticsMutationSpec) (map[string]interface{}, error) {
	monitor := map[string]interface{}{}

	if input.Name != "" {
		monitor["name"] = input.Name
	}
	if input.Frequency != 0 {
		period, err := syntheticsPeriodForMinutes(input.Frequency)
		if err != nil {
			return nil, err
		}
		monitor["period"] = period
	}
	if input.Status != "" {
		if input.Status != "ENABLED" && input.Status != "DISABLED" {
			return nil, fmt.Errorf("invalid status %q: NerdGraph supports ENABLED or DISABLED (MUTED was REST-only; use alert muting rules instead)", input.Status)
		}
		monitor["status"] = input.Status
	}
	if spec.usesURI && input.URI != "" {
		monitor["uri"] = input.URI
	}
	if spec.usesScript && input.Script != "" {
		monitor["script"] = input.Script
	}
	if len(input.Locations) > 0 {
		monitor["locations"] = map[string]interface{}{"public": input.Locations}
	}
	if spec.usesRuntime && input.Runtime != nil {
		runtime := map[string]interface{}{
			"runtimeType":        input.Runtime.RuntimeType,
			"runtimeTypeVersion": input.Runtime.RuntimeTypeVersion,
		}
		if input.Runtime.ScriptLanguage != "" {
			runtime["scriptLanguage"] = input.Runtime.ScriptLanguage
		}
		monitor["runtime"] = runtime
	}

	return monitor, nil
}

// runMonitorMutation executes a synthetics monitor mutation and returns the
// resulting monitor.
func (c *Client) runMonitorMutation(mutationName, inputType string, extraArg string, extraVal interface{}, monitor map[string]interface{}, usesURI bool) (*SyntheticMonitor, error) {
	fields := "guid id name period status"
	if usesURI {
		fields += " uri"
	}

	var argType string
	switch extraArg {
	case "accountId":
		argType = "Int!"
	case "guid":
		argType = "EntityGuid!"
	default:
		return nil, fmt.Errorf("unsupported mutation argument: %s", extraArg)
	}

	mutation := fmt.Sprintf(`
	mutation($%s: %s, $monitor: %s!) {
		result: %s(%s: $%s, monitor: $monitor) {
			errors {
				description
				type
			}
			monitor {
				%s
			}
		}
	}`, extraArg, argType, inputType, mutationName, extraArg, extraArg, fields)

	data, err := c.NerdGraphQuery(mutation, map[string]interface{}{
		extraArg:  extraVal,
		"monitor": monitor,
	})
	if err != nil {
		return nil, err
	}

	result, ok := safeMap(data["result"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing mutation result"}
	}

	if errs, ok := safeSlice(result["errors"]); ok && len(errs) > 0 {
		if e, ok := safeMap(errs[0]); ok {
			return nil, fmt.Errorf("%s failed: %s (%s)", mutationName, safeString(e["description"]), safeString(e["type"]))
		}
		return nil, fmt.Errorf("%s failed", mutationName)
	}

	created, ok := safeMap(result["monitor"])
	if !ok || created == nil {
		return nil, &ResponseError{Message: "unexpected response format: missing monitor"}
	}

	return &SyntheticMonitor{
		ID:        safeString(created["id"]),
		GUID:      EntityGUID(safeString(created["guid"])),
		Name:      safeString(created["name"]),
		Frequency: syntheticsMinutesForPeriod(safeString(created["period"])),
		Status:    safeString(created["status"]),
		URI:       safeString(created["uri"]),
	}, nil
}

// CreateSyntheticMonitor creates a synthetic monitor via the type-specific
// NerdGraph mutations, which support current synthetics runtimes. Requires a
// configured account ID.
func (c *Client) CreateSyntheticMonitor(input *SyntheticMonitorInput) (*SyntheticMonitor, error) {
	accountID, err := c.GetAccountIDInt()
	if err != nil {
		return nil, err
	}

	spec, ok := syntheticsMutationByType[input.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported monitor type %q: supported types are SIMPLE, BROWSER, SCRIPT_API, SCRIPT_BROWSER", input.Type)
	}

	if spec.usesURI && input.URI == "" {
		return nil, fmt.Errorf("uri is required for %s monitors", input.Type)
	}
	if spec.usesScript && input.Script == "" {
		return nil, fmt.Errorf("script is required for %s monitors", input.Type)
	}
	if len(input.Locations) == 0 {
		return nil, fmt.Errorf("at least one location is required (e.g. AWS_US_EAST_1)")
	}
	if input.Status == "" {
		input.Status = "ENABLED"
	}

	monitor, err := buildMonitorInput(input, spec)
	if err != nil {
		return nil, err
	}

	created, err := c.runMonitorMutation(spec.create, spec.createInput, "accountId", accountID, monitor, spec.usesURI)
	if err != nil {
		return nil, err
	}
	created.Type = input.Type
	return created, nil
}

// UpdateSyntheticMonitor updates a synthetic monitor via the type-specific
// NerdGraph mutations. The identifier may be an entity GUID, a monitor ID
// (UUID), or a monitor name. The monitor type cannot be changed.
func (c *Client) UpdateSyntheticMonitor(identifier string, input *SyntheticMonitorInput) (*SyntheticMonitor, error) {
	entity, err := c.findMonitorEntity(identifier)
	if err != nil {
		return nil, err
	}

	monitorType := safeString(entity["monitorType"])
	spec, ok := syntheticsMutationByType[monitorType]
	if !ok {
		return nil, fmt.Errorf("monitor type %q is not supported for update: supported types are SIMPLE, BROWSER, SCRIPT_API, SCRIPT_BROWSER", monitorType)
	}
	if input.Type != "" && input.Type != monitorType {
		return nil, fmt.Errorf("monitor type cannot be changed (existing type: %s)", monitorType)
	}

	monitor, err := buildMonitorInput(input, spec)
	if err != nil {
		return nil, err
	}

	guid := safeString(entity["guid"])
	updated, err := c.runMonitorMutation(spec.update, spec.updateInput, "guid", guid, monitor, spec.usesURI)
	if err != nil {
		return nil, err
	}
	updated.Type = monitorType
	return updated, nil
}

// DeleteSyntheticMonitor deletes a synthetic monitor via the NerdGraph
// syntheticsDeleteMonitor mutation. The identifier may be an entity GUID, a
// monitor ID (UUID), or a monitor name.
func (c *Client) DeleteSyntheticMonitor(identifier string) error {
	entity, err := c.findMonitorEntity(identifier)
	if err != nil {
		return err
	}
	guid := safeString(entity["guid"])

	mutation := `
	mutation($guid: EntityGuid!) {
		syntheticsDeleteMonitor(guid: $guid) {
			deletedGuid
		}
	}`

	result, err := c.NerdGraphQuery(mutation, map[string]interface{}{"guid": guid})
	if err != nil {
		return err
	}

	deleted, ok := safeMap(result["syntheticsDeleteMonitor"])
	if !ok || safeString(deleted["deletedGuid"]) == "" {
		return &ResponseError{Message: "unexpected response format: missing deletedGuid"}
	}
	return nil
}

// ListSyntheticMonitorsREST lists monitors via the Synthetics REST v3 API.
//
// Deprecated: New Relic has deprecated the Synthetics REST API in favor of
// NerdGraph; it only supports the legacy synthetics runtimes, which are being
// end-of-lifed. See
// https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/administration/synthetics-api/
// and https://docs.newrelic.com/docs/apis/nerdgraph/examples/synthetics-api/overview/.
// Use ListSyntheticMonitors, which is NerdGraph-backed.
func (c *Client) ListSyntheticMonitorsREST() ([]SyntheticMonitor, error) {
	data, err := c.doRequest("GET", c.SyntheticsURL+"/monitors.json", nil)
	if err != nil {
		return nil, err
	}

	var resp SyntheticsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return resp.Monitors, nil
}

// GetSyntheticMonitorREST gets a monitor by UUID via the Synthetics REST v3
// API.
//
// Deprecated: New Relic has deprecated the Synthetics REST API in favor of
// NerdGraph; see
// https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/administration/synthetics-api/.
// Use GetSyntheticMonitor, which is NerdGraph-backed.
func (c *Client) GetSyntheticMonitorREST(monitorID string) (*SyntheticMonitor, error) {
	data, err := c.doRequest("GET", c.SyntheticsURL+"/monitors/"+monitorID, nil)
	if err != nil {
		return nil, err
	}

	var monitor SyntheticMonitor
	if err := json.Unmarshal(data, &monitor); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &monitor, nil
}

// CreateSyntheticMonitorREST creates a monitor via the Synthetics REST v3
// API.
//
// Deprecated: the Synthetics REST API can only create monitors on the legacy
// synthetics runtimes, and New Relic has blocked new legacy-runtime monitors
// since August 26, 2024 — this call fails or degrades on current accounts.
// See
// https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/administration/synthetics-api/.
// Use CreateSyntheticMonitor, which uses the runtime-capable NerdGraph
// mutations.
func (c *Client) CreateSyntheticMonitorREST(input *SyntheticMonitorInput) (*SyntheticMonitor, error) {
	body := map[string]interface{}{
		"name":      input.Name,
		"type":      input.Type,
		"frequency": input.Frequency,
		"status":    input.Status,
	}

	if input.URI != "" {
		body["uri"] = input.URI
	}
	if len(input.Locations) > 0 {
		body["locations"] = input.Locations
	}

	data, err := c.doRequest("POST", c.SyntheticsURL+"/monitors", body)
	if err != nil {
		return nil, err
	}

	var monitor SyntheticMonitor
	if err := json.Unmarshal(data, &monitor); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &monitor, nil
}

// UpdateSyntheticMonitorREST updates a monitor via the Synthetics REST v3
// API.
//
// Deprecated: New Relic has deprecated the Synthetics REST API in favor of
// NerdGraph; see
// https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/administration/synthetics-api/.
// Use UpdateSyntheticMonitor, which is NerdGraph-backed.
func (c *Client) UpdateSyntheticMonitorREST(monitorID string, input *SyntheticMonitorInput) (*SyntheticMonitor, error) {
	body := map[string]interface{}{
		"name":      input.Name,
		"frequency": input.Frequency,
		"status":    input.Status,
	}

	if input.URI != "" {
		body["uri"] = input.URI
	}
	if len(input.Locations) > 0 {
		body["locations"] = input.Locations
	}

	data, err := c.doRequest("PUT", c.SyntheticsURL+"/monitors/"+monitorID, body)
	if err != nil {
		return nil, err
	}

	var monitor SyntheticMonitor
	if err := json.Unmarshal(data, &monitor); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	return &monitor, nil
}

// DeleteSyntheticMonitorREST deletes a monitor by UUID via the Synthetics
// REST v3 API.
//
// Deprecated: New Relic has deprecated the Synthetics REST API in favor of
// NerdGraph; see
// https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/administration/synthetics-api/.
// Use DeleteSyntheticMonitor, which is NerdGraph-backed.
func (c *Client) DeleteSyntheticMonitorREST(monitorID string) error {
	_, err := c.doRequest("DELETE", c.SyntheticsURL+"/monitors/"+monitorID, nil)
	return err
}
