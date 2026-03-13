package api

import "fmt"

// ListDashboards returns all dashboards for the account
func (c *Client) ListDashboards() ([]Dashboard, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
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

	// Navigate the nested response safely
	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	entitySearch, ok := safeMap(actor["entitySearch"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing entitySearch"}
	}
	results, ok := safeMap(entitySearch["results"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing results"}
	}
	entities, ok := safeSlice(results["entities"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing entities"}
	}

	dashboards := make([]Dashboard, 0, len(entities))
	for _, e := range entities {
		entity, ok := safeMap(e)
		if !ok {
			continue
		}
		dashboards = append(dashboards, Dashboard{
			GUID:      EntityGUID(safeString(entity["guid"])),
			Name:      safeString(entity["name"]),
			AccountID: safeInt(entity["accountId"]),
		})
	}

	return dashboards, nil
}

// GetDashboard returns detailed information for a specific dashboard
func (c *Client) GetDashboard(guid EntityGUID) (*DashboardDetail, error) {
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
							layout { column row width height }
							rawConfiguration
						}
					}
				}
			}
		}
	}`

	variables := map[string]interface{}{
		"guid": guid.String(),
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	entity, ok := safeMap(actor["entity"])
	if !ok || entity == nil {
		return nil, fmt.Errorf("dashboard not found")
	}

	dashboard := &DashboardDetail{
		GUID:        EntityGUID(safeString(entity["guid"])),
		Name:        safeString(entity["name"]),
		Description: safeString(entity["description"]),
		Permissions: safeString(entity["permissions"]),
	}

	// Parse pages
	if pages, ok := safeSlice(entity["pages"]); ok {
		for _, p := range pages {
			page, ok := safeMap(p)
			if !ok {
				continue
			}
			dp := DashboardPage{
				GUID: EntityGUID(safeString(page["guid"])),
				Name: safeString(page["name"]),
			}

			if widgets, ok := safeSlice(page["widgets"]); ok {
				for _, w := range widgets {
					widget, ok := safeMap(w)
					if !ok {
						continue
					}
					dw := DashboardWidget{
						ID:    safeString(widget["id"]),
						Title: safeString(widget["title"]),
					}
					if viz, ok := safeMap(widget["visualization"]); ok {
						dw.Visualization = viz
					}
					if layout, ok := safeMap(widget["layout"]); ok {
						dw.Layout = layout
					}
					if conf, ok := safeMap(widget["rawConfiguration"]); ok {
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

// DashboardInput represents the input for creating or updating a dashboard
type DashboardInput struct {
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Permissions string               `json:"permissions,omitempty"`
	Pages       []DashboardPageInput `json:"pages"`
}

// DashboardPageInput represents a page in dashboard input
type DashboardPageInput struct {
	Name    string                 `json:"name"`
	Widgets []DashboardWidgetInput `json:"widgets,omitempty"`
}

// DashboardWidgetInput represents a widget in dashboard page input
type DashboardWidgetInput struct {
	Title         string                 `json:"title"`
	Visualization map[string]interface{} `json:"visualization"`
	Layout        map[string]interface{} `json:"layout,omitempty"`
	Configuration map[string]interface{} `json:"rawConfiguration"`
}

// CreateDashboard creates a new dashboard from the provided input
func (c *Client) CreateDashboard(input *DashboardInput) (*DashboardDetail, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
	}

	mutation := `
	mutation($accountId: Int!, $dashboard: DashboardInput!) {
		dashboardCreate(accountId: $accountId, dashboard: $dashboard) {
			entityResult {
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
			errors {
				description
				type
			}
		}
	}`

	// Convert input to the format expected by NerdGraph
	dashboardMap := map[string]interface{}{
		"name":        input.Name,
		"permissions": input.Permissions,
	}
	if input.Description != "" {
		dashboardMap["description"] = input.Description
	}
	if input.Permissions == "" {
		dashboardMap["permissions"] = "PUBLIC_READ_WRITE"
	}

	pages := make([]map[string]interface{}, len(input.Pages))
	for i, p := range input.Pages {
		pageMap := map[string]interface{}{
			"name": p.Name,
		}
		widgets := make([]map[string]interface{}, len(p.Widgets))
		for j, w := range p.Widgets {
			widgetMap := map[string]interface{}{
				"title":            w.Title,
				"visualization":    w.Visualization,
				"rawConfiguration": w.Configuration,
			}
			if w.Layout != nil {
				widgetMap["layout"] = w.Layout
			}
			widgets[j] = widgetMap
		}
		pageMap["widgets"] = widgets
		pages[i] = pageMap
	}
	dashboardMap["pages"] = pages

	variables := map[string]interface{}{
		"accountId": c.AccountID.Int(),
		"dashboard": dashboardMap,
	}

	result, err := c.NerdGraphQuery(mutation, variables)
	if err != nil {
		return nil, err
	}

	dashboardCreate, ok := safeMap(result["dashboardCreate"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing dashboardCreate"}
	}

	// Check for errors
	if errors, ok := safeSlice(dashboardCreate["errors"]); ok && len(errors) > 0 {
		if errMap, ok := safeMap(errors[0]); ok {
			return nil, fmt.Errorf("failed to create dashboard: %s", safeString(errMap["description"]))
		}
	}

	entityResult, ok := safeMap(dashboardCreate["entityResult"])
	if !ok || entityResult == nil {
		return nil, &ResponseError{Message: "unexpected response format: missing entityResult"}
	}

	return parseDashboardEntity(entityResult), nil
}

// UpdateDashboard updates an existing dashboard
func (c *Client) UpdateDashboard(guid EntityGUID, input *DashboardInput) (*DashboardDetail, error) {
	mutation := `
	mutation($guid: EntityGuid!, $dashboard: DashboardInput!) {
		dashboardUpdate(guid: $guid, dashboard: $dashboard) {
			entityResult {
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
			errors {
				description
				type
			}
		}
	}`

	// Convert input to the format expected by NerdGraph
	dashboardMap := map[string]interface{}{
		"name": input.Name,
	}
	if input.Description != "" {
		dashboardMap["description"] = input.Description
	}
	if input.Permissions != "" {
		dashboardMap["permissions"] = input.Permissions
	}

	pages := make([]map[string]interface{}, len(input.Pages))
	for i, p := range input.Pages {
		pageMap := map[string]interface{}{
			"name": p.Name,
		}
		widgets := make([]map[string]interface{}, len(p.Widgets))
		for j, w := range p.Widgets {
			widgetMap := map[string]interface{}{
				"title":            w.Title,
				"visualization":    w.Visualization,
				"rawConfiguration": w.Configuration,
			}
			if w.Layout != nil {
				widgetMap["layout"] = w.Layout
			}
			widgets[j] = widgetMap
		}
		pageMap["widgets"] = widgets
		pages[i] = pageMap
	}
	dashboardMap["pages"] = pages

	variables := map[string]interface{}{
		"guid":      guid.String(),
		"dashboard": dashboardMap,
	}

	result, err := c.NerdGraphQuery(mutation, variables)
	if err != nil {
		return nil, err
	}

	dashboardUpdate, ok := safeMap(result["dashboardUpdate"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing dashboardUpdate"}
	}

	// Check for errors
	if errors, ok := safeSlice(dashboardUpdate["errors"]); ok && len(errors) > 0 {
		if errMap, ok := safeMap(errors[0]); ok {
			return nil, fmt.Errorf("failed to update dashboard: %s", safeString(errMap["description"]))
		}
	}

	entityResult, ok := safeMap(dashboardUpdate["entityResult"])
	if !ok || entityResult == nil {
		return nil, &ResponseError{Message: "unexpected response format: missing entityResult"}
	}

	return parseDashboardEntity(entityResult), nil
}

// parseDashboardEntity converts a NerdGraph entity result to DashboardDetail
func parseDashboardEntity(entity map[string]interface{}) *DashboardDetail {
	dashboard := &DashboardDetail{
		GUID:        EntityGUID(safeString(entity["guid"])),
		Name:        safeString(entity["name"]),
		Description: safeString(entity["description"]),
		Permissions: safeString(entity["permissions"]),
	}

	if pages, ok := safeSlice(entity["pages"]); ok {
		for _, p := range pages {
			page, ok := safeMap(p)
			if !ok {
				continue
			}
			dp := DashboardPage{
				GUID: EntityGUID(safeString(page["guid"])),
				Name: safeString(page["name"]),
			}

			if widgets, ok := safeSlice(page["widgets"]); ok {
				for _, w := range widgets {
					widget, ok := safeMap(w)
					if !ok {
						continue
					}
					dw := DashboardWidget{
						ID:    safeString(widget["id"]),
						Title: safeString(widget["title"]),
					}
					if viz, ok := safeMap(widget["visualization"]); ok {
						dw.Visualization = viz
					}
					if layout, ok := safeMap(widget["layout"]); ok {
						dw.Layout = layout
					}
					if conf, ok := safeMap(widget["rawConfiguration"]); ok {
						dw.Configuration = conf
					}
					dp.Widgets = append(dp.Widgets, dw)
				}
			}
			dashboard.Pages = append(dashboard.Pages, dp)
		}
	}

	return dashboard
}

// DeleteDashboard deletes a dashboard by GUID
func (c *Client) DeleteDashboard(guid EntityGUID) error {
	mutation := `
	mutation($guid: EntityGuid!) {
		dashboardDelete(guid: $guid) {
			status
			errors {
				description
				type
			}
		}
	}`

	variables := map[string]interface{}{
		"guid": guid.String(),
	}

	result, err := c.NerdGraphQuery(mutation, variables)
	if err != nil {
		return err
	}

	// Check for deletion errors
	dashboardDelete, ok := safeMap(result["dashboardDelete"])
	if !ok {
		return &ResponseError{Message: "unexpected response format: missing dashboardDelete"}
	}

	status := safeString(dashboardDelete["status"])
	if status != "SUCCESS" {
		// Check for specific errors
		if errors, ok := safeSlice(dashboardDelete["errors"]); ok && len(errors) > 0 {
			if errMap, ok := safeMap(errors[0]); ok {
				return fmt.Errorf("failed to delete dashboard: %s", safeString(errMap["description"]))
			}
		}
		return fmt.Errorf("failed to delete dashboard: status %s", status)
	}

	return nil
}
