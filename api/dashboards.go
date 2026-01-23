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
