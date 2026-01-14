package api

// SearchEntities searches for entities matching the query
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
	entitiesData, ok := safeSlice(results["entities"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing entities"}
	}

	entities := make([]Entity, 0, len(entitiesData))
	for _, e := range entitiesData {
		entity, ok := safeMap(e)
		if !ok {
			continue
		}
		ent := Entity{
			GUID:       EntityGUID(safeString(entity["guid"])),
			Name:       safeString(entity["name"]),
			Type:       safeString(entity["type"]),
			EntityType: safeString(entity["entityType"]),
			Domain:     safeString(entity["domain"]),
			AccountID:  safeInt(entity["accountId"]),
		}
		entities = append(entities, ent)
	}

	return entities, nil
}
