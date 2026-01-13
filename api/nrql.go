package api

// QueryNRQL executes an NRQL query
func (c *Client) QueryNRQL(nrql string) (*NRQLResult, error) {
	if err := c.RequireAccountID(); err != nil {
		return nil, err
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

	accountID, _ := c.GetAccountIDInt()
	variables := map[string]interface{}{
		"accountId": accountID,
		"nrql":      nrql,
	}

	result, err := c.NerdGraphQuery(query, variables)
	if err != nil {
		return nil, err
	}

	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	account, ok := safeMap(actor["account"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing account"}
	}
	nrqlResult, ok := safeMap(account["nrql"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing nrql"}
	}
	results, ok := safeSlice(nrqlResult["results"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing results"}
	}

	nrqlResults := &NRQLResult{
		Results: make([]map[string]interface{}, len(results)),
	}
	for i, r := range results {
		if m, ok := safeMap(r); ok {
			nrqlResults.Results[i] = m
		}
	}

	return nrqlResults, nil
}
