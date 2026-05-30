package api

import "fmt"

type ConnectionTestResult struct {
	APIKeyValid   bool
	AccountAccess bool
	AccountID     int
	AccountName   string
	UserID        string
	UserEmail     string
	Region        string
	NerdGraphURL  string
	Error         error
	ErrorMessage  string
}

func (c *Client) TestConnection() (*ConnectionTestResult, error) {
	result := &ConnectionTestResult{
		Region:       c.Region,
		NerdGraphURL: c.NerdGraphURL,
	}

	query := `query { actor { user { id email } } }`

	data, err := c.NerdGraphQuery(query, nil)
	if err != nil {
		result.Error = err
		result.ErrorMessage = fmt.Sprintf("API key validation failed: %v", err)
		return result, nil
	}

	result.APIKeyValid = true

	if actor, ok := safeMap(data["actor"]); ok {
		if user, ok := safeMap(actor["user"]); ok {
			result.UserID = safeString(user["id"])
			result.UserEmail = safeString(user["email"])
		}
	}

	if !c.AccountID.IsEmpty() {
		accountQuery := `
		query($accountId: Int!) {
			actor {
				account(id: $accountId) {
					id
					name
				}
			}
		}`

		accountID, _ := c.GetAccountIDInt()
		vars := map[string]interface{}{"accountId": accountID}

		accountData, err := c.NerdGraphQuery(accountQuery, vars)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("Account access failed: %v", err)
			return result, nil
		}

		if actor, ok := safeMap(accountData["actor"]); ok {
			if account, ok := safeMap(actor["account"]); ok {
				result.AccountAccess = true
				result.AccountID = safeInt(account["id"])
				result.AccountName = safeString(account["name"])
			}
		}
	}

	return result, nil
}
