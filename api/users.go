package api

import "fmt"

// ListUsers returns all users in the organization
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

	// Navigate the nested structure safely
	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing actor"}
	}
	org, ok := safeMap(actor["organization"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing organization"}
	}
	userMgmt, ok := safeMap(org["userManagement"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing userManagement"}
	}
	authDomains, ok := safeMap(userMgmt["authenticationDomains"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing authenticationDomains"}
	}
	domains, ok := safeSlice(authDomains["authenticationDomains"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format: missing domains list"}
	}

	var users []User
	for _, d := range domains {
		domain, ok := safeMap(d)
		if !ok {
			continue
		}
		domainName := safeString(domain["name"])
		usersData, ok := safeMap(domain["users"])
		if !ok {
			continue
		}
		usersList, ok := safeSlice(usersData["users"])
		if !ok {
			continue
		}

		for _, u := range usersList {
			user, ok := safeMap(u)
			if !ok {
				continue
			}
			userType := ""
			if t, ok := safeMap(user["type"]); ok {
				userType = safeString(t["displayName"])
			}
			users = append(users, User{
				ID:                   safeString(user["id"]),
				Name:                 safeString(user["name"]),
				Email:                safeString(user["email"]),
				Type:                 userType,
				AuthenticationDomain: domainName,
			})
		}
	}

	return users, nil
}

// GetUser returns a specific user by ID
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
	actor, ok := safeMap(result["actor"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	org, ok := safeMap(actor["organization"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	userMgmt, ok := safeMap(org["userManagement"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	authDomains, ok := safeMap(userMgmt["authenticationDomains"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}
	domains, ok := safeSlice(authDomains["authenticationDomains"])
	if !ok {
		return nil, &ResponseError{Message: "unexpected response format"}
	}

	for _, d := range domains {
		domain, ok := safeMap(d)
		if !ok {
			continue
		}
		domainName := safeString(domain["name"])
		usersData, ok := safeMap(domain["users"])
		if !ok {
			continue
		}
		usersList, ok := safeSlice(usersData["users"])
		if !ok {
			continue
		}

		for _, u := range usersList {
			user, ok := safeMap(u)
			if !ok {
				continue
			}
			if safeString(user["id"]) == userID {
				userType := ""
				if t, ok := safeMap(user["type"]); ok {
					userType = safeString(t["displayName"])
				}

				var groups []string
				if g, ok := safeMap(user["groups"]); ok {
					if groupsList, ok := safeSlice(g["groups"]); ok {
						for _, grp := range groupsList {
							group, ok := safeMap(grp)
							if !ok {
								continue
							}
							groups = append(groups, safeString(group["displayName"]))
						}
					}
				}

				return &User{
					ID:                   safeString(user["id"]),
					Name:                 safeString(user["name"]),
					Email:                safeString(user["email"]),
					Type:                 userType,
					Groups:               groups,
					AuthenticationDomain: domainName,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("user not found")
}
