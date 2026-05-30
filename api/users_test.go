package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListUsers(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "users_list.json"))

	client := NewTestClient(server)
	users, err := client.ListUsers()

	require.NoError(t, err)
	require.Len(t, users, 2)

	assert.Equal(t, "user-001", users[0].ID)
	assert.Equal(t, "Alice Admin", users[0].Name)
	assert.Equal(t, "alice@example.com", users[0].Email)
	assert.Equal(t, "Default", users[0].AuthenticationDomain)

	assert.Equal(t, "user-002", users[1].ID)
	assert.Equal(t, "Bob Developer", users[1].Name)

	server.AssertLastPath(t, "/graphql")
}

func TestListUsers_Empty(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"organization": {
					"userManagement": {
						"authenticationDomains": {
							"authenticationDomains": []
						}
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	users, err := client.ListUsers()

	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestListUsers_MultiDomain(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"organization": {
					"userManagement": {
						"authenticationDomains": {
							"authenticationDomains": [
								{
									"id": "domain-1",
									"name": "Default",
									"users": {
										"users": [
											{"id": "user-1", "name": "User One", "email": "one@example.com", "type": {"displayName": "Basic"}}
										]
									}
								},
								{
									"id": "domain-2",
									"name": "SSO",
									"users": {
										"users": [
											{"id": "user-2", "name": "User Two", "email": "two@example.com", "type": {"displayName": "Full"}}
										]
									}
								}
							]
						}
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	users, err := client.ListUsers()

	require.NoError(t, err)
	require.Len(t, users, 2)

	assert.Equal(t, "Default", users[0].AuthenticationDomain)
	assert.Equal(t, "SSO", users[1].AuthenticationDomain)
}

func TestListUsers_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusUnauthorized, `{"error": "unauthorized"}`)

	client := NewTestClient(server)
	_, err := client.ListUsers()

	require.Error(t, err)
	assert.True(t, IsUnauthorized(err))
}

func TestGetUser(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "user_detail.json"))

	client := NewTestClient(server)
	user, err := client.GetUser("user-001")

	require.NoError(t, err)
	require.NotNil(t, user)

	assert.Equal(t, "user-001", user.ID)
	assert.Equal(t, "Alice Admin", user.Name)
	assert.Equal(t, "alice@example.com", user.Email)
	require.Len(t, user.Groups, 3)
	assert.Contains(t, user.Groups, "Admin")
	assert.Contains(t, user.Groups, "Engineering")
	assert.Contains(t, user.Groups, "On-Call")
}

func TestGetUser_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"organization": {
					"userManagement": {
						"authenticationDomains": {
							"authenticationDomains": [
								{
									"name": "Default",
									"users": {
										"users": [
											{"id": "other-user", "name": "Other", "email": "other@example.com"}
										]
									}
								}
							]
						}
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.GetUser("nonexistent")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestGetUser_EmptyDomains(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"organization": {
					"userManagement": {
						"authenticationDomains": {
							"authenticationDomains": []
						}
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.GetUser("user-001")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}
