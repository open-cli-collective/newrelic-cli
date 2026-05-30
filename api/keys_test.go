package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchAPIKeys(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_keys_search.json"))

	client := NewTestClient(server)
	keys, err := client.SearchAPIKeys(nil, 0)

	require.NoError(t, err)
	require.Len(t, keys, 3)

	assert.Equal(t, "NRAK-ABCDEF1234567890", keys[0].ID)
	assert.Equal(t, "My User Key", keys[0].Name)
	assert.Equal(t, "USER", keys[0].Type)
	assert.Equal(t, "", keys[0].IngestType)

	assert.Equal(t, "NRII-ABCDEF1234567890", keys[1].ID)
	assert.Equal(t, "INGEST", keys[1].Type)
	assert.Equal(t, "LICENSE", keys[1].IngestType)

	assert.Equal(t, "NRII-BROWSER1234567890", keys[2].ID)
	assert.Equal(t, "BROWSER", keys[2].IngestType)

	server.AssertLastPath(t, "/graphql")
}

func TestSearchAPIKeys_FilterByType(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_keys_search.json"))

	client := NewTestClient(server)
	_, err := client.SearchAPIKeys([]string{"USER"}, 0)

	require.NoError(t, err)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "USER")
}

func TestSearchAPIKeys_WithAccountFilter(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_keys_search.json"))

	client := NewTestClient(server)
	_, err := client.SearchAPIKeys(nil, 12345)

	require.NoError(t, err)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "12345")
}

func TestSearchAPIKeys_EmptyResult(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"apiAccess": {
					"keySearch": {
						"keys": []
					}
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	keys, err := client.SearchAPIKeys(nil, 0)

	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestGetAPIAccessKey(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_key_get.json"))

	client := NewTestClient(server)
	key, err := client.GetAPIAccessKey("NRAK-ABCDEF1234567890", "USER")

	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Equal(t, "NRAK-ABCDEF1234567890", key.ID)
	assert.Equal(t, "My User Key", key.Name)
	assert.Equal(t, "USER", key.Type)
	assert.Equal(t, "For automation", key.Notes)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "NRAK-ABCDEF1234567890")
	assert.Contains(t, string(req.Body), "USER")
}

func TestGetAPIAccessKey_NotFound(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"actor": {
				"apiAccess": {
					"key": null
				}
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.GetAPIAccessKey("nonexistent", "USER")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

func TestFindAPIAccessKey_FoundAsUser(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_key_get.json"))

	client := NewTestClient(server)
	key, err := client.FindAPIAccessKey("NRAK-ABCDEF1234567890")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, "USER", key.Type)

	server.AssertRequestCount(t, 1)
}

func TestFindAPIAccessKey_FoundAsIngest(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	requestCount := 0
	server.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			w.Write([]byte(`{"data": {"actor": {"apiAccess": {"key": null}}}}`))
		} else {
			w.Write([]byte(`{
				"data": {
					"actor": {
						"apiAccess": {
							"key": {
								"id": "NRII-ABC123",
								"name": "License Key",
								"notes": "",
								"type": "INGEST",
								"key": "",
								"ingestType": "LICENSE"
							}
						}
					}
				}
			}`))
		}
	})

	client := NewTestClient(server)
	key, err := client.FindAPIAccessKey("NRII-ABC123")

	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, "INGEST", key.Type)
	assert.Equal(t, 2, requestCount)
}

func TestGetCurrentUserID(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_key_current_user.json"))

	client := NewTestClient(server)
	userID, err := client.GetCurrentUserID()

	require.NoError(t, err)
	assert.Equal(t, 99999, userID)
}

func TestCreateUserAPIKey(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_key_created.json"))

	client := NewTestClient(server)
	key, err := client.CreateUserAPIKey(12345, 99999, "New Key", "Fresh key")

	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Equal(t, "NRAK-NEW1234567890", key.ID)
	assert.Equal(t, "New Key", key.Name)
	assert.Equal(t, "Fresh key", key.Notes)
	assert.Equal(t, "USER", key.Type)
	assert.NotEmpty(t, key.Key)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "12345")
	assert.Contains(t, string(req.Body), "99999")
}

func TestCreateUserAPIKey_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"apiAccessCreateKeys": {
				"createdKeys": [],
				"errors": [
					{"message": "Unauthorized", "type": "UNAUTHORIZED"}
				]
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.CreateUserAPIKey(12345, 99999, "Test", "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Unauthorized")
}

func TestCreateIngestAPIKey(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"apiAccessCreateKeys": {
				"createdKeys": [
					{
						"id": "NRII-NEW123",
						"name": "License Key",
						"notes": "",
						"type": "INGEST",
						"key": "license-key-value",
						"ingestType": "LICENSE"
					}
				],
				"errors": []
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	key, err := client.CreateIngestAPIKey(12345, "LICENSE", "License Key", "")

	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Equal(t, "INGEST", key.Type)
	assert.Equal(t, "LICENSE", key.IngestType)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "LICENSE")
}

func TestUpdateAPIAccessKey(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_key_updated.json"))

	client := NewTestClient(server)
	name := "Updated Name"
	notes := "Updated notes"
	key, err := client.UpdateAPIAccessKey("NRAK-ABCDEF1234567890", "USER", ApiAccessKeyUpdate{
		Name:  &name,
		Notes: &notes,
	})

	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Equal(t, "NRAK-ABCDEF1234567890", key.ID)
	assert.Equal(t, "Updated Name", key.Name)
	assert.Equal(t, "Updated notes", key.Notes)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "user")
	assert.Contains(t, string(req.Body), "Updated Name")
}

func TestUpdateAPIAccessKey_IngestType(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"apiAccessUpdateKeys": {
				"updatedKeys": [
					{
						"id": "NRII-ABC123",
						"name": "Updated Ingest",
						"notes": "",
						"type": "INGEST",
						"ingestType": "LICENSE"
					}
				],
				"errors": []
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	name := "Updated Ingest"
	key, err := client.UpdateAPIAccessKey("NRII-ABC123", "INGEST", ApiAccessKeyUpdate{
		Name: &name,
	})

	require.NoError(t, err)
	require.NotNil(t, key)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "ingest")
}

func TestUpdateAPIAccessKey_InvalidType(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	name := "Test"
	_, err := client.UpdateAPIAccessKey("key-id", "INVALID", ApiAccessKeyUpdate{
		Name: &name,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key type")
}

func TestUpdateAPIAccessKey_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"apiAccessUpdateKeys": {
				"updatedKeys": [],
				"errors": [
					{"message": "Key not found"}
				]
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	name := "Test"
	_, err := client.UpdateAPIAccessKey("nonexistent", "USER", ApiAccessKeyUpdate{
		Name: &name,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Key not found")
}

func TestDeleteAPIAccessKeys_UserKeys(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_key_deleted.json"))

	client := NewTestClient(server)
	deleted, err := client.DeleteAPIAccessKeys([]string{"NRAK-ABCDEF1234567890"}, nil)

	require.NoError(t, err)
	require.Len(t, deleted, 1)
	assert.Equal(t, "NRAK-ABCDEF1234567890", deleted[0])

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "userKeyIds")
}

func TestDeleteAPIAccessKeys_IngestKeys(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	server.SetResponse(http.StatusOK, LoadTestFixture(t, "api_key_deleted.json"))

	client := NewTestClient(server)
	deleted, err := client.DeleteAPIAccessKeys(nil, []string{"NRII-ABC123"})

	require.NoError(t, err)
	require.Len(t, deleted, 1)

	req := server.LastRequest()
	require.NotNil(t, req)
	assert.Contains(t, string(req.Body), "ingestKeyIds")
}

func TestDeleteAPIAccessKeys_NoIDs(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	client := NewTestClient(server)
	_, err := client.DeleteAPIAccessKeys(nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key IDs provided")
}

func TestDeleteAPIAccessKeys_Error(t *testing.T) {
	server := NewMockServer()
	defer server.Close()

	response := `{
		"data": {
			"apiAccessDeleteKeys": {
				"deletedKeys": [],
				"errors": [
					{"message": "Key not found"}
				]
			}
		}
	}`
	server.SetResponse(http.StatusOK, response)

	client := NewTestClient(server)
	_, err := client.DeleteAPIAccessKeys([]string{"nonexistent"}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Key not found")
}

func TestEscapeGraphQL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple string", "hello", "hello"},
		{"double quotes", `say "hello"`, `say \"hello\"`},
		{"backslash", `path\to\file`, `path\\to\\file`},
		{"newline", "line1\nline2", `line1\nline2`},
		{"tab", "col1\tcol2", `col1\tcol2`},
		{"mixed", "a \"b\" c\nd", `a \"b\" c\nd`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeGraphQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{"single", []string{"abc"}, `"abc"`},
		{"multiple", []string{"a", "b", "c"}, `"a", "b", "c"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatStringSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseApiAccessKey(t *testing.T) {
	data := map[string]interface{}{
		"id":         "NRAK-123",
		"name":       "Test Key",
		"notes":      "Some notes",
		"type":       "USER",
		"key":        "actual-key-value",
		"ingestType": "",
	}

	key := parseApiAccessKey(data)

	assert.Equal(t, "NRAK-123", key.ID)
	assert.Equal(t, "Test Key", key.Name)
	assert.Equal(t, "Some notes", key.Notes)
	assert.Equal(t, "USER", key.Type)
	assert.Equal(t, "actual-key-value", key.Key)
}

func TestParseApiAccessKey_InvalidInput(t *testing.T) {
	key := parseApiAccessKey("not a map")
	assert.Equal(t, ApiAccessKey{}, key)
}
