package nrql

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNRQLDeepLink(t *testing.T) {
	tests := []struct {
		name      string
		accountID int
		nrql      string
	}{
		{
			name:      "simple query",
			accountID: 2712640,
			nrql:      "SELECT count(*) FROM Transaction SINCE 1 hour ago",
		},
		{
			name:      "query with special characters",
			accountID: 12345,
			nrql:      "SELECT * FROM Log WHERE message LIKE '%error%' SINCE 1 day ago",
		},
		{
			name:      "complex query",
			accountID: 99999,
			nrql:      "SELECT average(duration) FROM Transaction WHERE appName = 'my-app' FACET host SINCE 7 days ago TIMESERIES",
		},
		{
			name:      "query with single quotes and newlines",
			accountID: 2712640,
			nrql:      "SELECT * FROM Log WHERE message LIKE '%error\n%' AND name = 'foo'",
		},
		{
			name:      "query with unicode",
			accountID: 2712640,
			nrql:      "SELECT count(*) FROM Transaction WHERE name = '日本語テスト'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildNRQLDeepLink(tt.accountID, tt.nrql)
			require.NoError(t, err)

			// Verify URL starts with the correct base
			assert.True(t, strings.HasPrefix(result, "https://one.newrelic.com/launcher/nr1-core.explorer?"))

			// Parse the URL to extract query params
			u, err := url.Parse(result)
			require.NoError(t, err)

			// Check the account ID parameter
			assert.Equal(t, fmt.Sprintf("%d", tt.accountID), u.Query().Get("platform[accountId]"))

			// Decode and verify the pane parameter
			paneEncoded := u.Query().Get("pane")
			require.NotEmpty(t, paneEncoded)

			paneJSON, err := base64.StdEncoding.DecodeString(paneEncoded)
			require.NoError(t, err)

			var pane map[string]interface{}
			err = json.Unmarshal(paneJSON, &pane)
			require.NoError(t, err)

			assert.Equal(t, "data-exploration.query-builder", pane["nerdletId"])
			assert.Equal(t, "nrqlEditor", pane["initialActiveInterface"])
			assert.Equal(t, float64(tt.accountID), pane["initialAccountId"])
			assert.Equal(t, tt.nrql, pane["initialNrqlValue"])
			assert.Equal(t, true, pane["isViewingQuery"])
		})
	}
}

func TestBuildEntityDeepLink(t *testing.T) {
	tests := []struct {
		name       string
		entityGUID string
		expected   string
	}{
		{
			name:       "APM application",
			entityGUID: "MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=",
			expected:   "https://one.newrelic.com/redirect/entity/MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=",
		},
		{
			name:       "dashboard",
			entityGUID: "MXxWSVp8REFTSEJPQVJEX3wxMjM0NTY3OA==",
			expected:   "https://one.newrelic.com/redirect/entity/MXxWSVp8REFTSEJPQVJEX3wxMjM0NTY3OA==",
		},
		{
			name:       "GUID with slash is escaped",
			entityGUID: "abc+def/ghi=",
			expected:   "https://one.newrelic.com/redirect/entity/abc+def%2Fghi=",
		},
		{
			name:       "GUID with question mark is escaped",
			entityGUID: "MXxBUE18QVBQTElDQVRJT04?MTIz",
			expected:   "https://one.newrelic.com/redirect/entity/MXxBUE18QVBQTElDQVRJT04%3FMTIz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildEntityDeepLink(tt.entityGUID)
			assert.Equal(t, tt.expected, result)
		})
	}
}
