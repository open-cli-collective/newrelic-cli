package deeplink

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildNRQLDeepLink(tt.accountID, tt.nrql)

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

func TestBuildLogDeepLink(t *testing.T) {
	tests := []struct {
		name        string
		accountID   int
		filterQuery string
		beginMs     int64
		endMs       int64
	}{
		{
			name:        "single entity error filter",
			accountID:   2712640,
			filterQuery: `entity.name:"prd-use1-monitapp-user-api-service" level:"ERROR"`,
		},
		{
			name:        "multiple entities",
			accountID:   2712640,
			filterQuery: `(entity.name:"svc-a" OR entity.name:"svc-b") level:"ERROR"`,
		},
		{
			name:        "keyword search",
			accountID:   12345,
			filterQuery: `message:"*timeout*"`,
		},
		{
			name:        "with time range",
			accountID:   2712640,
			filterQuery: `level:"ERROR"`,
			beginMs:     1773323224894,
			endMs:       1773323344894,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildLogDeepLink(tt.accountID, tt.filterQuery, tt.beginMs, tt.endMs)

			// Verify URL starts with the correct base
			assert.True(t, strings.HasPrefix(result, "https://one.newrelic.com/launcher/logger.log-launcher?"))

			// Parse the URL to extract query params
			u, err := url.Parse(result)
			require.NoError(t, err)

			// Check the account ID parameter
			assert.Equal(t, fmt.Sprintf("%d", tt.accountID), u.Query().Get("platform[accountId]"))

			// Decode and verify the launcher parameter
			launcherEncoded := u.Query().Get("launcher")
			require.NotEmpty(t, launcherEncoded)

			launcherJSON, err := base64.StdEncoding.DecodeString(launcherEncoded)
			require.NoError(t, err)

			var launcher map[string]interface{}
			err = json.Unmarshal(launcherJSON, &launcher)
			require.NoError(t, err)

			assert.Equal(t, true, launcher["isEntitled"])
			assert.Equal(t, tt.filterQuery, launcher["query"])

			// Decode and verify the pane parameter
			paneEncoded := u.Query().Get("pane")
			require.NotEmpty(t, paneEncoded)

			paneJSON, err := base64.StdEncoding.DecodeString(paneEncoded)
			require.NoError(t, err)

			var pane map[string]interface{}
			err = json.Unmarshal(paneJSON, &pane)
			require.NoError(t, err)

			assert.Equal(t, "logger.log-tailer", pane["nerdletId"])
			assert.Equal(t, float64(tt.accountID), pane["accountId"])

			// Verify time range params
			if tt.beginMs > 0 {
				assert.Equal(t, fmt.Sprintf("%d", tt.beginMs), u.Query().Get("begin"))
			} else {
				assert.Empty(t, u.Query().Get("begin"))
			}
			if tt.endMs > 0 {
				assert.Equal(t, fmt.Sprintf("%d", tt.endMs), u.Query().Get("end"))
			} else {
				assert.Empty(t, u.Query().Get("end"))
			}
		})
	}
}

func TestBuildEntityDeepLink(t *testing.T) {
	tests := []struct {
		name       string
		entityGUID string
		beginMs    int64
		endMs      int64
		expected   string
	}{
		{
			name:       "APM application without time range",
			entityGUID: "MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=",
			expected:   "https://one.newrelic.com/redirect/entity/MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=",
		},
		{
			name:       "dashboard without time range",
			entityGUID: "MXxWSVp8REFTSEJPQVJEX3wxMjM0NTY3OA==",
			expected:   "https://one.newrelic.com/redirect/entity/MXxWSVp8REFTSEJPQVJEX3wxMjM0NTY3OA==",
		},
		{
			name:       "with time range",
			entityGUID: "MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=",
			beginMs:    1773323224894,
			endMs:      1773323344894,
			expected:   "https://one.newrelic.com/redirect/entity/MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=?begin=1773323224894&end=1773323344894",
		},
		{
			name:       "with begin only",
			entityGUID: "MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=",
			beginMs:    1773323224894,
			expected:   "https://one.newrelic.com/redirect/entity/MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=?begin=1773323224894",
		},
		{
			name:       "GUID with base64 slash is escaped",
			entityGUID: "MXx+L0FQTX/+QVBQTElDQVRJT058MTIz",
			expected:   "https://one.newrelic.com/redirect/entity/MXx+L0FQTX%2F+QVBQTElDQVRJT058MTIz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildEntityDeepLink(tt.entityGUID, tt.beginMs, tt.endMs)
			assert.Equal(t, tt.expected, result)
		})
	}
}
