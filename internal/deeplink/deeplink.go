package deeplink

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/open-cli-collective/newrelic-cli/api"
)

// ParseTimeRange parses optional since/until strings into epoch millisecond
// timestamps. If since is set but until is empty, until defaults to now.
// Returns (0, 0, nil) when both inputs are empty.
func ParseTimeRange(since, until string) (beginMs, endMs int64, err error) {
	if since != "" {
		t, err := api.ParseFlexibleTime(since)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid --since value: %w", err)
		}
		beginMs = t.UnixMilli()
		if until == "" {
			endMs = time.Now().UnixMilli()
		}
	}
	if until != "" {
		t, err := api.ParseFlexibleTime(until)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid --until value: %w", err)
		}
		endMs = t.UnixMilli()
	}
	return beginMs, endMs, nil
}

// BuildNRQLDeepLink generates a New Relic deep link URL that opens the query
// builder with the given NRQL query pre-populated and auto-executed.
func BuildNRQLDeepLink(accountID int, nrql string) string {
	pane := map[string]interface{}{
		"nerdletId":              "data-exploration.query-builder",
		"initialActiveInterface": "nrqlEditor",
		"initialAccountId":       accountID,
		"initialNrqlValue":       nrql,
		"isViewingQuery":         true,
	}

	paneJSON, _ := json.Marshal(pane)
	paneEncoded := base64.StdEncoding.EncodeToString(paneJSON)

	return fmt.Sprintf(
		"https://one.newrelic.com/launcher/nr1-core.explorer?platform%%5BaccountId%%5D=%d&pane=%s",
		accountID,
		url.QueryEscape(paneEncoded),
	)
}

// BuildEntityDeepLink generates a New Relic deep link URL for an entity.
// beginMs and endMs are optional epoch millisecond timestamps for the time range
// (pass 0 to omit).
func BuildEntityDeepLink(entityGUID string, beginMs, endMs int64) string {
	link := fmt.Sprintf("https://one.newrelic.com/redirect/entity/%s", url.PathEscape(entityGUID))

	sep := "?"
	if beginMs > 0 {
		link += fmt.Sprintf("%sbegin=%d", sep, beginMs)
		sep = "&"
	}
	if endMs > 0 {
		link += fmt.Sprintf("%send=%d", sep, endMs)
	}

	return link
}

// BuildLogDeepLink generates a New Relic deep link URL that opens the log
// viewer with the given Lucene filter query pre-populated.
// beginMs and endMs are optional epoch millisecond timestamps for the time range
// (pass 0 to omit).
func BuildLogDeepLink(accountID int, filterQuery string, beginMs, endMs int64) string {
	launcher := map[string]interface{}{
		"isEntitled": true,
		"query":      filterQuery,
		// Log_Logging is the event type used by the NR log launcher nerdlet
		// to query the Logging data partition (distinct from the "Log" NRQL event type).
		"eventTypes": []string{"Log_Logging"},
	}

	pane := map[string]interface{}{
		"nerdletId": "logger.log-tailer",
		"accountId": accountID,
	}

	launcherJSON, _ := json.Marshal(launcher)
	launcherEncoded := base64.StdEncoding.EncodeToString(launcherJSON)

	paneJSON, _ := json.Marshal(pane)
	paneEncoded := base64.StdEncoding.EncodeToString(paneJSON)

	link := fmt.Sprintf(
		"https://one.newrelic.com/launcher/logger.log-launcher?platform%%5BaccountId%%5D=%d&launcher=%s&pane=%s",
		accountID,
		url.QueryEscape(launcherEncoded),
		url.QueryEscape(paneEncoded),
	)

	if beginMs > 0 {
		link += fmt.Sprintf("&begin=%d", beginMs)
	}
	if endMs > 0 {
		link += fmt.Sprintf("&end=%d", endMs)
	}

	return link
}
