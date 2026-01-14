package api

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Common time formats to try when parsing timestamps
var timeFormats = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"01/02/2006",
	"Jan 2, 2006",
}

// relativeTimePattern matches strings like "7 days ago", "2 hours ago", "1 week ago"
var relativeTimePattern = regexp.MustCompile(`^(\d+)\s+(second|minute|hour|day|week|month|year)s?\s+ago$`)

// ParseFlexibleTime parses a time string in various formats:
// - ISO 8601 / RFC3339 formats
// - Date-only formats (YYYY-MM-DD, MM/DD/YYYY, etc.)
// - Relative formats ("7 days ago", "1 week ago", etc.)
// - Special values ("now", "today", "yesterday")
func ParseFlexibleTime(s string) (time.Time, error) {
	original := strings.TrimSpace(s)
	lower := strings.ToLower(original)

	if original == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}

	// Handle special values (case-insensitive)
	now := time.Now()
	switch lower {
	case "now":
		return now, nil
	case "today":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()), nil
	case "yesterday":
		yesterday := now.AddDate(0, 0, -1)
		return time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, now.Location()), nil
	}

	// Handle relative time expressions (case-insensitive)
	if matches := relativeTimePattern.FindStringSubmatch(lower); matches != nil {
		amount, _ := strconv.Atoi(matches[1])
		unit := matches[2]
		return parseRelativeTime(now, amount, unit)
	}

	// Try standard formats with original case (important for RFC3339 with 'Z' suffix)
	for _, format := range timeFormats {
		if t, err := time.Parse(format, original); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", original)
}

func parseRelativeTime(now time.Time, amount int, unit string) (time.Time, error) {
	switch unit {
	case "second":
		return now.Add(-time.Duration(amount) * time.Second), nil
	case "minute":
		return now.Add(-time.Duration(amount) * time.Minute), nil
	case "hour":
		return now.Add(-time.Duration(amount) * time.Hour), nil
	case "day":
		return now.AddDate(0, 0, -amount), nil
	case "week":
		return now.AddDate(0, 0, -amount*7), nil
	case "month":
		return now.AddDate(0, -amount, 0), nil
	case "year":
		return now.AddDate(-amount, 0, 0), nil
	default:
		return time.Time{}, fmt.Errorf("unknown time unit: %s", unit)
	}
}

// ParseDeploymentTimestamp parses the timestamp format returned by New Relic's deployment API
func ParseDeploymentTimestamp(s string) (time.Time, error) {
	// New Relic typically returns timestamps in RFC3339 or similar formats
	for _, format := range timeFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse deployment timestamp: %s", s)
}

// FilterDeploymentsByTime filters a slice of deployments to only include those within the time range.
// If since is zero, no lower bound is applied.
// If until is zero, no upper bound is applied.
func FilterDeploymentsByTime(deployments []Deployment, since, until time.Time) []Deployment {
	if since.IsZero() && until.IsZero() {
		return deployments
	}

	filtered := make([]Deployment, 0, len(deployments))
	for _, d := range deployments {
		ts, err := ParseDeploymentTimestamp(d.Timestamp)
		if err != nil {
			// If we can't parse the timestamp, include the deployment
			filtered = append(filtered, d)
			continue
		}

		// Check if within range
		if !since.IsZero() && ts.Before(since) {
			continue
		}
		if !until.IsZero() && ts.After(until) {
			continue
		}
		filtered = append(filtered, d)
	}

	return filtered
}
