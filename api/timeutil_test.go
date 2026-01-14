package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseFlexibleTime(t *testing.T) {
	t.Run("ISO 8601 format", func(t *testing.T) {
		result, err := ParseFlexibleTime("2025-01-15T14:30:00Z")

		assert.NoError(t, err)
		assert.Equal(t, 2025, result.Year())
		assert.Equal(t, time.January, result.Month())
		assert.Equal(t, 15, result.Day())
	})

	t.Run("date only format YYYY-MM-DD", func(t *testing.T) {
		result, err := ParseFlexibleTime("2025-01-15")

		assert.NoError(t, err)
		assert.Equal(t, 2025, result.Year())
		assert.Equal(t, time.January, result.Month())
		assert.Equal(t, 15, result.Day())
	})

	t.Run("special value now", func(t *testing.T) {
		before := time.Now()
		result, err := ParseFlexibleTime("now")
		after := time.Now()

		assert.NoError(t, err)
		assert.True(t, result.After(before) || result.Equal(before))
		assert.True(t, result.Before(after) || result.Equal(after))
	})

	t.Run("special value today", func(t *testing.T) {
		result, err := ParseFlexibleTime("today")
		now := time.Now()

		assert.NoError(t, err)
		assert.Equal(t, now.Year(), result.Year())
		assert.Equal(t, now.Month(), result.Month())
		assert.Equal(t, now.Day(), result.Day())
		assert.Equal(t, 0, result.Hour())
		assert.Equal(t, 0, result.Minute())
	})

	t.Run("special value yesterday", func(t *testing.T) {
		result, err := ParseFlexibleTime("yesterday")
		yesterday := time.Now().AddDate(0, 0, -1)

		assert.NoError(t, err)
		assert.Equal(t, yesterday.Year(), result.Year())
		assert.Equal(t, yesterday.Month(), result.Month())
		assert.Equal(t, yesterday.Day(), result.Day())
	})

	t.Run("relative time - days ago", func(t *testing.T) {
		result, err := ParseFlexibleTime("7 days ago")
		expected := time.Now().AddDate(0, 0, -7)

		assert.NoError(t, err)
		// Compare dates only (ignoring time component)
		assert.Equal(t, expected.Year(), result.Year())
		assert.Equal(t, expected.Month(), result.Month())
		assert.Equal(t, expected.Day(), result.Day())
	})

	t.Run("relative time - 1 day ago", func(t *testing.T) {
		result, err := ParseFlexibleTime("1 day ago")
		expected := time.Now().AddDate(0, 0, -1)

		assert.NoError(t, err)
		assert.Equal(t, expected.Year(), result.Year())
		assert.Equal(t, expected.Month(), result.Month())
		assert.Equal(t, expected.Day(), result.Day())
	})

	t.Run("relative time - hours ago", func(t *testing.T) {
		result, err := ParseFlexibleTime("2 hours ago")
		expected := time.Now().Add(-2 * time.Hour)

		assert.NoError(t, err)
		// Within a few seconds tolerance
		diff := expected.Sub(result)
		assert.True(t, diff < time.Second && diff > -time.Second)
	})

	t.Run("relative time - weeks ago", func(t *testing.T) {
		result, err := ParseFlexibleTime("2 weeks ago")
		expected := time.Now().AddDate(0, 0, -14)

		assert.NoError(t, err)
		assert.Equal(t, expected.Year(), result.Year())
		assert.Equal(t, expected.Month(), result.Month())
		assert.Equal(t, expected.Day(), result.Day())
	})

	t.Run("relative time - months ago", func(t *testing.T) {
		result, err := ParseFlexibleTime("3 months ago")
		expected := time.Now().AddDate(0, -3, 0)

		assert.NoError(t, err)
		assert.Equal(t, expected.Year(), result.Year())
		assert.Equal(t, expected.Month(), result.Month())
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := ParseFlexibleTime("")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty time string")
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := ParseFlexibleTime("not a date")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse time")
	})
}

func TestFilterDeploymentsByTime(t *testing.T) {
	// Create test deployments with different timestamps
	deployments := []Deployment{
		{ID: 1, Revision: "v1", Timestamp: "2025-01-10T10:00:00Z"},
		{ID: 2, Revision: "v2", Timestamp: "2025-01-12T10:00:00Z"},
		{ID: 3, Revision: "v3", Timestamp: "2025-01-14T10:00:00Z"},
		{ID: 4, Revision: "v4", Timestamp: "2025-01-16T10:00:00Z"},
	}

	t.Run("no filtering when both zero", func(t *testing.T) {
		result := FilterDeploymentsByTime(deployments, time.Time{}, time.Time{})
		assert.Len(t, result, 4)
	})

	t.Run("filter by since only", func(t *testing.T) {
		since, _ := time.Parse(time.RFC3339, "2025-01-13T00:00:00Z")
		result := FilterDeploymentsByTime(deployments, since, time.Time{})

		assert.Len(t, result, 2)
		assert.Equal(t, 3, result[0].ID)
		assert.Equal(t, 4, result[1].ID)
	})

	t.Run("filter by until only", func(t *testing.T) {
		until, _ := time.Parse(time.RFC3339, "2025-01-13T00:00:00Z")
		result := FilterDeploymentsByTime(deployments, time.Time{}, until)

		assert.Len(t, result, 2)
		assert.Equal(t, 1, result[0].ID)
		assert.Equal(t, 2, result[1].ID)
	})

	t.Run("filter by both since and until", func(t *testing.T) {
		since, _ := time.Parse(time.RFC3339, "2025-01-11T00:00:00Z")
		until, _ := time.Parse(time.RFC3339, "2025-01-15T00:00:00Z")
		result := FilterDeploymentsByTime(deployments, since, until)

		assert.Len(t, result, 2)
		assert.Equal(t, 2, result[0].ID)
		assert.Equal(t, 3, result[1].ID)
	})

	t.Run("unparseable timestamp included", func(t *testing.T) {
		deploymentsWithBadTS := []Deployment{
			{ID: 1, Revision: "v1", Timestamp: "not-a-date"},
			{ID: 2, Revision: "v2", Timestamp: "2025-01-14T10:00:00Z"},
		}
		since, _ := time.Parse(time.RFC3339, "2025-01-13T00:00:00Z")
		result := FilterDeploymentsByTime(deploymentsWithBadTS, since, time.Time{})

		// Both should be included - the unparseable one and the one after since
		assert.Len(t, result, 2)
	})
}

func TestParseDeploymentTimestamp(t *testing.T) {
	t.Run("RFC3339 format", func(t *testing.T) {
		result, err := ParseDeploymentTimestamp("2025-01-15T14:30:00Z")

		assert.NoError(t, err)
		assert.Equal(t, 2025, result.Year())
		assert.Equal(t, time.January, result.Month())
		assert.Equal(t, 15, result.Day())
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := ParseDeploymentTimestamp("not-a-timestamp")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse deployment timestamp")
	})
}
