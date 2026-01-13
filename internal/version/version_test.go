package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	// Save original values
	origVersion := Version
	origCommit := Commit
	origBuildDate := BuildDate

	// Set test values
	Version = "1.0.0"
	Commit = "abc123"
	BuildDate = "2024-01-01T00:00:00Z"

	// Restore after test
	defer func() {
		Version = origVersion
		Commit = origCommit
		BuildDate = origBuildDate
	}()

	info := Info()
	assert.Equal(t, "1.0.0 (commit: abc123, built: 2024-01-01T00:00:00Z)", info)
}

func TestShort(t *testing.T) {
	// Save original value
	origVersion := Version

	// Set test value
	Version = "2.0.0"

	// Restore after test
	defer func() {
		Version = origVersion
	}()

	assert.Equal(t, "2.0.0", Short())
}
