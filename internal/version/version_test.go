package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	origVersion := Version
	origCommit := Commit
	origBuildDate := BuildDate

	Version = "1.0.0"
	Commit = "abc123"
	BuildDate = "2024-01-01T00:00:00Z"

	defer func() {
		Version = origVersion
		Commit = origCommit
		BuildDate = origBuildDate
	}()

	info := Info()
	assert.Equal(t, "1.0.0 (commit: abc123, built: 2024-01-01T00:00:00Z)", info)
}

func TestShort(t *testing.T) {
	origVersion := Version

	Version = "2.0.0"

	defer func() {
		Version = origVersion
	}()

	assert.Equal(t, "2.0.0", Short())
}
