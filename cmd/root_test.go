package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd_Help(t *testing.T) {
	stdout, _, err := executeCommand(rootCmd, "help")
	require.NoError(t, err)
	assert.Contains(t, stdout, "newrelic-cli")
	assert.Contains(t, stdout, "Available Commands")
}

func TestRootCmd_JSONFlagRecognized(t *testing.T) {
	// Test that --json flag exists and is recognized
	stdout, _, err := executeCommand(rootCmd, "help")
	require.NoError(t, err)
	assert.Contains(t, stdout, "--json")
}

func TestRootCmd_UnknownCommand(t *testing.T) {
	_, _, err := executeCommand(rootCmd, "nonexistent-command-xyz")
	require.Error(t, err)
}

func TestTruncate_Short(t *testing.T) {
	result := truncate("short", 10)
	assert.Equal(t, "short", result)
}

func TestTruncate_Exact(t *testing.T) {
	result := truncate("exactly10!", 10)
	assert.Equal(t, "exactly10!", result)
}

func TestTruncate_Long(t *testing.T) {
	result := truncate("this is a very long string", 10)
	assert.Equal(t, "this is...", result)
}

func TestTruncate_Empty(t *testing.T) {
	result := truncate("", 10)
	assert.Equal(t, "", result)
}
