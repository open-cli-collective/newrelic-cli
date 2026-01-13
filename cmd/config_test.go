package cmd

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigCmd_Help(t *testing.T) {
	stdout, _, err := executeCommand(rootCmd, "config", "--help")
	require.NoError(t, err)
	assert.Contains(t, stdout, "config")
	assert.Contains(t, stdout, "set-api-key")
	assert.Contains(t, stdout, "set-account-id")
	assert.Contains(t, stdout, "set-region")
}

func TestSetAPIKeyCmd_WithArg(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdout, _, err := executeCommand(rootCmd, "config", "set-api-key", "NRAK-test-key-12345")
	require.NoError(t, err)
	assert.Contains(t, stdout, "API key stored")
}

func TestSetAPIKeyCmd_WithPrompt(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdout, _, err := executeCommandWithInput(rootCmd, "NRAK-prompted-key\n", "config", "set-api-key")
	require.NoError(t, err)
	assert.Contains(t, stdout, "API key stored")
}

func TestSetAPIKeyCmd_EmptyInput(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	_, _, err := executeCommandWithInput(rootCmd, "\n", "config", "set-api-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestSetAPIKeyCmd_NonNRAKWarning(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdout, _, err := executeCommand(rootCmd, "config", "set-api-key", "not-nrak-key")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Warning")
	assert.Contains(t, stdout, "NRAK-")
}

func TestSetAccountIDCmd_Valid(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdout, _, err := executeCommand(rootCmd, "config", "set-account-id", "12345")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Account ID stored")
}

func TestSetAccountIDCmd_MissingArg(t *testing.T) {
	_, _, err := executeCommand(rootCmd, "config", "set-account-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg")
}

func TestSetRegionCmd_US(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdout, _, err := executeCommand(rootCmd, "config", "set-region", "US")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Region set to US")
}

func TestSetRegionCmd_EU(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdout, _, err := executeCommand(rootCmd, "config", "set-region", "EU")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Region set to EU")
}

func TestSetRegionCmd_Lowercase(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdout, _, err := executeCommand(rootCmd, "config", "set-region", "eu")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Region set to EU")
}

func TestSetRegionCmd_Invalid(t *testing.T) {
	_, _, err := executeCommand(rootCmd, "config", "set-region", "APAC")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be US or EU")
}

func TestSetRegionCmd_MissingArg(t *testing.T) {
	_, _, err := executeCommand(rootCmd, "config", "set-region")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg")
}

func TestDeleteAPIKeyCmd(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// First set a key
	_, _, err := executeCommand(rootCmd, "config", "set-api-key", "NRAK-to-delete")
	require.NoError(t, err)

	// Then delete it
	stdout, _, err := executeCommand(rootCmd, "config", "delete-api-key")
	require.NoError(t, err)
	assert.Contains(t, stdout, "API key deleted")
}

func TestDeleteAccountIDCmd(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// First set an account ID
	_, _, err := executeCommand(rootCmd, "config", "set-account-id", "12345")
	require.NoError(t, err)

	// Then delete it
	stdout, _, err := executeCommand(rootCmd, "config", "delete-account-id")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Account ID deleted")
}

func TestShowConfigCmd(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("NEWRELIC_API_KEY", "")
	t.Setenv("NEWRELIC_ACCOUNT_ID", "")
	t.Setenv("NEWRELIC_REGION", "")

	stdout, _, err := executeCommand(rootCmd, "config", "show")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Configuration Status")
	assert.Contains(t, stdout, "Region")
}

func TestShowConfigCmd_WithCredentials(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config tests use keychain on darwin")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("NEWRELIC_API_KEY", "")
	t.Setenv("NEWRELIC_ACCOUNT_ID", "")
	t.Setenv("NEWRELIC_REGION", "")

	// Set credentials
	_, _, _ = executeCommand(rootCmd, "config", "set-api-key", "NRAK-1234567890abcdef")
	_, _, _ = executeCommand(rootCmd, "config", "set-account-id", "12345")
	_, _, _ = executeCommand(rootCmd, "config", "set-region", "US")

	stdout, _, err := executeCommand(rootCmd, "config", "show")
	require.NoError(t, err)
	assert.Contains(t, stdout, "API Key")
	assert.Contains(t, stdout, "Account ID")
	assert.Contains(t, stdout, "Region")
	assert.Contains(t, stdout, "12345")
	// API key should be masked
	assert.Contains(t, stdout, "****")
}
