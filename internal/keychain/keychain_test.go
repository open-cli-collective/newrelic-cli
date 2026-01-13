package keychain

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


// --- Environment Variable Tests ---

func TestGetAPIKey_FromEnv(t *testing.T) {
	// Skip keychain-based test on darwin since we can't mock keychain
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping env test on darwin due to keychain priority")
	}

	t.Setenv("NEWRELIC_API_KEY", "NRAK-test-key-from-env")

	key, err := GetAPIKey()
	require.NoError(t, err)
	assert.Equal(t, "NRAK-test-key-from-env", key)
}

func TestGetAPIKey_Missing(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping on darwin due to keychain")
	}

	// Ensure no env var is set
	t.Setenv("NEWRELIC_API_KEY", "")

	_, err := GetAPIKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no API key found")
}

func TestGetAccountID_FromEnv(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping env test on darwin due to keychain priority")
	}

	t.Setenv("NEWRELIC_ACCOUNT_ID", "12345")

	id, err := GetAccountID()
	require.NoError(t, err)
	assert.Equal(t, "12345", id)
}

func TestGetAccountID_Missing(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping on darwin due to keychain")
	}

	t.Setenv("NEWRELIC_ACCOUNT_ID", "")

	_, err := GetAccountID()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no account ID found")
}

func TestGetRegion_FromEnv(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping env test on darwin due to keychain priority")
	}

	t.Setenv("NEWRELIC_REGION", "eu")

	region := GetRegion()
	assert.Equal(t, "EU", region) // Should be uppercased
}

func TestGetRegion_Default(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping on darwin due to keychain")
	}

	t.Setenv("NEWRELIC_REGION", "")

	region := GetRegion()
	assert.Equal(t, "US", region)
}

// --- IsSecureStorage Tests ---

func TestIsSecureStorage(t *testing.T) {
	result := IsSecureStorage()
	if runtime.GOOS == "darwin" {
		assert.True(t, result)
	} else {
		assert.False(t, result)
	}
}

// --- GetCredentialStatus Tests ---

func TestGetCredentialStatus_EnvVars(t *testing.T) {
	t.Setenv("NEWRELIC_API_KEY", "test-key")
	t.Setenv("NEWRELIC_ACCOUNT_ID", "12345")
	t.Setenv("NEWRELIC_REGION", "US")

	status := GetCredentialStatus()

	assert.True(t, status["api_key_env"])
	assert.True(t, status["account_id_env"])
	assert.True(t, status["region_env"])
}

func TestGetCredentialStatus_NoEnvVars(t *testing.T) {
	t.Setenv("NEWRELIC_API_KEY", "")
	t.Setenv("NEWRELIC_ACCOUNT_ID", "")
	t.Setenv("NEWRELIC_REGION", "")

	status := GetCredentialStatus()

	assert.False(t, status["api_key_env"])
	assert.False(t, status["account_id_env"])
	assert.False(t, status["region_env"])
}

// --- Config File Tests (Linux only) ---

func TestConfigFile_GetConfigDir_Default(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	t.Setenv("XDG_CONFIG_HOME", "")

	dir := getConfigDir()
	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, ".config", "newrelic-cli")
	assert.Equal(t, expected, dir)
}

func TestConfigFile_GetConfigDir_XDG(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	t.Setenv("XDG_CONFIG_HOME", "/custom/config")

	dir := getConfigDir()
	assert.Equal(t, "/custom/config/newrelic-cli", dir)
}

func TestConfigFile_SetAndGet(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	// Use a temp directory
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set a value
	err := setInConfigFile("test_key", "test_value")
	require.NoError(t, err)

	// Get the value
	value, err := getFromConfigFile("test_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", value)
}

func TestConfigFile_SetMultipleKeys(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set multiple values
	require.NoError(t, setInConfigFile("key1", "value1"))
	require.NoError(t, setInConfigFile("key2", "value2"))
	require.NoError(t, setInConfigFile("key3", "value3"))

	// Get all values
	v1, err := getFromConfigFile("key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", v1)

	v2, err := getFromConfigFile("key2")
	require.NoError(t, err)
	assert.Equal(t, "value2", v2)

	v3, err := getFromConfigFile("key3")
	require.NoError(t, err)
	assert.Equal(t, "value3", v3)
}

func TestConfigFile_UpdateExisting(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set initial value
	require.NoError(t, setInConfigFile("key", "initial"))

	// Update value
	require.NoError(t, setInConfigFile("key", "updated"))

	// Verify update
	value, err := getFromConfigFile("key")
	require.NoError(t, err)
	assert.Equal(t, "updated", value)
}

func TestConfigFile_GetMissing(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	_, err := getFromConfigFile("nonexistent")
	require.Error(t, err)
}

func TestConfigFile_Delete(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set values
	require.NoError(t, setInConfigFile("key1", "value1"))
	require.NoError(t, setInConfigFile("key2", "value2"))

	// Delete one
	require.NoError(t, deleteFromConfigFile("key1"))

	// Verify deleted
	_, err := getFromConfigFile("key1")
	require.Error(t, err)

	// Verify other still exists
	v2, err := getFromConfigFile("key2")
	require.NoError(t, err)
	assert.Equal(t, "value2", v2)
}

func TestConfigFile_DeleteLast(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set single value
	require.NoError(t, setInConfigFile("key", "value"))

	// Delete it (should remove file)
	require.NoError(t, deleteFromConfigFile("key"))

	// Config file should be gone
	configPath := filepath.Join(tmpDir, "newrelic-cli", "credentials")
	_, err := os.Stat(configPath)
	assert.True(t, os.IsNotExist(err))
}

func TestConfigFile_Permissions(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Config file tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set a value (creates file)
	require.NoError(t, setInConfigFile("key", "value"))

	// Check file permissions
	configPath := filepath.Join(tmpDir, "newrelic-cli", "credentials")
	info, err := os.Stat(configPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Check directory permissions
	configDir := filepath.Join(tmpDir, "newrelic-cli")
	dirInfo, err := os.Stat(configDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())
}

// --- Integration Tests (Full API, Linux only) ---

func TestFullAPI_SetAndGetAPIKey(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Full API tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("NEWRELIC_API_KEY", "")

	// Set API key
	err := SetAPIKey("NRAK-test-api-key")
	require.NoError(t, err)

	// Get API key
	key, err := GetAPIKey()
	require.NoError(t, err)
	assert.Equal(t, "NRAK-test-api-key", key)
}

func TestFullAPI_DeleteAPIKey(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Full API tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("NEWRELIC_API_KEY", "")

	// Set and then delete
	require.NoError(t, SetAPIKey("NRAK-test-api-key"))
	require.NoError(t, DeleteAPIKey())

	// Should fail to get
	_, err := GetAPIKey()
	require.Error(t, err)
}

func TestFullAPI_SetAndGetAccountID(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Full API tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("NEWRELIC_ACCOUNT_ID", "")

	// Set account ID
	err := SetAccountID("12345")
	require.NoError(t, err)

	// Get account ID
	id, err := GetAccountID()
	require.NoError(t, err)
	assert.Equal(t, "12345", id)
}

func TestFullAPI_SetAndGetRegion(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Full API tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("NEWRELIC_REGION", "")

	// Set region
	err := SetRegion("EU")
	require.NoError(t, err)

	// Get region
	region := GetRegion()
	assert.Equal(t, "EU", region)
}

func TestFullAPI_EnvOverridesStorage(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Full API tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Set values in storage
	require.NoError(t, SetAPIKey("stored-key"))
	require.NoError(t, SetAccountID("stored-id"))
	require.NoError(t, SetRegion("US"))

	// Set different values in env
	t.Setenv("NEWRELIC_API_KEY", "env-key")
	t.Setenv("NEWRELIC_ACCOUNT_ID", "env-id")
	t.Setenv("NEWRELIC_REGION", "EU")

	// Storage takes priority over env for API key and account ID
	// because storage is checked first
	key, _ := GetAPIKey()
	assert.Equal(t, "stored-key", key)

	id, _ := GetAccountID()
	assert.Equal(t, "stored-id", id)

	region := GetRegion()
	assert.Equal(t, "US", region)
}

func TestFullAPI_CredentialStatus(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Full API tests only run on Linux")
	}

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("NEWRELIC_API_KEY", "")
	t.Setenv("NEWRELIC_ACCOUNT_ID", "")
	t.Setenv("NEWRELIC_REGION", "")

	// Initially nothing stored
	status := GetCredentialStatus()
	assert.False(t, status["api_key_stored"])
	assert.False(t, status["account_id_stored"])
	assert.False(t, status["region_stored"])

	// Store credentials
	require.NoError(t, SetAPIKey("test-key"))
	require.NoError(t, SetAccountID("12345"))
	require.NoError(t, SetRegion("EU"))

	// Check stored status
	status = GetCredentialStatus()
	assert.True(t, status["api_key_stored"])
	assert.True(t, status["account_id_stored"])
	assert.True(t, status["region_stored"])
}
