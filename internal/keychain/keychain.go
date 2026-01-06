package keychain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	serviceName = "newrelic-cli"
)

// Credential keys
const (
	APIKeyKey    = "api_key"
	AccountIDKey = "account_id"
	RegionKey    = "region"
)

// GetAPIKey retrieves the New Relic API key
func GetAPIKey() (string, error) {
	// Try secure storage first
	key, err := getCredential(APIKeyKey)
	if err == nil && key != "" {
		return key, nil
	}

	// Fallback to environment variable
	key = os.Getenv("NEWRELIC_API_KEY")
	if key != "" {
		return key, nil
	}

	return "", fmt.Errorf("no API key found - run 'newrelic-cli config set-api-key' or set NEWRELIC_API_KEY")
}

// SetAPIKey stores the New Relic API key
func SetAPIKey(key string) error {
	return setCredential(APIKeyKey, key)
}

// DeleteAPIKey removes the New Relic API key
func DeleteAPIKey() error {
	return deleteCredential(APIKeyKey)
}

// GetAccountID retrieves the New Relic account ID
func GetAccountID() (string, error) {
	// Try secure storage first
	id, err := getCredential(AccountIDKey)
	if err == nil && id != "" {
		return id, nil
	}

	// Fallback to environment variable
	id = os.Getenv("NEWRELIC_ACCOUNT_ID")
	if id != "" {
		return id, nil
	}

	return "", fmt.Errorf("no account ID found - run 'newrelic-cli config set-account-id' or set NEWRELIC_ACCOUNT_ID")
}

// SetAccountID stores the New Relic account ID
func SetAccountID(id string) error {
	return setCredential(AccountIDKey, id)
}

// DeleteAccountID removes the New Relic account ID
func DeleteAccountID() error {
	return deleteCredential(AccountIDKey)
}

// GetRegion retrieves the New Relic region (US or EU)
func GetRegion() string {
	// Try secure storage first
	region, err := getCredential(RegionKey)
	if err == nil && region != "" {
		return region
	}

	// Fallback to environment variable
	region = os.Getenv("NEWRELIC_REGION")
	if region != "" {
		return strings.ToUpper(region)
	}

	return "US"
}

// SetRegion stores the New Relic region
func SetRegion(region string) error {
	return setCredential(RegionKey, strings.ToUpper(region))
}

// IsSecureStorage returns true if using secure storage (macOS Keychain)
func IsSecureStorage() bool {
	return runtime.GOOS == "darwin"
}

// GetCredentialStatus returns the current credential status
func GetCredentialStatus() map[string]bool {
	status := make(map[string]bool)

	if key, _ := getCredential(APIKeyKey); key != "" {
		status["api_key_stored"] = true
	}
	if id, _ := getCredential(AccountIDKey); id != "" {
		status["account_id_stored"] = true
	}
	if region, _ := getCredential(RegionKey); region != "" {
		status["region_stored"] = true
	}

	status["api_key_env"] = os.Getenv("NEWRELIC_API_KEY") != ""
	status["account_id_env"] = os.Getenv("NEWRELIC_ACCOUNT_ID") != ""
	status["region_env"] = os.Getenv("NEWRELIC_REGION") != ""

	return status
}

// --- Platform-specific implementations ---

func getCredential(key string) (string, error) {
	if runtime.GOOS == "darwin" {
		return getFromKeychain(key)
	}
	return getFromConfigFile(key)
}

func setCredential(key, value string) error {
	if runtime.GOOS == "darwin" {
		return setInKeychain(key, value)
	}
	return setInConfigFile(key, value)
}

func deleteCredential(key string) error {
	if runtime.GOOS == "darwin" {
		return deleteFromKeychain(key)
	}
	return deleteFromConfigFile(key)
}

// --- macOS Keychain ---

func getFromKeychain(account string) (string, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-s", serviceName,
		"-a", account,
		"-w")

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

func setInKeychain(account, value string) error {
	// First try to delete any existing item (ignore errors)
	_ = deleteFromKeychain(account)

	cmd := exec.Command("security", "add-generic-password",
		"-s", serviceName,
		"-a", account,
		"-w", value,
		"-U") // Update if exists

	return cmd.Run()
}

func deleteFromKeychain(account string) error {
	cmd := exec.Command("security", "delete-generic-password",
		"-s", serviceName,
		"-a", account)

	return cmd.Run()
}

// --- Config File (Linux fallback) ---

func getConfigDir() string {
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "newrelic-cli")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "newrelic-cli")
}

func getConfigFilePath() string {
	return filepath.Join(getConfigDir(), "credentials")
}

func getFromConfigFile(key string) (string, error) {
	data, err := os.ReadFile(getConfigFilePath())
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && parts[0] == key {
			return parts[1], nil
		}
	}

	return "", fmt.Errorf("key not found")
}

func setInConfigFile(key, value string) error {
	configDir := getConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	configPath := getConfigFilePath()

	// Read existing config
	existing := make(map[string]string)
	if data, err := os.ReadFile(configPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				existing[parts[0]] = parts[1]
			}
		}
	}

	// Update value
	existing[key] = value

	// Write back
	var lines []string
	for k, v := range existing {
		lines = append(lines, fmt.Sprintf("%s=%s", k, v))
	}

	return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}

func deleteFromConfigFile(key string) error {
	configPath := getConfigFilePath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var newLines []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && parts[0] != key {
			newLines = append(newLines, line)
		}
	}

	if len(newLines) == 0 {
		return os.Remove(configPath)
	}

	return os.WriteFile(configPath, []byte(strings.Join(newLines, "\n")+"\n"), 0600)
}
