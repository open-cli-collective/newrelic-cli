package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/keychain"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure newrelic-cli credentials",
}

var setAPIKeyCmd = &cobra.Command{
	Use:   "set-api-key [key]",
	Short: "Set the New Relic API key",
	Long: `Set the New Relic API key for authentication.

On macOS: Key is stored securely in the system Keychain.
On Linux: Key is stored in ~/.config/newrelic-cli/credentials (file permissions 0600).

If no key is provided as an argument, you will be prompted to enter it.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !keychain.IsSecureStorage() {
			fmt.Println("Warning: On Linux, your API key will be stored in a config file")
			fmt.Println("         (~/.config/newrelic-cli/credentials) with restricted permissions (0600).")
			fmt.Println("         This is less secure than macOS Keychain storage.")
			fmt.Println()
		}

		var apiKey string

		if len(args) > 0 {
			apiKey = args[0]
		} else {
			fmt.Print("Enter New Relic API key: ")
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}
			apiKey = strings.TrimSpace(input)
		}

		if apiKey == "" {
			return fmt.Errorf("API key cannot be empty")
		}

		if !strings.HasPrefix(apiKey, "NRAK-") {
			fmt.Println("Warning: New Relic User API keys typically start with 'NRAK-'")
		}

		if err := keychain.SetAPIKey(apiKey); err != nil {
			return fmt.Errorf("failed to store API key: %w", err)
		}

		if keychain.IsSecureStorage() {
			fmt.Println("API key stored securely in Keychain")
		} else {
			fmt.Println("API key stored in ~/.config/newrelic-cli/credentials")
		}
		return nil
	},
}

var deleteAPIKeyCmd = &cobra.Command{
	Use:   "delete-api-key",
	Short: "Delete the stored New Relic API key",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := keychain.DeleteAPIKey(); err != nil {
			return fmt.Errorf("failed to delete API key: %w", err)
		}

		if keychain.IsSecureStorage() {
			fmt.Println("API key deleted from Keychain")
		} else {
			fmt.Println("API key deleted from config file")
		}
		return nil
	},
}

var setAccountIDCmd = &cobra.Command{
	Use:   "set-account-id <account-id>",
	Short: "Set the New Relic account ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		accountID := args[0]

		if err := keychain.SetAccountID(accountID); err != nil {
			return fmt.Errorf("failed to store account ID: %w", err)
		}

		if keychain.IsSecureStorage() {
			fmt.Println("Account ID stored securely in Keychain")
		} else {
			fmt.Println("Account ID stored in config file")
		}
		return nil
	},
}

var deleteAccountIDCmd = &cobra.Command{
	Use:   "delete-account-id",
	Short: "Delete the stored New Relic account ID",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := keychain.DeleteAccountID(); err != nil {
			return fmt.Errorf("failed to delete account ID: %w", err)
		}

		if keychain.IsSecureStorage() {
			fmt.Println("Account ID deleted from Keychain")
		} else {
			fmt.Println("Account ID deleted from config file")
		}
		return nil
	},
}

var setRegionCmd = &cobra.Command{
	Use:   "set-region <region>",
	Short: "Set the New Relic region (US or EU)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		region := strings.ToUpper(args[0])
		if region != "US" && region != "EU" {
			return fmt.Errorf("region must be US or EU")
		}

		if err := keychain.SetRegion(region); err != nil {
			return fmt.Errorf("failed to store region: %w", err)
		}

		fmt.Printf("Region set to %s\n", region)
		return nil
	},
}

var showConfigCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration status",
	RunE: func(cmd *cobra.Command, args []string) error {
		status := keychain.GetCredentialStatus()

		fmt.Println("Configuration Status:")
		fmt.Println()

		// API Key
		if apiKey, err := keychain.GetAPIKey(); err == nil {
			masked := apiKey[:8] + strings.Repeat("*", len(apiKey)-12) + apiKey[len(apiKey)-4:]
			source := "stored"
			if status["api_key_env"] {
				source = "environment"
			}
			fmt.Printf("  API Key:    %s (%s)\n", masked, source)
		} else {
			fmt.Println("  API Key:    Not configured")
		}

		// Account ID
		if accountID, err := keychain.GetAccountID(); err == nil {
			source := "stored"
			if status["account_id_env"] {
				source = "environment"
			}
			fmt.Printf("  Account ID: %s (%s)\n", accountID, source)
		} else {
			fmt.Println("  Account ID: Not configured")
		}

		// Region
		region := keychain.GetRegion()
		source := "default"
		if status["region_stored"] {
			source = "stored"
		} else if status["region_env"] {
			source = "environment"
		}
		fmt.Printf("  Region:     %s (%s)\n", region, source)

		fmt.Println()

		// Storage type
		if keychain.IsSecureStorage() {
			fmt.Println("Storage: macOS Keychain (secure)")
		} else {
			fmt.Println("Storage: Config file (~/.config/newrelic-cli/credentials)")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(setAPIKeyCmd)
	configCmd.AddCommand(deleteAPIKeyCmd)
	configCmd.AddCommand(setAccountIDCmd)
	configCmd.AddCommand(deleteAccountIDCmd)
	configCmd.AddCommand(setRegionCmd)
	configCmd.AddCommand(showConfigCmd)
}
