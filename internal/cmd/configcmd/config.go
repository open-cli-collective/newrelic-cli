package configcmd

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/config"
)

// Register adds the config commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configure newrelic-cli credentials",
	}

	configCmd.AddCommand(newSetAPIKeyCmd(opts))
	configCmd.AddCommand(newDeleteAPIKeyCmd(opts))
	configCmd.AddCommand(newSetAccountIDCmd(opts))
	configCmd.AddCommand(newDeleteAccountIDCmd(opts))
	configCmd.AddCommand(newSetRegionCmd(opts))
	configCmd.AddCommand(newShowCmd(opts))

	rootCmd.AddCommand(configCmd)
}

func newSetAPIKeyCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "set-api-key [key]",
		Short: "Set the New Relic API key",
		Long: `Set the New Relic API key for authentication.

On macOS: Key is stored securely in the system Keychain.
On Linux: Key is stored in ~/.config/newrelic-cli/credentials (file permissions 0600).

If no key is provided as an argument, you will be prompted to enter it.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetAPIKey(opts, args)
		},
	}
}

func runSetAPIKey(opts *root.Options, args []string) error {
	v := opts.View()

	if !config.IsSecureStorage() {
		v.Warning("Warning: On Linux, your API key will be stored in a config file")
		v.Println("         (~/.config/newrelic-cli/credentials) with restricted permissions (0600).")
		v.Println("         This is less secure than macOS Keychain storage.")
		v.Println("")
	}

	var apiKey string
	if len(args) > 0 {
		apiKey = args[0]
	} else {
		fmt.Fprint(opts.Stdout, "Enter New Relic API key: ")
		reader := bufio.NewReader(opts.Stdin)
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
		v.Warning("Warning: New Relic User API keys typically start with 'NRAK-'")
	}

	if err := config.SetAPIKey(apiKey); err != nil {
		return fmt.Errorf("failed to store API key: %w", err)
	}

	if config.IsSecureStorage() {
		v.Success("API key stored securely in Keychain")
	} else {
		v.Success("API key stored in ~/.config/newrelic-cli/credentials")
	}
	return nil
}

func newDeleteAPIKeyCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete-api-key",
		Short: "Delete the stored New Relic API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeleteAPIKey(opts)
		},
	}
}

func runDeleteAPIKey(opts *root.Options) error {
	v := opts.View()

	if err := config.DeleteAPIKey(); err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}

	if config.IsSecureStorage() {
		v.Success("API key deleted from Keychain")
	} else {
		v.Success("API key deleted from config file")
	}
	return nil
}

func newSetAccountIDCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "set-account-id <account-id>",
		Short: "Set the New Relic account ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetAccountID(opts, args[0])
		},
	}
}

func runSetAccountID(opts *root.Options, accountID string) error {
	v := opts.View()

	if err := config.SetAccountID(accountID); err != nil {
		return fmt.Errorf("failed to store account ID: %w", err)
	}

	if config.IsSecureStorage() {
		v.Success("Account ID stored securely in Keychain")
	} else {
		v.Success("Account ID stored in config file")
	}
	return nil
}

func newDeleteAccountIDCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete-account-id",
		Short: "Delete the stored New Relic account ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeleteAccountID(opts)
		},
	}
}

func runDeleteAccountID(opts *root.Options) error {
	v := opts.View()

	if err := config.DeleteAccountID(); err != nil {
		return fmt.Errorf("failed to delete account ID: %w", err)
	}

	if config.IsSecureStorage() {
		v.Success("Account ID deleted from Keychain")
	} else {
		v.Success("Account ID deleted from config file")
	}
	return nil
}

func newSetRegionCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "set-region <region>",
		Short: "Set the New Relic region (US or EU)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetRegion(opts, args[0])
		},
	}
}

func runSetRegion(opts *root.Options, region string) error {
	v := opts.View()

	region = strings.ToUpper(region)
	if region != "US" && region != "EU" {
		return fmt.Errorf("region must be US or EU")
	}

	if err := config.SetRegion(region); err != nil {
		return fmt.Errorf("failed to store region: %w", err)
	}

	v.Success("Region set to %s", region)
	return nil
}

func newShowCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show current configuration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShow(opts)
		},
	}
}

func runShow(opts *root.Options) error {
	v := opts.View()
	status := config.GetCredentialStatus()

	v.Println("Configuration Status:")
	v.Println("")

	// API Key
	if apiKey, err := config.GetAPIKey(); err == nil {
		masked := apiKey[:8] + strings.Repeat("*", len(apiKey)-12) + apiKey[len(apiKey)-4:]
		source := "stored"
		if status["api_key_env"] {
			source = "environment"
		}
		v.Print("  API Key:    %s (%s)\n", masked, source)
	} else {
		v.Println("  API Key:    Not configured")
	}

	// Account ID
	if accountID, err := config.GetAccountID(); err == nil {
		source := "stored"
		if status["account_id_env"] {
			source = "environment"
		}
		v.Print("  Account ID: %s (%s)\n", accountID, source)
	} else {
		v.Println("  Account ID: Not configured")
	}

	// Region
	region := config.GetRegion()
	source := "default"
	if status["region_stored"] {
		source = "stored"
	} else if status["region_env"] {
		source = "environment"
	}
	v.Print("  Region:     %s (%s)\n", region, source)

	v.Println("")

	// Storage type
	if config.IsSecureStorage() {
		v.Println("Storage: macOS Keychain (secure)")
	} else {
		v.Println("Storage: Config file (~/.config/newrelic-cli/credentials)")
	}

	return nil
}
