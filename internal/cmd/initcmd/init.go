package initcmd

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/validate"
)

type initOptions struct {
	*root.Options
	apiKey    string
	accountID string
	region    string
	noVerify  bool
}

// Register adds the init command to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	initOpts := &initOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactive setup wizard for New Relic CLI",
		Long: `Configure the New Relic CLI with your credentials.

This interactive wizard will guide you through setting up:
  - API key (stored securely in Keychain on macOS, config file on Linux)
  - Account ID
  - Region (US or EU)

After configuration, the connection is tested automatically.`,
		Example: `  # Interactive setup
  nrq init

  # Non-interactive setup
  nrq init --api-key NRAK-xxx --account-id 12345 --region US

  # Skip connection verification
  nrq init --no-verify`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(initOpts)
		},
	}

	cmd.Flags().StringVar(&initOpts.apiKey, "api-key", "", "API key (for non-interactive setup)")
	cmd.Flags().StringVar(&initOpts.accountID, "account-id", "", "Account ID (for non-interactive setup)")
	cmd.Flags().StringVar(&initOpts.region, "region", "", "Region: US or EU (for non-interactive setup)")
	cmd.Flags().BoolVar(&initOpts.noVerify, "no-verify", false, "Skip connection verification")

	rootCmd.AddCommand(cmd)
}

func runInit(opts *initOptions) error {
	v := opts.View()

	v.Println("New Relic CLI Setup")
	v.Println("")

	// Check for existing config
	status := config.GetCredentialStatus()
	if status["api_key_stored"] || status["account_id_stored"] {
		v.Warning("Existing configuration detected.")
		v.Println("This will overwrite your current settings.")
		v.Println("")
	}

	reader := bufio.NewReader(opts.Stdin)

	// Get API Key
	apiKey := opts.apiKey
	if apiKey == "" {
		fmt.Fprint(opts.Stdout, "API Key (NRAK-...): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		apiKey = strings.TrimSpace(input)
	}

	// Validate API key
	warning, err := validate.APIKey(apiKey)
	if err != nil {
		return err
	}
	if warning != "" {
		v.Warning("Warning: " + warning)
	}

	// Get Account ID
	accountID := opts.accountID
	if accountID == "" {
		fmt.Fprint(opts.Stdout, "Account ID: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		accountID = strings.TrimSpace(input)
	}

	// Validate account ID
	if accountID != "" {
		if err := validate.AccountID(accountID); err != nil {
			return err
		}
	}

	// Get Region
	region := opts.region
	if region == "" {
		fmt.Fprint(opts.Stdout, "Region (US/EU) [US]: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		region = strings.TrimSpace(input)
		if region == "" {
			region = "US"
		}
	}
	region = strings.ToUpper(region)

	// Validate region
	if err := validate.Region(region); err != nil {
		return err
	}

	v.Println("")

	// Store credentials
	if err := config.SetAPIKey(apiKey); err != nil {
		return fmt.Errorf("failed to store API key: %w", err)
	}

	if accountID != "" {
		if err := config.SetAccountID(accountID); err != nil {
			return fmt.Errorf("failed to store account ID: %w", err)
		}
	}

	if err := config.SetRegion(region); err != nil {
		return fmt.Errorf("failed to store region: %w", err)
	}

	// Verify connection (unless --no-verify)
	if !opts.noVerify {
		v.Println("Testing connection...")
		v.Println("")

		client, err := opts.APIClient()
		if err != nil {
			v.Error("Failed to create client: %v", err)
			v.Println("")
			v.Println("Configuration saved but connection test failed.")
			v.Println("You can test again with: nrq config test")
			return nil
		}

		result, err := client.TestConnection()
		if err != nil {
			v.Error("Connection test error: %v", err)
			return nil
		}

		if result.APIKeyValid {
			v.Success("API key valid")
		} else {
			v.Error("API key invalid or expired")
			if result.ErrorMessage != "" {
				v.Println("Error: " + result.ErrorMessage)
			}
			return nil
		}

		if accountID != "" {
			if result.AccountAccess {
				v.Success("Account %d accessible", result.AccountID)
			} else {
				v.Error("Account not accessible")
				if result.ErrorMessage != "" {
					v.Println("Error: " + result.ErrorMessage)
				}
			}
		}

		v.Println("")
	}

	v.Success("Configuration saved.")
	v.Println("")
	v.Println("Try it out:")
	v.Println("  nrq apps list")
	v.Println("  nrq nrql \"SELECT count(*) FROM Transaction\"")

	return nil
}
