package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	outputJSON bool
	version    = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "newrelic-cli",
	Short: "A CLI tool for interacting with New Relic",
	Long: `newrelic-cli is a command-line interface for New Relic.

It provides commands for managing applications, dashboards, alerts,
users, and other New Relic resources.

Configure your API key with:
  newrelic-cli config set-api-key

Set your account ID with:
  newrelic-cli config set-account-id <your-account-id>

Or set environment variables:
  NEWRELIC_API_KEY
  NEWRELIC_ACCOUNT_ID
  NEWRELIC_REGION (US or EU)`,
	Version: version,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
}
