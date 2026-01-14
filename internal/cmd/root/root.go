package root

import (
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/api"
	"github.com/piekstra/newrelic-cli/internal/config"
	"github.com/piekstra/newrelic-cli/internal/version"
	"github.com/piekstra/newrelic-cli/internal/view"
)

// RegisterFunc is a function that registers a command
type RegisterFunc func(rootCmd *cobra.Command, opts *Options)

// Options contains global command options
type Options struct {
	Output  string
	NoColor bool
	Verbose bool
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// DefaultOptions returns options with defaults
func DefaultOptions() *Options {
	return &Options{
		Output: "table",
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

// View returns a configured view from options
func (o *Options) View() *view.View {
	v := view.New(o.Stdout, o.Stderr)
	v.Format = view.Format(o.Output)
	v.NoColor = o.NoColor
	return v
}

// APIClient creates a New Relic API client with options applied
func (o *Options) APIClient() (*api.Client, error) {
	apiKey, err := config.GetAPIKey()
	if err != nil {
		return nil, err
	}

	accountID, _ := config.GetAccountID() // Optional
	region := config.GetRegion()

	return api.NewWithConfig(api.ClientConfig{
		APIKey:    apiKey,
		AccountID: accountID,
		Region:    region,
		Verbose:   o.Verbose,
		Stderr:    o.Stderr,
	}), nil
}

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
	Version: version.Info(),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate output format
		output, _ := cmd.Flags().GetString("output")
		return view.ValidateFormat(output)
	},
}

var globalOpts = DefaultOptions()

func init() {
	rootCmd.PersistentFlags().StringVarP(&globalOpts.Output, "output", "o", "table",
		"Output format: table, json, or plain")
	rootCmd.PersistentFlags().BoolVar(&globalOpts.NoColor, "no-color", false,
		"Disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Verbose, "verbose", "v", false,
		"Enable verbose output (shows API requests)")

	// Keep backward compatibility with --json flag
	rootCmd.PersistentFlags().Bool("json", false, "Output in JSON format (deprecated: use -o json)")
	rootCmd.PersistentFlags().MarkDeprecated("json", "use --output json instead")
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

// RootCmd returns the root command (for registering subcommands)
func RootCmd() *cobra.Command {
	return rootCmd
}

// GlobalOpts returns the global options
func GlobalOpts() *Options {
	return globalOpts
}

// RegisterCommands registers all subcommands with the provided register functions
func RegisterCommands(registerFuncs ...RegisterFunc) {
	for _, register := range registerFuncs {
		register(rootCmd, globalOpts)
	}
}
