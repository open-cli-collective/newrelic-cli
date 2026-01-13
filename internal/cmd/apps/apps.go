package apps

import (
	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

// Register adds the apps commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	appsCmd := &cobra.Command{
		Use:     "apps",
		Aliases: []string{"applications", "app"},
		Short:   "Manage New Relic APM applications",
	}

	appsCmd.AddCommand(newListCmd(opts))
	appsCmd.AddCommand(newGetCmd(opts))
	appsCmd.AddCommand(newMetricsCmd(opts))

	rootCmd.AddCommand(appsCmd)
}
