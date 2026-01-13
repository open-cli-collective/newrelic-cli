package alerts

import (
	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

// Register adds the alerts commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	alertsCmd := &cobra.Command{
		Use:     "alerts",
		Aliases: []string{"alert"},
		Short:   "Manage New Relic alerts",
	}

	policiesCmd := &cobra.Command{
		Use:   "policies",
		Short: "Manage alert policies",
	}

	policiesCmd.AddCommand(newListPoliciesCmd(opts))
	policiesCmd.AddCommand(newGetPolicyCmd(opts))

	alertsCmd.AddCommand(policiesCmd)
	rootCmd.AddCommand(alertsCmd)
}
