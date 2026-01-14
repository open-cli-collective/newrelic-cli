package nrql

import (
	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

// Register adds the nrql commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	nrqlCmd := &cobra.Command{
		Use:   "nrql",
		Short: "Execute NRQL queries",
	}

	nrqlCmd.AddCommand(newQueryCmd(opts))

	rootCmd.AddCommand(nrqlCmd)
}

func newQueryCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "query <nrql>",
		Short: "Execute an NRQL query",
		Long: `Execute an NRQL query against your New Relic account.

Examples:
  newrelic-cli nrql query "SELECT count(*) FROM Transaction SINCE 1 hour ago"
  newrelic-cli nrql query "SELECT * FROM Log LIMIT 10"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuery(opts, args[0])
		},
	}
}

func runQuery(opts *root.Options, nrql string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	result, err := client.QueryNRQL(nrql)
	if err != nil {
		return err
	}

	v := opts.View()
	return v.JSON(result)
}
