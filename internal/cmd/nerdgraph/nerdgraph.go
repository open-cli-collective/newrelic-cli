package nerdgraph

import (
	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/api"
	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

// Register adds the nerdgraph commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	nerdgraphCmd := &cobra.Command{
		Use:     "nerdgraph",
		Aliases: []string{"ng", "graphql"},
		Short:   "Execute NerdGraph GraphQL queries",
	}

	nerdgraphCmd.AddCommand(newQueryCmd(opts))

	rootCmd.AddCommand(nerdgraphCmd)
}

func newQueryCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "query <graphql-query>",
		Short: "Execute a GraphQL query",
		Long: `Execute a GraphQL query against the NerdGraph API.

Example:
  newrelic-cli nerdgraph query '{ actor { user { email } } }'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuery(opts, args[0])
		},
	}
}

func runQuery(opts *root.Options, query string) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	result, err := client.NerdGraphQuery(query, nil)
	if err != nil {
		return err
	}

	v := opts.View()
	return v.JSON(result)
}
