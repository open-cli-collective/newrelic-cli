package entities

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/api"
	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/view"
)

// Register adds the entities commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	entitiesCmd := &cobra.Command{
		Use:     "entities",
		Aliases: []string{"entity", "ent"},
		Short:   "Search and manage New Relic entities",
	}

	entitiesCmd.AddCommand(newSearchCmd(opts))

	rootCmd.AddCommand(entitiesCmd)
}

func newSearchCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search for entities",
		Long: `Search for entities using NRQL-style queries.

Examples:
  newrelic-cli entities search "type = 'APPLICATION'"
  newrelic-cli entities search "name LIKE 'production%'"
  newrelic-cli entities search "domain = 'APM'"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSearch(opts, args[0])
		},
	}
}

func runSearch(opts *root.Options, query string) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	entities, err := client.SearchEntities(query)
	if err != nil {
		return err
	}

	v := opts.View()

	if len(entities) == 0 {
		v.Println("No entities found")
		return nil
	}

	headers := []string{"GUID", "NAME", "TYPE", "DOMAIN", "ACCOUNT ID"}
	rows := make([][]string, len(entities))
	for i, e := range entities {
		rows[i] = []string{
			view.Truncate(e.GUID, 40),
			view.Truncate(e.Name, 30),
			e.Type,
			e.Domain,
			fmt.Sprintf("%d", e.AccountID),
		}
	}

	return v.Render(headers, rows, entities)
}
