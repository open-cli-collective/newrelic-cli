package entities

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/nrql"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

type searchOptions struct {
	*root.Options
	link bool
}

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
	searchOpts := &searchOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search for entities",
		Long: `Search for entities using NRQL-style query syntax.

Query syntax supports:
  - Equality:         type = 'APPLICATION'
  - Pattern matching: name LIKE 'prod%'
  - Logical operators: AND, OR
  - Domains:          domain = 'APM', 'INFRA', 'BROWSER', 'SYNTH', 'VIZ'
  - Types:            type = 'APPLICATION', 'HOST', 'DASHBOARD', etc.

Common domains and types:
  APM:      APPLICATION
  INFRA:    HOST, AWSLAMBDAFUNCTION
  BROWSER:  BROWSER_APPLICATION
  SYNTH:    MONITOR
  VIZ:      DASHBOARD`,
		Example: `  # Find all APM applications
  nrq entities search "type = 'APPLICATION'"

  # Find by name pattern
  nrq entities search "name LIKE 'production%'"

  # Find by domain
  nrq entities search "domain = 'APM'"

  # Combined conditions
  nrq entities search "domain = 'APM' AND name LIKE 'api%'"

  # Find dashboards
  nrq entities search "type = 'DASHBOARD'"

  # Include deep links to New Relic
  nrq entities search "domain = 'APM'" --link`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSearch(searchOpts, args[0])
		},
	}

	cmd.Flags().BoolVar(&searchOpts.link, "link", false, "Include New Relic deep link URLs in output")

	return cmd
}

func runSearch(opts *searchOptions, query string) error {
	client, err := opts.APIClient()
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
	if opts.link {
		headers = append(headers, "LINK")
	}

	rows := make([][]string, len(entities))
	for i, e := range entities {
		row := []string{
			view.Truncate(e.GUID.String(), 40),
			view.Truncate(e.Name, 30),
			e.Type,
			e.Domain,
			fmt.Sprintf("%d", e.AccountID),
		}
		if opts.link {
			row = append(row, nrql.BuildEntityDeepLink(e.GUID.String()))
		}
		rows[i] = row
	}

	return v.Render(headers, rows, entities)
}
