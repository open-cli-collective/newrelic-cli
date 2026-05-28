package nerdgraph

import (
	"encoding/json"
	"io"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
)

// emitPassthroughJSON is the passthrough wire contract for `nrq nerdgraph
// query`: pretty-printed JSON with 2-space indent and a trailing newline.
// Extracted from runQuery so the byte shape can be pinned without a
// stubbed API client. Matches the format the deleted View.JSON path
// produced via MarshalWithMigration + json.Indent.
func emitPassthroughJSON(w io.Writer, result interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

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

NerdGraph is New Relic's GraphQL API, providing access to all New Relic
data and functionality. Use the NerdGraph API explorer to discover
available queries and mutations:
  https://api.newrelic.com/graphiql

Output is always JSON format.`,
		Example: `  # Get current user info
  nrq nerdgraph query '{ actor { user { email name } } }'

  # List accounts
  nrq nerdgraph query '{ actor { accounts { id name } } }'

  # Get entity by GUID
  nrq nerdgraph query '{
    actor {
      entity(guid: "YOUR_ENTITY_GUID") {
        name
        entityType
        domain
      }
    }
  }'

  # Run NRQL query via GraphQL
  nrq nerdgraph query '{
    actor {
      account(id: 12345678) {
        nrql(query: "SELECT count(*) FROM Transaction SINCE 1 hour ago") {
          results
        }
      }
    }
  }'

  # Search entities
  nrq nerdgraph query '{
    actor {
      entitySearch(query: "domain = '\''APM'\'' AND type = '\''APPLICATION'\''") {
        results {
          entities {
            guid
            name
          }
        }
      }
    }
  }'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuery(opts, args[0])
		},
	}
}

func runQuery(opts *root.Options, query string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	result, err := client.NerdGraphQuery(query, nil)
	if err != nil {
		return err
	}
	return emitPassthroughJSON(opts.Stdout, result)
}
