package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var nerdgraphCmd = &cobra.Command{
	Use:   "nerdgraph",
	Short: "Execute NerdGraph GraphQL queries",
}

var nerdgraphQueryCmd = &cobra.Command{
	Use:   "query <graphql>",
	Short: "Execute a NerdGraph GraphQL query",
	Long: `Execute a custom NerdGraph GraphQL query.

Examples:
  newrelic-cli nerdgraph query '{ actor { user { name email } } }'
  newrelic-cli nerdgraph query --file query.graphql
  newrelic-cli nerdgraph query --file query.graphql --variables '{"accountId": 12345}'`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		var query string

		// Get query from file or argument
		queryFile, _ := cmd.Flags().GetString("file")
		if queryFile != "" {
			data, err := os.ReadFile(queryFile)
			if err != nil {
				return fmt.Errorf("failed to read query file: %w", err)
			}
			query = string(data)
		} else if len(args) > 0 {
			query = args[0]
		} else {
			return fmt.Errorf("query required: provide as argument or use --file")
		}

		// Parse variables if provided
		var variables map[string]interface{}
		varsStr, _ := cmd.Flags().GetString("variables")
		if varsStr != "" {
			if err := json.Unmarshal([]byte(varsStr), &variables); err != nil {
				return fmt.Errorf("failed to parse variables JSON: %w", err)
			}
		}

		result, err := c.NerdGraphQuery(query, variables)
		if err != nil {
			return err
		}

		// Always output as JSON for GraphQL results
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(nerdgraphCmd)

	nerdgraphCmd.AddCommand(nerdgraphQueryCmd)
	nerdgraphQueryCmd.Flags().StringP("file", "f", "", "Read query from file")
	nerdgraphQueryCmd.Flags().StringP("variables", "v", "", "Variables as JSON object")
}
