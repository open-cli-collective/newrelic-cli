package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var nrqlCmd = &cobra.Command{
	Use:   "nrql <query>",
	Short: "Execute an NRQL query",
	Long: `Execute an NRQL query against your New Relic account.

Examples:
  newrelic-cli nrql "SELECT count(*) FROM Transaction SINCE 1 day ago"
  newrelic-cli nrql "SELECT average(duration) FROM Transaction FACET appName SINCE 1 hour ago"
  newrelic-cli nrql "FROM Log SELECT * WHERE level = 'ERROR' SINCE 30 minutes ago LIMIT 10"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		if err := c.RequireAccountID(); err != nil {
			return err
		}

		result, err := c.QueryNRQL(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(result.Results) == 0 {
			fmt.Println("No results")
			return nil
		}

		// Try to display results in a table format
		// Get all keys from the first result
		if len(result.Results) > 0 {
			first := result.Results[0]
			keys := make([]string, 0, len(first))
			for k := range first {
				keys = append(keys, k)
			}

			// Print header
			for _, k := range keys {
				fmt.Printf("%-20s ", k)
			}
			fmt.Println()
			fmt.Println(strings.Repeat("-", 20*len(keys)))

			// Print rows
			for _, row := range result.Results {
				for _, k := range keys {
					val := row[k]
					switch v := val.(type) {
					case float64:
						fmt.Printf("%-20.2f ", v)
					case string:
						fmt.Printf("%-20s ", truncate(v, 20))
					default:
						fmt.Printf("%-20v ", v)
					}
				}
				fmt.Println()
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(nrqlCmd)
}
