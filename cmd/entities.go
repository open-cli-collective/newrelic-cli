package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var entitiesCmd = &cobra.Command{
	Use:   "entities",
	Short: "Search and manage New Relic entities",
}

var searchEntitiesCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search for entities",
	Long: `Search for entities using New Relic entity search query syntax.

Examples:
  newrelic-cli entities search "type = 'APPLICATION'"
  newrelic-cli entities search "name LIKE 'production%'"
  newrelic-cli entities search "domain = 'APM' AND accountId = 12345"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		entities, err := c.SearchEntities(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(entities, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(entities) == 0 {
			fmt.Println("No entities found")
			return nil
		}

		fmt.Printf("%-40s %-30s %-15s %s\n", "GUID", "NAME", "TYPE", "DOMAIN")
		fmt.Println(strings.Repeat("-", 100))
		for _, e := range entities {
			fmt.Printf("%-40s %-30s %-15s %s\n",
				truncate(e.GUID, 40),
				truncate(e.Name, 30),
				e.EntityType,
				e.Domain,
			)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(entitiesCmd)
	entitiesCmd.AddCommand(searchEntitiesCmd)
}
