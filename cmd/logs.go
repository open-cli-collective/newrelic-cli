package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Manage log parsing rules",
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage log parsing rules",
}

var listRulesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all log parsing rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		rules, err := c.ListLogParsingRules()
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(rules, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(rules) == 0 {
			fmt.Println("No log parsing rules found")
			return nil
		}

		fmt.Printf("%-40s %-40s %s\n", "ID", "DESCRIPTION", "ENABLED")
		fmt.Println(strings.Repeat("-", 90))
		for _, r := range rules {
			enabled := "no"
			if r.Enabled {
				enabled = "yes"
			}
			fmt.Printf("%-40s %-40s %s\n",
				r.ID,
				truncate(r.Description, 40),
				enabled,
			)
		}

		return nil
	},
}

var createRuleCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new log parsing rule",
	Long: `Create a new log parsing rule.

Example:
  newrelic-cli logs rules create \
    --description "Parse user login events" \
    --grok "User %{UUID:user_id} logged in" \
    --nrql "SELECT * FROM Log WHERE message LIKE 'User % logged in'"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		description, _ := cmd.Flags().GetString("description")
		grok, _ := cmd.Flags().GetString("grok")
		nrql, _ := cmd.Flags().GetString("nrql")
		lucene, _ := cmd.Flags().GetString("lucene")
		enabled, _ := cmd.Flags().GetBool("enabled")

		if description == "" || grok == "" || nrql == "" {
			return fmt.Errorf("--description, --grok, and --nrql are required")
		}

		rule, err := c.CreateLogParsingRule(description, grok, nrql, enabled, lucene)
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(rule, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("Created log parsing rule:\n")
		fmt.Printf("  ID:          %s\n", rule.ID)
		fmt.Printf("  Description: %s\n", rule.Description)
		fmt.Printf("  Enabled:     %t\n", rule.Enabled)

		return nil
	},
}

var deleteRuleCmd = &cobra.Command{
	Use:   "delete <rule-id>",
	Short: "Delete a log parsing rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		if err := c.DeleteLogParsingRule(args[0]); err != nil {
			return err
		}

		fmt.Printf("Deleted log parsing rule: %s\n", args[0])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logsCmd)
	logsCmd.AddCommand(rulesCmd)

	rulesCmd.AddCommand(listRulesCmd)

	rulesCmd.AddCommand(createRuleCmd)
	createRuleCmd.Flags().StringP("description", "d", "", "Rule description (required)")
	createRuleCmd.Flags().StringP("grok", "g", "", "GROK pattern (required)")
	createRuleCmd.Flags().StringP("nrql", "n", "", "NRQL pattern (required)")
	createRuleCmd.Flags().StringP("lucene", "l", "", "Lucene filter (optional)")
	createRuleCmd.Flags().Bool("enabled", true, "Enable the rule (default: true)")

	rulesCmd.AddCommand(deleteRuleCmd)
}
