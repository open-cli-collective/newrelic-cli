package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Manage New Relic alert policies",
}

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "Manage alert policies",
}

var listPoliciesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all alert policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		policies, err := c.ListAlertPolicies()
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(policies, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(policies) == 0 {
			fmt.Println("No alert policies found")
			return nil
		}

		fmt.Printf("%-12s %-50s %s\n", "ID", "NAME", "INCIDENT PREFERENCE")
		fmt.Println(strings.Repeat("-", 80))
		for _, p := range policies {
			fmt.Printf("%-12d %-50s %s\n", p.ID, truncate(p.Name, 50), p.IncidentPreference)
		}

		return nil
	},
}

var getPolicyCmd = &cobra.Command{
	Use:   "get <policy-id>",
	Short: "Get details for a specific alert policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		policy, err := c.GetAlertPolicy(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("ID:                  %d\n", policy.ID)
		fmt.Printf("Name:                %s\n", policy.Name)
		fmt.Printf("Incident Preference: %s\n", policy.IncidentPreference)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(alertsCmd)
	alertsCmd.AddCommand(policiesCmd)
	policiesCmd.AddCommand(listPoliciesCmd)
	policiesCmd.AddCommand(getPolicyCmd)
}
