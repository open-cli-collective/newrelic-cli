package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var appsCmd = &cobra.Command{
	Use:     "apps",
	Aliases: []string{"applications"},
	Short:   "Manage New Relic APM applications",
}

var listAppsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all APM applications",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		apps, err := c.ListApplications()
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(apps, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(apps) == 0 {
			fmt.Println("No applications found")
			return nil
		}

		fmt.Printf("%-12s %-40s %-12s %s\n", "ID", "NAME", "LANGUAGE", "STATUS")
		fmt.Println(strings.Repeat("-", 80))
		for _, app := range apps {
			status := app.HealthStatus
			if !app.Reporting {
				status = "not reporting"
			}
			fmt.Printf("%-12d %-40s %-12s %s\n", app.ID, truncate(app.Name, 40), app.Language, status)
		}

		return nil
	},
}

var getAppCmd = &cobra.Command{
	Use:   "get <app-id>",
	Short: "Get details for a specific application",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		app, err := c.GetApplication(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(app, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("ID:              %d\n", app.ID)
		fmt.Printf("Name:            %s\n", app.Name)
		fmt.Printf("Language:        %s\n", app.Language)
		fmt.Printf("Health Status:   %s\n", app.HealthStatus)
		fmt.Printf("Reporting:       %t\n", app.Reporting)
		fmt.Printf("Last Reported:   %s\n", app.LastReportedAt)

		return nil
	},
}

var listMetricsCmd = &cobra.Command{
	Use:   "metrics <app-id>",
	Short: "List available metrics for an application",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		metrics, err := c.ListApplicationMetrics(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(metrics, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(metrics) == 0 {
			fmt.Println("No metrics found")
			return nil
		}

		fmt.Printf("Found %d metrics for application %s:\n\n", len(metrics), args[0])
		for _, m := range metrics {
			fmt.Printf("  %s\n", m.Name)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(appsCmd)
	appsCmd.AddCommand(listAppsCmd)
	appsCmd.AddCommand(getAppCmd)
	appsCmd.AddCommand(listMetricsCmd)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
