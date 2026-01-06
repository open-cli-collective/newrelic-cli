package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var dashboardsCmd = &cobra.Command{
	Use:     "dashboards",
	Aliases: []string{"dash"},
	Short:   "Manage New Relic dashboards",
}

var listDashboardsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all dashboards",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		dashboards, err := c.ListDashboards()
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(dashboards, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(dashboards) == 0 {
			fmt.Println("No dashboards found")
			return nil
		}

		fmt.Printf("%-40s %s\n", "GUID", "NAME")
		fmt.Println(strings.Repeat("-", 80))
		for _, d := range dashboards {
			fmt.Printf("%-40s %s\n", truncate(d.GUID, 40), d.Name)
		}

		return nil
	},
}

var getDashboardCmd = &cobra.Command{
	Use:   "get <guid>",
	Short: "Get details for a specific dashboard",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		dashboard, err := c.GetDashboard(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(dashboard, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("GUID:        %s\n", dashboard.GUID)
		fmt.Printf("Name:        %s\n", dashboard.Name)
		fmt.Printf("Permissions: %s\n", dashboard.Permissions)
		if dashboard.Description != "" {
			fmt.Printf("Description: %s\n", dashboard.Description)
		}
		fmt.Printf("Pages:       %d\n", len(dashboard.Pages))
		fmt.Println()

		for i, page := range dashboard.Pages {
			fmt.Printf("Page %d: %s\n", i+1, page.Name)
			fmt.Printf("  GUID: %s\n", page.GUID)
			fmt.Printf("  Widgets: %d\n", len(page.Widgets))
			for _, w := range page.Widgets {
				vizID := ""
				if id, ok := w.Visualization["id"].(string); ok {
					vizID = id
				}
				fmt.Printf("    - [%s] %s (%s)\n", w.ID, w.Title, vizID)
			}
			fmt.Println()
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(dashboardsCmd)
	dashboardsCmd.AddCommand(listDashboardsCmd)
	dashboardsCmd.AddCommand(getDashboardCmd)
}
