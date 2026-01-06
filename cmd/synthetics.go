package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var syntheticsCmd = &cobra.Command{
	Use:     "synthetics",
	Aliases: []string{"syn"},
	Short:   "Manage New Relic Synthetic monitors",
}

var listMonitorsCmd = &cobra.Command{
	Use:   "list",
	Short: "List all synthetic monitors",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		monitors, err := c.ListSyntheticMonitors()
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(monitors, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(monitors) == 0 {
			fmt.Println("No synthetic monitors found")
			return nil
		}

		fmt.Printf("%-40s %-30s %-15s %s\n", "ID", "NAME", "TYPE", "STATUS")
		fmt.Println(strings.Repeat("-", 95))
		for _, m := range monitors {
			fmt.Printf("%-40s %-30s %-15s %s\n",
				m.ID,
				truncate(m.Name, 30),
				m.Type,
				m.Status,
			)
		}

		return nil
	},
}

var getMonitorCmd = &cobra.Command{
	Use:   "get <monitor-id>",
	Short: "Get details for a specific synthetic monitor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		monitor, err := c.GetSyntheticMonitor(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(monitor, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("ID:        %s\n", monitor.ID)
		fmt.Printf("Name:      %s\n", monitor.Name)
		fmt.Printf("Type:      %s\n", monitor.Type)
		fmt.Printf("Status:    %s\n", monitor.Status)
		fmt.Printf("Frequency: %d minutes\n", monitor.Frequency)
		if monitor.URI != "" {
			fmt.Printf("URI:       %s\n", monitor.URI)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(syntheticsCmd)
	syntheticsCmd.AddCommand(listMonitorsCmd)
	syntheticsCmd.AddCommand(getMonitorCmd)
}
