package dashboards

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/api"
	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/view"
)

// Register adds the dashboards commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	dashboardsCmd := &cobra.Command{
		Use:     "dashboards",
		Aliases: []string{"dashboard", "dash"},
		Short:   "Manage New Relic dashboards",
	}

	dashboardsCmd.AddCommand(newListCmd(opts))
	dashboardsCmd.AddCommand(newGetCmd(opts))

	rootCmd.AddCommand(dashboardsCmd)
}

func newListCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all dashboards",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts)
		},
	}
}

func runList(opts *root.Options) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	dashboards, err := client.ListDashboards()
	if err != nil {
		return err
	}

	v := opts.View()

	if len(dashboards) == 0 {
		v.Println("No dashboards found")
		return nil
	}

	headers := []string{"GUID", "NAME", "ACCOUNT ID"}
	rows := make([][]string, len(dashboards))
	for i, d := range dashboards {
		rows[i] = []string{
			view.Truncate(d.GUID, 40),
			view.Truncate(d.Name, 40),
			fmt.Sprintf("%d", d.AccountID),
		}
	}

	return v.Render(headers, rows, dashboards)
}

func newGetCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <guid>",
		Short: "Get details for a specific dashboard",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(opts, args[0])
		},
	}
}

func runGet(opts *root.Options, guid string) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	dashboard, err := client.GetDashboard(guid)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(dashboard)
	case "plain":
		rows := [][]string{
			{dashboard.GUID, dashboard.Name, dashboard.Permissions},
		}
		return v.Plain(rows)
	default:
		v.Print("GUID:        %s\n", dashboard.GUID)
		v.Print("Name:        %s\n", dashboard.Name)
		v.Print("Description: %s\n", dashboard.Description)
		v.Print("Permissions: %s\n", dashboard.Permissions)
		v.Print("Pages:       %d\n", len(dashboard.Pages))
		for _, page := range dashboard.Pages {
			v.Print("  - %s (%d widgets)\n", page.Name, len(page.Widgets))
		}
		return nil
	}
}
