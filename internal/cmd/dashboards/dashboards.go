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
		Long: `List all dashboards in your account.

Displays dashboard GUID, name, and account ID. The GUID is a base64-encoded
entity identifier that can be used with 'dashboards get'.`,
		Example: `  newrelic-cli dashboards list
  newrelic-cli dashboards list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts)
		},
	}
}

func runList(opts *root.Options) error {
	client, err := opts.APIClient()
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
			view.Truncate(d.GUID.String(), 40),
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
		Long: `Get detailed information about a dashboard including its pages and widgets.

The GUID is a base64-encoded entity identifier from 'dashboards list' or
the New Relic UI (visible in the dashboard URL).`,
		Example: `  newrelic-cli dashboards get "MjcxMjY0MHxWSVp8REFTSEJPQVJEXDI5Mjg="
  newrelic-cli dashboards get "MjcxMjY0MHxWSVp8REFTSEJPQVJEXDI5Mjg=" -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(opts, api.EntityGUID(args[0]))
		},
	}
}

func runGet(opts *root.Options, guid api.EntityGUID) error {
	client, err := opts.APIClient()
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
			{dashboard.GUID.String(), dashboard.Name, dashboard.Permissions},
		}
		return v.Plain(rows)
	default:
		v.Print("GUID:        %s\n", dashboard.GUID.String())
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
