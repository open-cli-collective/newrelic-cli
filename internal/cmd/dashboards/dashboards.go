package dashboards

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/confirm"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
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
	dashboardsCmd.AddCommand(newDeleteCmd(opts))

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

// deleteOptions holds options for the delete command
type deleteOptions struct {
	*root.Options
	force bool
}

func newDeleteCmd(opts *root.Options) *cobra.Command {
	deleteOpts := &deleteOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "delete <guid>",
		Short: "Delete a dashboard",
		Long: `Delete a dashboard by its GUID.

By default, you will be prompted to confirm the deletion.
Use --force to skip the confirmation prompt.

WARNING: This action cannot be undone.`,
		Example: `  # Delete with confirmation
  newrelic-cli dashboards delete "MjcxMjY0MHxWSVp8REFTSEJPQVJEXDI5Mjg="

  # Delete without confirmation (use with caution)
  newrelic-cli dashboards delete "MjcxMjY0MHxWSVp8REFTSEJPQVJEXDI5Mjg=" --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDelete(deleteOpts, api.EntityGUID(args[0]))
		},
	}

	cmd.Flags().BoolVarP(&deleteOpts.force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func runDelete(opts *deleteOptions, guid api.EntityGUID) error {
	v := opts.View()

	// First, fetch the dashboard to show its name in the confirmation
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	dashboard, err := client.GetDashboard(guid)
	if err != nil {
		return fmt.Errorf("failed to get dashboard: %w", err)
	}

	if !opts.force {
		p := &confirm.Prompter{
			In:  opts.Stdin,
			Out: opts.Stderr,
		}
		msg := fmt.Sprintf("Delete dashboard \"%s\" (GUID: %s)?", dashboard.Name, view.Truncate(guid.String(), 20))
		if !p.Confirm(msg) {
			v.Warning("Operation canceled")
			return nil
		}
	}

	if err := client.DeleteDashboard(guid); err != nil {
		return fmt.Errorf("failed to delete dashboard: %w", err)
	}

	v.Success("Dashboard \"%s\" deleted", dashboard.Name)
	return nil
}
