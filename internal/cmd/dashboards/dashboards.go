package dashboards

import (
	"encoding/json"
	"fmt"
	"os"

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
	dashboardsCmd.AddCommand(newCreateCmd(opts))
	dashboardsCmd.AddCommand(newUpdateCmd(opts))
	dashboardsCmd.AddCommand(newDeleteCmd(opts))

	rootCmd.AddCommand(dashboardsCmd)
}

type listOptions struct {
	*root.Options
	limit int
}

func newListCmd(opts *root.Options) *cobra.Command {
	listOpts := &listOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all dashboards",
		Long: `List all dashboards in your account.

Displays dashboard GUID, name, and account ID. The GUID is a base64-encoded
entity identifier that can be used with 'dashboards get'.`,
		Example: `  newrelic-cli dashboards list
  newrelic-cli dashboards list -o json
  newrelic-cli dashboards list --limit 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(listOpts)
		},
	}

	cmd.Flags().IntVarP(&listOpts.limit, "limit", "l", 0, "Limit number of results (0 = no limit)")

	return cmd
}

func runList(opts *listOptions) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	dashboards, err := client.ListDashboards()
	if err != nil {
		return err
	}

	// Apply limit
	if opts.limit > 0 && len(dashboards) > opts.limit {
		dashboards = dashboards[:opts.limit]
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

// createOptions holds options for the create command
type createOptions struct {
	*root.Options
	fromFile string
}

func newCreateCmd(opts *root.Options) *cobra.Command {
	createOpts := &createOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new dashboard from a JSON file",
		Long: `Create a new dashboard from a JSON file.

The JSON file should contain the dashboard definition with the following structure:
{
  "name": "Dashboard Name",
  "description": "Optional description",
  "permissions": "PUBLIC_READ_WRITE",
  "pages": [
    {
      "name": "Page 1",
      "widgets": [
        {
          "title": "Widget Title",
          "visualization": {"id": "viz.line"},
          "layout": {"column": 1, "row": 1, "width": 4, "height": 3},
          "rawConfiguration": {
            "nrqlQueries": [{"accountId": 123, "query": "SELECT count(*) FROM Transaction"}]
          }
        }
      ]
    }
  ]
}

Permissions: PUBLIC_READ_WRITE, PUBLIC_READ_ONLY, PRIVATE`,
		Example: `  # Create a dashboard from a JSON file
  newrelic-cli dashboards create --from-file dashboard.json

  # Create and output result as JSON
  newrelic-cli dashboards create --from-file dashboard.json -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(createOpts)
		},
	}

	cmd.Flags().StringVarP(&createOpts.fromFile, "from-file", "f", "", "Path to JSON file containing dashboard definition (required)")
	_ = cmd.MarkFlagRequired("from-file")

	return cmd
}

func runCreate(opts *createOptions) error {
	v := opts.View()

	// Read and parse the JSON file
	data, err := os.ReadFile(opts.fromFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var input api.DashboardInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate required fields
	if input.Name == "" {
		return fmt.Errorf("dashboard name is required")
	}
	if len(input.Pages) == 0 {
		return fmt.Errorf("at least one page is required")
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	dashboard, err := client.CreateDashboard(&input)
	if err != nil {
		return fmt.Errorf("failed to create dashboard: %w", err)
	}

	switch v.Format {
	case "json":
		return v.JSON(dashboard)
	case "plain":
		rows := [][]string{
			{dashboard.GUID.String(), dashboard.Name},
		}
		return v.Plain(rows)
	default:
		v.Success("Dashboard \"%s\" created", dashboard.Name)
		v.Print("GUID: %s\n", dashboard.GUID.String())
		return nil
	}
}

// updateOptions holds options for the update command
type updateOptions struct {
	*root.Options
	fromFile string
}

func newUpdateCmd(opts *root.Options) *cobra.Command {
	updateOpts := &updateOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "update <guid>",
		Short: "Update an existing dashboard from a JSON file",
		Long: `Update an existing dashboard from a JSON file.

The JSON file format is the same as for 'dashboards create'.
The GUID identifies which dashboard to update.`,
		Example: `  # Update a dashboard from a JSON file
  newrelic-cli dashboards update "MjcxMjY0MHxWSVp8REFTSEJPQVJEXDI5Mjg=" --from-file dashboard.json

  # Update and output result as JSON
  newrelic-cli dashboards update "MjcxMjY0MHxWSVp8REFTSEJPQVJEXDI5Mjg=" --from-file dashboard.json -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(updateOpts, api.EntityGUID(args[0]))
		},
	}

	cmd.Flags().StringVarP(&updateOpts.fromFile, "from-file", "f", "", "Path to JSON file containing dashboard definition (required)")
	_ = cmd.MarkFlagRequired("from-file")

	return cmd
}

func runUpdate(opts *updateOptions, guid api.EntityGUID) error {
	v := opts.View()

	// Read and parse the JSON file
	data, err := os.ReadFile(opts.fromFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var input api.DashboardInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate required fields
	if input.Name == "" {
		return fmt.Errorf("dashboard name is required")
	}
	if len(input.Pages) == 0 {
		return fmt.Errorf("at least one page is required")
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	dashboard, err := client.UpdateDashboard(guid, &input)
	if err != nil {
		return fmt.Errorf("failed to update dashboard: %w", err)
	}

	switch v.Format {
	case "json":
		return v.JSON(dashboard)
	case "plain":
		rows := [][]string{
			{dashboard.GUID.String(), dashboard.Name},
		}
		return v.Plain(rows)
	default:
		v.Success("Dashboard \"%s\" updated", dashboard.Name)
		v.Print("GUID: %s\n", dashboard.GUID.String())
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
