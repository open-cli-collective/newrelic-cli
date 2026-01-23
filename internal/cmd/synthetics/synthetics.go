package synthetics

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/confirm"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

// Register adds the synthetics commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	syntheticsCmd := &cobra.Command{
		Use:     "synthetics",
		Aliases: []string{"synthetic", "syn"},
		Short:   "Manage New Relic synthetic monitors",
	}

	syntheticsCmd.AddCommand(newListCmd(opts))
	syntheticsCmd.AddCommand(newGetCmd(opts))
	syntheticsCmd.AddCommand(newDeleteCmd(opts))

	rootCmd.AddCommand(syntheticsCmd)
}

func newListCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all synthetic monitors",
		Long: `List all synthetic monitors in your account.

Monitor types:
  SIMPLE:      Simple browser ping
  BROWSER:     Scripted browser
  SCRIPT_API:  API test
  SCRIPT_BROWSER: Scripted browser with custom scripts

Status values: ENABLED, DISABLED, MUTED`,
		Example: `  newrelic-cli synthetics list
  newrelic-cli synthetics list -o json`,
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

	monitors, err := client.ListSyntheticMonitors()
	if err != nil {
		return err
	}

	v := opts.View()

	if len(monitors) == 0 {
		v.Println("No synthetic monitors found")
		return nil
	}

	headers := []string{"ID", "NAME", "TYPE", "STATUS", "FREQUENCY"}
	rows := make([][]string, len(monitors))
	for i, m := range monitors {
		rows[i] = []string{
			view.Truncate(m.ID, 40),
			view.Truncate(m.Name, 30),
			m.Type,
			m.Status,
			fmt.Sprintf("%d min", m.Frequency),
		}
	}

	return v.Render(headers, rows, monitors)
}

func newGetCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <monitor-id>",
		Short: "Get details for a specific synthetic monitor",
		Long: `Get detailed information about a synthetic monitor including
its type, status, frequency, and target URI (for applicable types).`,
		Example: `  newrelic-cli synthetics get abc-123-def-456
  newrelic-cli synthetics get abc-123-def-456 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(opts, args[0])
		},
	}
}

func runGet(opts *root.Options, monitorID string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	monitor, err := client.GetSyntheticMonitor(monitorID)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(monitor)
	case "plain":
		return v.Plain([][]string{
			{monitor.ID, monitor.Name, monitor.Type, monitor.Status},
		})
	default:
		v.Print("ID:        %s\n", monitor.ID)
		v.Print("Name:      %s\n", monitor.Name)
		v.Print("Type:      %s\n", monitor.Type)
		v.Print("Status:    %s\n", monitor.Status)
		v.Print("Frequency: %d minutes\n", monitor.Frequency)
		if monitor.URI != "" {
			v.Print("URI:       %s\n", monitor.URI)
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
		Use:   "delete <monitor-id>",
		Short: "Delete a synthetic monitor",
		Long: `Delete a synthetic monitor by its ID.

By default, you will be prompted to confirm the deletion.
Use --force to skip the confirmation prompt.

WARNING: This action cannot be undone.`,
		Example: `  # Delete with confirmation
  newrelic-cli synthetics delete abc-123-def-456

  # Delete without confirmation (use with caution)
  newrelic-cli synthetics delete abc-123-def-456 --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDelete(deleteOpts, args[0])
		},
	}

	cmd.Flags().BoolVarP(&deleteOpts.force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func runDelete(opts *deleteOptions, monitorID string) error {
	v := opts.View()

	// First, fetch the monitor to show its name in the confirmation
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	monitor, err := client.GetSyntheticMonitor(monitorID)
	if err != nil {
		return fmt.Errorf("failed to get monitor: %w", err)
	}

	if !opts.force {
		p := &confirm.Prompter{
			In:  opts.Stdin,
			Out: opts.Stderr,
		}
		msg := fmt.Sprintf("Delete synthetic monitor \"%s\" (ID: %s)?", monitor.Name, view.Truncate(monitorID, 20))
		if !p.Confirm(msg) {
			v.Warning("Operation canceled")
			return nil
		}
	}

	if err := client.DeleteSyntheticMonitor(monitorID); err != nil {
		return fmt.Errorf("failed to delete monitor: %w", err)
	}

	v.Success("Synthetic monitor \"%s\" deleted", monitor.Name)
	return nil
}
