package synthetics

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

// Register adds the synthetics commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	syntheticsCmd := &cobra.Command{
		Use:     "synthetics",
		Aliases: []string{"synthetic", "syn"},
		Short:   "Manage New Relic synthetic monitors",
	}

	syntheticsCmd.AddCommand(newListCmd(opts))
	syntheticsCmd.AddCommand(newGetCmd(opts))
	syntheticsCmd.AddCommand(newCreateCmd(opts))
	syntheticsCmd.AddCommand(newUpdateCmd(opts))
	syntheticsCmd.AddCommand(newDeleteCmd(opts))

	rootCmd.AddCommand(syntheticsCmd)
}

type listOptions struct {
	*root.Options
	limit int
}

func newListCmd(opts *root.Options) *cobra.Command {
	listOpts := &listOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all synthetic monitors",
		Long: `List all synthetic monitors in your account.

Monitor types:
  SIMPLE:      Simple browser ping
  BROWSER:     Scripted browser
  SCRIPT_API:  API test
  SCRIPT_BROWSER: Scripted browser with custom scripts

Status values: ENABLED, DISABLED, MUTED`,
		Example: `  nrq synthetics list
  nrq synthetics list -o json
  nrq synthetics list --limit 10`,
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

	monitors, err := client.ListSyntheticMonitors()
	if err != nil {
		return err
	}

	// Apply limit
	if opts.limit > 0 && len(monitors) > opts.limit {
		monitors = monitors[:opts.limit]
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
		Example: `  nrq synthetics get abc-123-def-456
  nrq synthetics get abc-123-def-456 -o json`,
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

// createOptions holds options for the create command
type createOptions struct {
	*root.Options
	fromFile string
}

func newCreateCmd(opts *root.Options) *cobra.Command {
	createOpts := &createOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new synthetic monitor from a JSON file",
		Long: `Create a new synthetic monitor from a JSON file.

The JSON file should contain the monitor definition with the following structure:
{
  "name": "Monitor Name",
  "type": "SIMPLE",
  "frequency": 10,
  "status": "ENABLED",
  "uri": "https://example.com",
  "locations": ["AWS_US_EAST_1", "AWS_US_WEST_1"]
}

Monitor types:
  SIMPLE:          Simple browser ping
  BROWSER:         Scripted browser
  SCRIPT_API:      API test
  SCRIPT_BROWSER:  Scripted browser with custom scripts

Status values: ENABLED, DISABLED, MUTED

Common locations: AWS_US_EAST_1, AWS_US_EAST_2, AWS_US_WEST_1, AWS_US_WEST_2,
                  AWS_EU_WEST_1, AWS_EU_WEST_2, AWS_EU_CENTRAL_1, AWS_AP_SOUTHEAST_1`,
		Example: `  # Create a monitor from a JSON file
  nrq synthetics create --from-file monitor.json

  # Create and output result as JSON
  nrq synthetics create --from-file monitor.json -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(createOpts)
		},
	}

	cmd.Flags().StringVarP(&createOpts.fromFile, "from-file", "f", "", "Path to JSON file containing monitor definition (required)")
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

	var input api.SyntheticMonitorInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate required fields
	if input.Name == "" {
		return fmt.Errorf("monitor name is required")
	}
	if input.Type == "" {
		return fmt.Errorf("monitor type is required (SIMPLE, BROWSER, SCRIPT_API, SCRIPT_BROWSER)")
	}
	if input.Frequency == 0 {
		return fmt.Errorf("monitor frequency is required (in minutes)")
	}
	if input.Status == "" {
		input.Status = "ENABLED"
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	monitor, err := client.CreateSyntheticMonitor(&input)
	if err != nil {
		return fmt.Errorf("failed to create monitor: %w", err)
	}

	switch v.Format {
	case "json":
		return v.JSON(monitor)
	case "plain":
		rows := [][]string{
			{monitor.ID, monitor.Name, monitor.Type, monitor.Status},
		}
		return v.Plain(rows)
	default:
		v.Success("Synthetic monitor \"%s\" created", monitor.Name)
		v.Print("ID:   %s\n", monitor.ID)
		v.Print("Type: %s\n", monitor.Type)
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
		Use:   "update <monitor-id>",
		Short: "Update an existing synthetic monitor from a JSON file",
		Long: `Update an existing synthetic monitor from a JSON file.

The JSON file format is similar to 'synthetics create', but the type cannot be changed.
The monitor-id identifies which monitor to update.`,
		Example: `  # Update a monitor from a JSON file
  nrq synthetics update abc-123-def-456 --from-file monitor.json

  # Update and output result as JSON
  nrq synthetics update abc-123-def-456 --from-file monitor.json -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(updateOpts, args[0])
		},
	}

	cmd.Flags().StringVarP(&updateOpts.fromFile, "from-file", "f", "", "Path to JSON file containing monitor definition (required)")
	_ = cmd.MarkFlagRequired("from-file")

	return cmd
}

func runUpdate(opts *updateOptions, monitorID string) error {
	v := opts.View()

	// Read and parse the JSON file
	data, err := os.ReadFile(opts.fromFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var input api.SyntheticMonitorInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate required fields
	if input.Name == "" {
		return fmt.Errorf("monitor name is required")
	}
	if input.Frequency == 0 {
		return fmt.Errorf("monitor frequency is required (in minutes)")
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	monitor, err := client.UpdateSyntheticMonitor(monitorID, &input)
	if err != nil {
		return fmt.Errorf("failed to update monitor: %w", err)
	}

	switch v.Format {
	case "json":
		return v.JSON(monitor)
	case "plain":
		rows := [][]string{
			{monitor.ID, monitor.Name, monitor.Type, monitor.Status},
		}
		return v.Plain(rows)
	default:
		v.Success("Synthetic monitor \"%s\" updated", monitor.Name)
		v.Print("ID:   %s\n", monitor.ID)
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
  nrq synthetics delete abc-123-def-456

  # Delete without confirmation (use with caution)
  nrq synthetics delete abc-123-def-456 --force`,
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
