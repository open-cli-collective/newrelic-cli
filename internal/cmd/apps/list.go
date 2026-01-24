package apps

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

type listOptions struct {
	*root.Options
	limit int
}

func newListCmd(opts *root.Options) *cobra.Command {
	listOpts := &listOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all APM applications",
		Long: `List all APM applications in your account.

Displays application ID, name, language, and health status.
Health status values: green (healthy), orange (warning), red (critical), gray (not reporting).`,
		Example: `  # List all applications
  nrq apps list

  # Output as JSON for scripting
  nrq apps list -o json

  # Plain output for parsing
  nrq apps list -o plain | cut -f1  # Get app IDs only

  # Limit results
  nrq apps list --limit 5`,
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

	apps, err := client.ListApplications()
	if err != nil {
		return err
	}

	// Apply limit
	if opts.limit > 0 && len(apps) > opts.limit {
		apps = apps[:opts.limit]
	}

	v := opts.View()

	if len(apps) == 0 {
		v.Println("No applications found")
		return nil
	}

	headers := []string{"ID", "NAME", "LANGUAGE", "STATUS"}
	rows := make([][]string, len(apps))
	for i, app := range apps {
		status := app.HealthStatus
		if !app.Reporting {
			status = "not reporting"
		}
		rows[i] = []string{
			fmt.Sprintf("%d", app.ID),
			view.Truncate(app.Name, 40),
			app.Language,
			status,
		}
	}

	return v.Render(headers, rows, apps)
}
