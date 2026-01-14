package apps

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/view"
)

func newListCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all APM applications",
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

	apps, err := client.ListApplications()
	if err != nil {
		return err
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
