package apps

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

func newGetCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <app-id>",
		Short: "Get details for a specific application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(opts, args[0])
		},
	}
}

func runGet(opts *root.Options, appID string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	app, err := client.GetApplication(appID)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(app)
	case "plain":
		return v.Plain([][]string{
			{fmt.Sprintf("%d", app.ID), app.Name, app.Language, app.HealthStatus},
		})
	default:
		v.Print("ID:              %d\n", app.ID)
		v.Print("Name:            %s\n", app.Name)
		v.Print("Language:        %s\n", app.Language)
		v.Print("Health Status:   %s\n", app.HealthStatus)
		v.Print("Reporting:       %t\n", app.Reporting)
		v.Print("Last Reported:   %s\n", app.LastReportedAt)
		return nil
	}
}
