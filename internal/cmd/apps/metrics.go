package apps

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

func newMetricsCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "metrics <app-id>",
		Short: "List available metrics for an application",
		Long: `List all available metric names for an APM application.

Metric names follow the format: Category/Name (e.g., Apdex, HttpDispatcher,
WebTransaction/Function/handler). Use these names with the Metric API or
in NRQL queries with FROM Metric.`,
		Example: `  newrelic-cli apps metrics 12345678
  newrelic-cli apps metrics 12345678 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMetrics(opts, args[0])
		},
	}
}

func runMetrics(opts *root.Options, appID string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	metrics, err := client.ListApplicationMetrics(appID)
	if err != nil {
		return err
	}

	v := opts.View()

	if len(metrics) == 0 {
		v.Println("No metrics found")
		return nil
	}

	switch v.Format {
	case "json":
		return v.JSON(metrics)
	case "plain":
		rows := make([][]string, len(metrics))
		for i, m := range metrics {
			rows[i] = []string{m.Name}
		}
		return v.Plain(rows)
	default:
		v.Print("Found %d metrics for application %s:\n\n", len(metrics), appID)
		for _, m := range metrics {
			fmt.Fprintf(opts.Stdout, "  %s\n", m.Name)
		}
		return nil
	}
}
