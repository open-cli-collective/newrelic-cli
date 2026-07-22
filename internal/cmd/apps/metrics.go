package apps

import (
	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
)

func newMetricsCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "metrics <app>",
		Short: "List available metrics for an application",
		Long: `List the metric names an APM application reported over the past day.

The application can be identified by numeric app ID, name, or entity GUID.
Requires a configured account ID (nrq config set --account-id): names are
read via NRQL (SELECT uniques(metricName) FROM Metric).

Metric names follow the format: Category/Name (e.g., Apdex, HttpDispatcher,
WebTransaction/Function/handler). Use these names in NRQL queries with
FROM Metric.`,
		Example: `  nrq apps metrics 12345678
  nrq apps metrics "my-production-app"`,
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
	case "plain":
		rows := make([][]string, len(metrics))
		for i, m := range metrics {
			rows[i] = []string{m.Name}
		}
		return v.Plain(rows)
	default:
		v.Print("Found %d metrics for application %s:\n\n", len(metrics), appID)
		for _, m := range metrics {
			v.Print("  %s\n", m.Name)
		}
		return nil
	}
}
