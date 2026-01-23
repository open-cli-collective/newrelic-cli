package alerts

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

type listPoliciesOptions struct {
	*root.Options
	limit int
}

func newListPoliciesCmd(opts *root.Options) *cobra.Command {
	listOpts := &listPoliciesOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all alert policies",
		Long: `List all alert policies in your account.

Incident preference values:
  PER_POLICY:             One incident per policy
  PER_CONDITION:          One incident per condition
  PER_CONDITION_AND_TARGET: One incident per condition and target`,
		Example: `  newrelic-cli alerts policies list
  newrelic-cli alerts policies list -o json
  newrelic-cli alerts policies list --limit 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListPolicies(listOpts)
		},
	}

	cmd.Flags().IntVarP(&listOpts.limit, "limit", "l", 0, "Limit number of results (0 = no limit)")

	return cmd
}

func runListPolicies(opts *listPoliciesOptions) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	policies, err := client.ListAlertPolicies()
	if err != nil {
		return err
	}

	// Apply limit
	if opts.limit > 0 && len(policies) > opts.limit {
		policies = policies[:opts.limit]
	}

	v := opts.View()

	if len(policies) == 0 {
		v.Println("No alert policies found")
		return nil
	}

	headers := []string{"ID", "NAME", "INCIDENT PREFERENCE"}
	rows := make([][]string, len(policies))
	for i, p := range policies {
		rows[i] = []string{
			fmt.Sprintf("%d", p.ID),
			view.Truncate(p.Name, 50),
			p.IncidentPreference,
		}
	}

	return v.Render(headers, rows, policies)
}
