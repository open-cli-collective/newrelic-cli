package alerts

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/view"
)

func newListPoliciesCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all alert policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListPolicies(opts)
		},
	}
}

func runListPolicies(opts *root.Options) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	policies, err := client.ListAlertPolicies()
	if err != nil {
		return err
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
