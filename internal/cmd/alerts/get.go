package alerts

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

func newGetPolicyCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <policy-id>",
		Short: "Get details for a specific alert policy",
		Long:  `Get detailed information about a specific alert policy including its incident preference setting.`,
		Example: `  newrelic-cli alerts policies get 12345
  newrelic-cli alerts policies get 12345 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGetPolicy(opts, args[0])
		},
	}
}

func runGetPolicy(opts *root.Options, policyID string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	policy, err := client.GetAlertPolicy(policyID)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(policy)
	case "plain":
		return v.Plain([][]string{
			{fmt.Sprintf("%d", policy.ID), policy.Name, policy.IncidentPreference},
		})
	default:
		v.Print("ID:                  %d\n", policy.ID)
		v.Print("Name:                %s\n", policy.Name)
		v.Print("Incident Preference: %s\n", policy.IncidentPreference)
		return nil
	}
}
