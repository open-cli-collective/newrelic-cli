package deployments

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/api"
	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/view"
)

// Register adds the deployments commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	deploymentsCmd := &cobra.Command{
		Use:     "deployments",
		Aliases: []string{"deployment", "deploy"},
		Short:   "Manage New Relic deployments",
	}

	deploymentsCmd.AddCommand(newListCmd(opts))
	deploymentsCmd.AddCommand(newCreateCmd(opts))

	rootCmd.AddCommand(deploymentsCmd)
}

func newListCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list <app-id>",
		Short: "List deployments for an application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts, args[0])
		},
	}
}

func runList(opts *root.Options, appID string) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	deployments, err := client.ListDeployments(appID)
	if err != nil {
		return err
	}

	v := opts.View()

	if len(deployments) == 0 {
		v.Println("No deployments found")
		return nil
	}

	headers := []string{"ID", "REVISION", "DESCRIPTION", "USER", "TIMESTAMP"}
	rows := make([][]string, len(deployments))
	for i, d := range deployments {
		rows[i] = []string{
			fmt.Sprintf("%d", d.ID),
			view.Truncate(d.Revision, 20),
			view.Truncate(d.Description, 30),
			view.Truncate(d.User, 15),
			d.Timestamp,
		}
	}

	return v.Render(headers, rows, deployments)
}

type createOptions struct {
	*root.Options
	revision    string
	description string
	user        string
	changelog   string
}

func newCreateCmd(opts *root.Options) *cobra.Command {
	createOpts := &createOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "create <app-id>",
		Short: "Create a deployment marker",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(createOpts, args[0])
		},
	}

	cmd.Flags().StringVarP(&createOpts.revision, "revision", "r", "", "Deployment revision (required)")
	cmd.Flags().StringVarP(&createOpts.description, "description", "d", "", "Deployment description")
	cmd.Flags().StringVarP(&createOpts.user, "user", "u", "", "User who deployed")
	cmd.Flags().StringVarP(&createOpts.changelog, "changelog", "c", "", "Changelog")
	cmd.MarkFlagRequired("revision")

	return cmd
}

func runCreate(opts *createOptions, appID string) error {
	client, err := api.New()
	if err != nil {
		return err
	}

	deployment, err := client.CreateDeployment(appID, opts.revision, opts.description, opts.user, opts.changelog)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(deployment)
	case "plain":
		return v.Plain([][]string{
			{fmt.Sprintf("%d", deployment.ID), deployment.Revision, deployment.Timestamp},
		})
	default:
		v.Success("Deployment created successfully")
		v.Print("ID:        %d\n", deployment.ID)
		v.Print("Revision:  %s\n", deployment.Revision)
		v.Print("Timestamp: %s\n", deployment.Timestamp)
		return nil
	}
}
