package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/internal/client"
	"github.com/spf13/cobra"
)

var deploymentsCmd = &cobra.Command{
	Use:     "deployments",
	Aliases: []string{"deploy"},
	Short:   "Manage application deployments",
}

var listDeploymentsCmd = &cobra.Command{
	Use:   "list <app-id>",
	Short: "List deployments for an application",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		deployments, err := c.ListDeployments(args[0])
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(deployments, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(deployments) == 0 {
			fmt.Println("No deployments found")
			return nil
		}

		fmt.Printf("%-10s %-20s %-30s %s\n", "ID", "REVISION", "TIMESTAMP", "USER")
		fmt.Println(strings.Repeat("-", 80))
		for _, d := range deployments {
			fmt.Printf("%-10d %-20s %-30s %s\n",
				d.ID,
				truncate(d.Revision, 20),
				d.Timestamp,
				d.User,
			)
		}

		return nil
	},
}

var createDeploymentCmd = &cobra.Command{
	Use:   "create <app-id>",
	Short: "Record a new deployment for an application",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := client.New()
		if err != nil {
			return err
		}

		revision, _ := cmd.Flags().GetString("revision")
		description, _ := cmd.Flags().GetString("description")
		user, _ := cmd.Flags().GetString("user")
		changelog, _ := cmd.Flags().GetString("changelog")

		if revision == "" {
			return fmt.Errorf("--revision is required")
		}

		deployment, err := c.CreateDeployment(args[0], revision, description, user, changelog)
		if err != nil {
			return err
		}

		if outputJSON {
			data, _ := json.MarshalIndent(deployment, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("Created deployment:\n")
		fmt.Printf("  ID:        %d\n", deployment.ID)
		fmt.Printf("  Revision:  %s\n", deployment.Revision)
		fmt.Printf("  Timestamp: %s\n", deployment.Timestamp)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(deploymentsCmd)
	deploymentsCmd.AddCommand(listDeploymentsCmd)

	deploymentsCmd.AddCommand(createDeploymentCmd)
	createDeploymentCmd.Flags().StringP("revision", "r", "", "Deployment revision (required)")
	createDeploymentCmd.Flags().StringP("description", "d", "", "Deployment description")
	createDeploymentCmd.Flags().StringP("user", "u", "", "User who performed the deployment")
	createDeploymentCmd.Flags().StringP("changelog", "c", "", "Changelog for the deployment")
}
