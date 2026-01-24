package deployments

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
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
	deploymentsCmd.AddCommand(newSearchCmd(opts))

	rootCmd.AddCommand(deploymentsCmd)
}

type listOptions struct {
	*root.Options
	name  string
	guid  string
	since string
	until string
	limit int
}

func newListCmd(opts *root.Options) *cobra.Command {
	listOpts := &listOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "list [app-id]",
		Short: "List deployments for an application",
		Long: `List deployments for an application.

The application can be specified by:
  - Numeric app ID (positional argument)
  - Application name (--name flag)
  - Entity GUID (--guid flag)

Examples:
  # By app ID
  nrq deployments list 12345678

  # By application name
  nrq deployments list --name "my-production-app"

  # By entity GUID
  nrq deployments list --guid "MjcxMjY0MHxBUE18QVBQTElDQVRJT058MTM3NzA4OTc5OQ"

  # With time filtering
  nrq deployments list 12345678 --since "7 days ago"
  nrq deployments list --name "my-app" --since "2025-01-01" --until "2025-01-15"

  # Limit results
  nrq deployments list --name "my-app" --limit 5`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(listOpts, args)
		},
	}

	cmd.Flags().StringVarP(&listOpts.name, "name", "n", "", "Application name to look up")
	cmd.Flags().StringVarP(&listOpts.guid, "guid", "g", "", "Entity GUID to look up")
	cmd.Flags().StringVar(&listOpts.since, "since", "", "Show deployments after this time (e.g., '7 days ago', '2025-01-01')")
	cmd.Flags().StringVar(&listOpts.until, "until", "", "Show deployments before this time")
	cmd.Flags().IntVarP(&listOpts.limit, "limit", "l", 0, "Limit number of results (0 = no limit)")

	return cmd
}

func runList(opts *listOptions, args []string) error {
	// Determine the app identifier from flags or positional arg
	var identifier string
	switch {
	case opts.name != "":
		identifier = opts.name
	case opts.guid != "":
		identifier = opts.guid
	case len(args) > 0:
		identifier = args[0]
	default:
		return fmt.Errorf("application must be specified via positional argument, --name, or --guid")
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	// Resolve the identifier to a numeric app ID
	appID, err := client.ResolveAppID(identifier)
	if err != nil {
		return fmt.Errorf("failed to resolve application: %w", err)
	}

	deployments, err := client.ListDeployments(appID)
	if err != nil {
		return err
	}

	// Apply time filtering
	var since, until time.Time
	if opts.since != "" {
		since, err = api.ParseFlexibleTime(opts.since)
		if err != nil {
			return fmt.Errorf("invalid --since value: %w", err)
		}
	}
	if opts.until != "" {
		until, err = api.ParseFlexibleTime(opts.until)
		if err != nil {
			return fmt.Errorf("invalid --until value: %w", err)
		}
	}
	deployments = api.FilterDeploymentsByTime(deployments, since, until)

	// Apply limit
	if opts.limit > 0 && len(deployments) > opts.limit {
		deployments = deployments[:opts.limit]
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
	name        string
	guid        string
	revision    string
	description string
	user        string
	changelog   string
}

func newCreateCmd(opts *root.Options) *cobra.Command {
	createOpts := &createOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "create [app-id]",
		Short: "Create a deployment marker",
		Long: `Create a deployment marker for an application.

The application can be specified by:
  - Numeric app ID (positional argument)
  - Application name (--name flag)
  - Entity GUID (--guid flag)

Examples:
  nrq deployments create 12345678 --revision "v1.2.3"
  nrq deployments create --name "my-app" --revision "v1.2.3" --description "Bug fixes"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(createOpts, args)
		},
	}

	cmd.Flags().StringVarP(&createOpts.name, "name", "n", "", "Application name to look up")
	cmd.Flags().StringVarP(&createOpts.guid, "guid", "g", "", "Entity GUID to look up")
	cmd.Flags().StringVarP(&createOpts.revision, "revision", "r", "", "Deployment revision (required)")
	cmd.Flags().StringVarP(&createOpts.description, "description", "d", "", "Deployment description")
	cmd.Flags().StringVarP(&createOpts.user, "user", "u", "", "User who deployed")
	cmd.Flags().StringVarP(&createOpts.changelog, "changelog", "c", "", "Changelog")
	cmd.MarkFlagRequired("revision")

	return cmd
}

func runCreate(opts *createOptions, args []string) error {
	// Determine the app identifier from flags or positional arg
	var identifier string
	switch {
	case opts.name != "":
		identifier = opts.name
	case opts.guid != "":
		identifier = opts.guid
	case len(args) > 0:
		identifier = args[0]
	default:
		return fmt.Errorf("application must be specified via positional argument, --name, or --guid")
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	// Resolve the identifier to a numeric app ID
	appID, err := client.ResolveAppID(identifier)
	if err != nil {
		return fmt.Errorf("failed to resolve application: %w", err)
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

type searchOptions struct {
	*root.Options
	since string
	until string
	limit int
}

func newSearchCmd(opts *root.Options) *cobra.Command {
	searchOpts := &searchOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "search <nrql-where-clause>",
		Short: "Search deployments across applications using NRQL",
		Long: `Search for deployments across multiple applications using NRQL WHERE clause syntax.

This command queries the Deployment event type via NRQL, allowing you to search
across all applications in your account.

Examples:
  # Find deployments for apps matching a pattern
  nrq deployments search "entity.name LIKE '%insights%'"

  # Find deployments by a specific user
  nrq deployments search "user = 'deploy-bot'"

  # Search with time bounds
  nrq deployments search "entity.name LIKE '%prod%'" --since "7 days ago"

  # Limit results
  nrq deployments search "revision LIKE 'v2%'" --limit 10`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSearch(searchOpts, args[0])
		},
	}

	cmd.Flags().StringVar(&searchOpts.since, "since", "", "Search from this time (e.g., '7 days ago', '2025-01-01')")
	cmd.Flags().StringVar(&searchOpts.until, "until", "", "Search until this time")
	cmd.Flags().IntVarP(&searchOpts.limit, "limit", "l", 100, "Maximum number of results")

	return cmd
}

func runSearch(opts *searchOptions, whereClause string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	// Build the NRQL query
	nrql := fmt.Sprintf("SELECT * FROM Deployment WHERE %s", whereClause)

	// Add time bounds using SINCE/UNTIL
	if opts.since != "" {
		since, err := api.ParseFlexibleTime(opts.since)
		if err != nil {
			return fmt.Errorf("invalid --since value: %w", err)
		}
		nrql += fmt.Sprintf(" SINCE %d", since.Unix())
	}
	if opts.until != "" {
		until, err := api.ParseFlexibleTime(opts.until)
		if err != nil {
			return fmt.Errorf("invalid --until value: %w", err)
		}
		nrql += fmt.Sprintf(" UNTIL %d", until.Unix())
	}

	// Add limit
	if opts.limit > 0 {
		nrql += fmt.Sprintf(" LIMIT %d", opts.limit)
	}

	result, err := client.QueryNRQL(nrql)
	if err != nil {
		return err
	}

	v := opts.View()

	if len(result.Results) == 0 {
		v.Println("No deployments found")
		return nil
	}

	// For JSON output, return the raw results
	if v.Format == "json" {
		return v.JSON(result.Results)
	}

	// For table output, extract common fields
	headers := []string{"TIMESTAMP", "APP NAME", "REVISION", "DESCRIPTION", "USER"}
	rows := make([][]string, len(result.Results))
	for i, r := range result.Results {
		rows[i] = []string{
			formatNRQLValue(r["timestamp"]),
			view.Truncate(formatNRQLValue(r["entity.name"]), 30),
			view.Truncate(formatNRQLValue(r["revision"]), 20),
			view.Truncate(formatNRQLValue(r["description"]), 30),
			view.Truncate(formatNRQLValue(r["user"]), 15),
		}
	}

	return v.Render(headers, rows, result.Results)
}

func formatNRQLValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		// Check if it looks like a timestamp (large number)
		if val > 1000000000000 { // milliseconds since epoch
			t := time.Unix(0, int64(val)*int64(time.Millisecond))
			return t.Format(time.RFC3339)
		}
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
