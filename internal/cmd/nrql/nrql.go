package nrql

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
)

type queryOptions struct {
	*root.Options
	since string
	until string
	link  bool
}

// Register adds the nrql commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	queryOpts := &queryOptions{Options: opts}

	nrqlCmd := &cobra.Command{
		Use:   "nrql [query]",
		Short: "Execute NRQL queries",
		Long: `Execute NRQL queries against your New Relic account.

You can run a query directly with 'nrql "<query>"' or use 'nrql query "<query>"'.

Time ranges can be specified either in the query itself (SINCE/UNTIL clauses)
or via --since and --until flags which will be appended to your query.

Supported time formats:
  - Relative: "7 days ago", "1 hour ago", "30 minutes ago"
  - Special: "now", "today", "yesterday"
  - Absolute: "2025-01-01", "2025-01-01T00:00:00Z"`,
		Example: `  # Direct query (shortcut)
  nrq nrql "SELECT count(*) FROM Transaction SINCE 1 hour ago"

  # Using query subcommand
  nrq nrql query "SELECT count(*) FROM Transaction"

  # Using --since flag (appends to query)
  nrq nrql "SELECT count(*) FROM Transaction" --since "7 days ago"

  # Using both --since and --until
  nrq nrql "SELECT * FROM Log" --since "2025-01-01" --until "2025-01-15"

  # Generate a deep link to open the query in New Relic
  nrq nrql --link "SELECT count(*) FROM Transaction SINCE 1 hour ago"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("query is required\n\nUsage:\n  nrq nrql \"<query>\"\n  nrq nrql query \"<query>\"\n\nDid you mean: nrq nrql query \"<your-query>\"?")
			}
			return runQuery(queryOpts, args[0])
		},
	}

	nrqlCmd.Flags().StringVar(&queryOpts.since, "since", "", "Time range start (e.g., '7 days ago', '2025-01-01')")
	nrqlCmd.Flags().StringVar(&queryOpts.until, "until", "", "Time range end (e.g., 'now', '2025-01-15')")
	nrqlCmd.Flags().BoolVar(&queryOpts.link, "link", false, "Output a New Relic deep link URL instead of executing the query")

	// Add query subcommand for compatibility
	nrqlCmd.AddCommand(newQueryCmd(queryOpts))

	rootCmd.AddCommand(nrqlCmd)
}

func newQueryCmd(opts *queryOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query <nrql>",
		Short: "Execute an NRQL query",
		Long: `Execute an NRQL query against your New Relic account.

Time ranges can be specified either in the query itself (SINCE/UNTIL clauses)
or via --since and --until flags which will be appended to your query.`,
		Example: `  nrq nrql query "SELECT count(*) FROM Transaction SINCE 1 hour ago"
  nrq nrql query "SELECT * FROM Log LIMIT 10"
  nrq nrql query "SELECT count(*) FROM Transaction" --since "7 days ago"
  nrq nrql query --link "SELECT count(*) FROM Transaction SINCE 1 hour ago"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuery(opts, args[0])
		},
	}

	cmd.Flags().StringVar(&opts.since, "since", "", "Time range start (e.g., '7 days ago', '2025-01-01')")
	cmd.Flags().StringVar(&opts.until, "until", "", "Time range end (e.g., 'now', '2025-01-15')")
	cmd.Flags().BoolVar(&opts.link, "link", false, "Output a New Relic deep link URL instead of executing the query")

	return cmd
}

func runQuery(opts *queryOptions, nrql string) error {
	// Build the final query with time range flags
	finalQuery := nrql

	// Append SINCE clause if provided and not already in query
	if opts.since != "" && !containsClause(nrql, "SINCE") {
		since, err := api.ParseFlexibleTime(opts.since)
		if err != nil {
			return fmt.Errorf("invalid --since value: %w", err)
		}
		// Use Unix timestamp for precision
		finalQuery += fmt.Sprintf(" SINCE %d", since.Unix())
	}

	// Append UNTIL clause if provided and not already in query
	if opts.until != "" && !containsClause(nrql, "UNTIL") {
		until, err := api.ParseFlexibleTime(opts.until)
		if err != nil {
			return fmt.Errorf("invalid --until value: %w", err)
		}
		finalQuery += fmt.Sprintf(" UNTIL %d", until.Unix())
	}

	// If --link flag is set, generate a deep link URL without needing an API key
	if opts.link {
		accountIDStr, err := config.GetAccountID()
		if err != nil {
			return fmt.Errorf("account ID required for --link: %w", err)
		}
		accountID, err := strconv.Atoi(accountIDStr)
		if err != nil {
			return fmt.Errorf("invalid account ID %q: %w", accountIDStr, err)
		}

		deepLink, err := BuildNRQLDeepLink(accountID, finalQuery)
		if err != nil {
			return err
		}
		v := opts.View()
		v.Println(deepLink)
		return nil
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	result, err := client.QueryNRQL(finalQuery)
	if err != nil {
		return err
	}

	v := opts.View()
	return v.JSON(result)
}

// BuildNRQLDeepLink generates a New Relic deep link URL that opens the query
// builder with the given NRQL query pre-populated and auto-executed.
func BuildNRQLDeepLink(accountID int, nrql string) (string, error) {
	pane := map[string]interface{}{
		"nerdletId":              "data-exploration.query-builder",
		"initialActiveInterface": "nrqlEditor",
		"initialAccountId":       accountID,
		"initialNrqlValue":       nrql,
		"isViewingQuery":         true,
	}

	paneJSON, err := json.Marshal(pane)
	if err != nil {
		return "", fmt.Errorf("encoding deep link pane: %w", err)
	}
	paneEncoded := base64.StdEncoding.EncodeToString(paneJSON)

	params := url.Values{}
	params.Set("platform[accountId]", strconv.Itoa(accountID))
	params.Set("pane", paneEncoded)

	return "https://one.newrelic.com/launcher/nr1-core.explorer?" + params.Encode(), nil
}

// BuildEntityDeepLink generates a New Relic deep link URL for an entity.
func BuildEntityDeepLink(entityGUID string) string {
	return "https://one.newrelic.com/redirect/entity/" + url.PathEscape(entityGUID)
}

// containsClause checks if the NRQL query already contains a specific clause
func containsClause(nrql, clause string) bool {
	upper := strings.ToUpper(nrql)
	return strings.Contains(upper, " "+clause+" ") || strings.HasSuffix(upper, " "+clause)
}
