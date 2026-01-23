package logs

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/confirm"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

// Register adds the logs commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	logsCmd := &cobra.Command{
		Use:     "logs",
		Aliases: []string{"log"},
		Short:   "Manage New Relic logs",
	}

	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage log parsing rules",
	}

	rulesCmd.AddCommand(newListRulesCmd(opts))
	rulesCmd.AddCommand(newCreateRuleCmd(opts))
	rulesCmd.AddCommand(newUpdateRuleCmd(opts))
	rulesCmd.AddCommand(newDeleteRuleCmd(opts))

	logsCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(logsCmd)
}

type listRulesOptions struct {
	*root.Options
	limit int
}

func newListRulesCmd(opts *root.Options) *cobra.Command {
	listOpts := &listRulesOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List log parsing rules",
		Long: `List all log parsing rules in your account.

Displays rule ID, description, enabled status, and last update time.
Use 'logs rules create' to add new rules or 'logs rules delete' to remove them.`,
		Example: `  newrelic-cli logs rules list
  newrelic-cli logs rules list -o json
  newrelic-cli logs rules list --limit 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListRules(listOpts)
		},
	}

	cmd.Flags().IntVarP(&listOpts.limit, "limit", "l", 0, "Limit number of results (0 = no limit)")

	return cmd
}

func runListRules(opts *listRulesOptions) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	rules, err := client.ListLogParsingRules()
	if err != nil {
		return err
	}

	// Apply limit
	if opts.limit > 0 && len(rules) > opts.limit {
		rules = rules[:opts.limit]
	}

	v := opts.View()

	if len(rules) == 0 {
		v.Println("No log parsing rules found")
		return nil
	}

	headers := []string{"ID", "DESCRIPTION", "ENABLED", "UPDATED"}
	rows := make([][]string, len(rules))
	for i, r := range rules {
		rows[i] = []string{
			r.ID,
			view.Truncate(r.Description, 40),
			fmt.Sprintf("%t", r.Enabled),
			r.UpdatedAt,
		}
	}

	return v.Render(headers, rows, rules)
}

type createRuleOptions struct {
	*root.Options
	description string
	grok        string
	nrql        string
	enabled     bool
	lucene      string
}

func newCreateRuleCmd(opts *root.Options) *cobra.Command {
	createOpts := &createRuleOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a log parsing rule",
		Long: `Create a log parsing rule using GROK patterns.

GROK patterns extract structured data from unstructured log messages.
Common GROK patterns:
  %{IP:client_ip}         - IPv4 or IPv6 address
  %{NUMBER:duration}      - Numeric value
  %{WORD:method}          - Single word
  %{DATA:message}         - Any characters (non-greedy)
  %{GREEDYDATA:rest}      - Any characters (greedy)
  %{UUID:request_id}      - UUID format
  %{TIMESTAMP_ISO8601:ts} - ISO8601 timestamp

The NRQL condition specifies which logs the rule applies to.

PATTERN MATCHING BEHAVIOR:
  Grok patterns must match from the start of the message. If your log has a
  variable prefix before the data you want to extract, use %{GREEDYDATA} or
  %{DATA} to consume it first.

  # This won't work if message has a prefix:
  --grok "%{UUID:id} - processed"

  # This will work:
  --grok "%{GREEDYDATA}%{UUID:id} - processed"

GREEDY VS NON-GREEDY:
  %{DATA}       - Non-greedy (matches as little as possible)
  %{GREEDYDATA} - Greedy (matches as much as possible)

  Use anchors like %{SPACE} or literal characters to avoid ambiguous matches:
  --grok "%{GREEDYDATA}%{SPACE}%{DATA:name}::%{UUID:id}"

CUSTOM CAPTURE GROUPS:
  Inline regex capture groups work when standard patterns don't fit:
  --grok "%{GREEDYDATA}(?<custom_id>[A-Z]{3}-[0-9]{4})"

HANDLING OPTIONAL PREFIXES:
  For logs from multiple sources with different prefix formats:
  --grok "(?:^|%{GREEDYDATA}\s)%{DATA:service}::%{UUID:id}"

MULTILINE MESSAGES:
  Logs with newlines (e.g., .NET console logging) need the prefix consumed:
  --grok "%{GREEDYDATA}%{SPACE}%{DATA:fi}::%{UUID:id} - %{GREEDYDATA:msg}"

TESTING PATTERNS:
  Test patterns with NRQL before creating rules:

  # Test with capture() for regex:
  FROM Log SELECT capture(message, r'.*(?P<id>[a-f0-9-]{36}).*')
  WHERE message LIKE '%your-filter%' LIMIT 5

  # Test with aparse() for grok:
  FROM Log SELECT aparse(message, '%{GREEDYDATA}%{UUID:id}')
  WHERE message LIKE '%your-filter%' LIMIT 5

IMPORTANT:
  - Parsing rules only apply to newly ingested logs
  - Existing logs will NOT be retroactively parsed
  - If parsed returns null in NRQL tests, your pattern doesn't match`,
		Example: `  # Parse user login events
  newrelic-cli logs rules create \
    --description "Parse user login events" \
    --grok "User %{UUID:user_id} logged in from %{IP:ip_address}" \
    --nrql "SELECT * FROM Log WHERE message LIKE 'User % logged in%'"

  # Parse HTTP access logs
  newrelic-cli logs rules create \
    --description "Parse HTTP access logs" \
    --grok "%{IP:client} - - %{DATA:timestamp} \"%{WORD:method} %{DATA:path}\" %{NUMBER:status}" \
    --nrql "SELECT * FROM Log WHERE logtype = 'accesslog'"

  # Parse error logs with Lucene filter
  newrelic-cli logs rules create \
    --description "Parse application errors" \
    --grok "ERROR %{TIMESTAMP_ISO8601:ts} %{DATA:class}: %{GREEDYDATA:message}" \
    --nrql "SELECT * FROM Log WHERE level = 'error'" \
    --lucene "message:ERROR"

  # Handle optional prefix (logs from multiple sources)
  newrelic-cli logs rules create \
    --description "Parse with optional prefix" \
    --grok "(?:^|%{GREEDYDATA}\s)%{DATA:service}::%{UUID:id} - %{GREEDYDATA:msg}" \
    --nrql "SELECT * FROM Log WHERE message LIKE '%::%'"

  # Custom regex capture for non-standard formats
  newrelic-cli logs rules create \
    --description "Parse custom ID format" \
    --grok "%{GREEDYDATA}(?<custom_id>[A-Z]{3}-[0-9]{4})" \
    --nrql "SELECT * FROM Log WHERE message LIKE '%-%'"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreateRule(createOpts)
		},
	}

	cmd.Flags().StringVarP(&createOpts.description, "description", "d", "", "Rule description (required)")
	cmd.Flags().StringVarP(&createOpts.grok, "grok", "g", "", "GROK pattern (required)")
	cmd.Flags().StringVarP(&createOpts.nrql, "nrql", "n", "", "NRQL matching condition (required)")
	cmd.Flags().BoolVarP(&createOpts.enabled, "enabled", "e", true, "Enable the rule")
	cmd.Flags().StringVarP(&createOpts.lucene, "lucene", "l", "", "Lucene filter")
	cmd.MarkFlagRequired("description")
	cmd.MarkFlagRequired("grok")
	cmd.MarkFlagRequired("nrql")

	return cmd
}

func runCreateRule(opts *createRuleOptions) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	rule, err := client.CreateLogParsingRule(opts.description, opts.grok, opts.nrql, opts.enabled, opts.lucene)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(rule)
	case "plain":
		return v.Plain([][]string{
			{rule.ID, rule.Description, fmt.Sprintf("%t", rule.Enabled)},
		})
	default:
		v.Success("Log parsing rule created successfully")
		v.Print("ID:          %s\n", rule.ID)
		v.Print("Description: %s\n", rule.Description)
		v.Print("Enabled:     %t\n", rule.Enabled)
		return nil
	}
}

type updateRuleOptions struct {
	*root.Options
	description string
	grok        string
	nrql        string
	lucene      string
	enabled     bool
	disabled    bool
}

func newUpdateRuleCmd(opts *root.Options) *cobra.Command {
	updateOpts := &updateRuleOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "update <rule-id>",
		Short: "Update a log parsing rule",
		Long: `Update an existing log parsing rule.

Only the specified fields will be modified - unspecified fields retain their current values.
Use --enabled to enable or --disabled to disable the rule.

PATTERN MATCHING BEHAVIOR:
  Grok patterns must match from the start of the message. If your log has a
  variable prefix before the data you want to extract, use %{GREEDYDATA} or
  %{DATA} to consume it first.

  # This won't work if message has a prefix:
  --grok "%{UUID:id} - processed"

  # This will work:
  --grok "%{GREEDYDATA}%{UUID:id} - processed"

GREEDY VS NON-GREEDY:
  %{DATA}       - Non-greedy (matches as little as possible)
  %{GREEDYDATA} - Greedy (matches as much as possible)

  Use anchors like %{SPACE} or literal characters to avoid ambiguous matches:
  --grok "%{GREEDYDATA}%{SPACE}%{DATA:name}::%{UUID:id}"

CUSTOM CAPTURE GROUPS:
  Inline regex capture groups work when standard patterns don't fit:
  --grok "%{GREEDYDATA}(?<custom_id>[A-Z]{3}-[0-9]{4})"

HANDLING OPTIONAL PREFIXES:
  For logs from multiple sources with different prefix formats:
  --grok "(?:^|%{GREEDYDATA}\s)%{DATA:service}::%{UUID:id}"

MULTILINE MESSAGES:
  Logs with newlines (e.g., .NET console logging) need the prefix consumed:
  --grok "%{GREEDYDATA}%{SPACE}%{DATA:fi}::%{UUID:id} - %{GREEDYDATA:msg}"

TESTING PATTERNS:
  Test patterns with NRQL before updating rules:

  # Test with capture() for regex:
  FROM Log SELECT capture(message, r'.*(?P<id>[a-f0-9-]{36}).*')
  WHERE message LIKE '%your-filter%' LIMIT 5

  # Test with aparse() for grok:
  FROM Log SELECT aparse(message, '%{GREEDYDATA}%{UUID:id}')
  WHERE message LIKE '%your-filter%' LIMIT 5

IMPORTANT:
  - Parsing rules only apply to newly ingested logs
  - Existing logs will NOT be retroactively parsed
  - If parsed returns null in NRQL tests, your pattern doesn't match`,
		Example: `  # Update the description
  newrelic-cli logs rules update rule-123 --description "Updated description"

  # Update the GROK pattern
  newrelic-cli logs rules update rule-123 --grok "%{IP:client} %{WORD:method}"

  # Disable a rule
  newrelic-cli logs rules update rule-123 --disabled

  # Update multiple fields
  newrelic-cli logs rules update rule-123 \
    --description "Parse HTTP logs" \
    --grok "%{COMBINEDAPACHELOG}" \
    --enabled

  # Update to handle optional prefix
  newrelic-cli logs rules update rule-123 \
    --grok "(?:^|%{GREEDYDATA}\s)%{DATA:service}::%{UUID:id} - %{GREEDYDATA:msg}"

  # Update with custom regex capture
  newrelic-cli logs rules update rule-123 \
    --grok "%{GREEDYDATA}(?<custom_id>[A-Z]{3}-[0-9]{4})"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdateRule(updateOpts, args[0], cmd)
		},
	}

	cmd.Flags().StringVarP(&updateOpts.description, "description", "d", "", "Rule description")
	cmd.Flags().StringVarP(&updateOpts.grok, "grok", "g", "", "GROK pattern")
	cmd.Flags().StringVarP(&updateOpts.nrql, "nrql", "n", "", "NRQL matching condition")
	cmd.Flags().StringVarP(&updateOpts.lucene, "lucene", "l", "", "Lucene filter")
	cmd.Flags().BoolVarP(&updateOpts.enabled, "enabled", "e", false, "Enable the rule")
	cmd.Flags().BoolVar(&updateOpts.disabled, "disabled", false, "Disable the rule")
	cmd.MarkFlagsMutuallyExclusive("enabled", "disabled")

	return cmd
}

func runUpdateRule(opts *updateRuleOptions, ruleID string, cmd *cobra.Command) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	// Build the update struct with only changed flags
	update := api.LogParsingRuleUpdate{}

	if cmd.Flags().Changed("description") {
		update.Description = &opts.description
	}
	if cmd.Flags().Changed("grok") {
		update.Grok = &opts.grok
	}
	if cmd.Flags().Changed("nrql") {
		update.NRQL = &opts.nrql
	}
	if cmd.Flags().Changed("lucene") {
		update.Lucene = &opts.lucene
	}
	if cmd.Flags().Changed("enabled") {
		enabled := true
		update.Enabled = &enabled
	}
	if cmd.Flags().Changed("disabled") {
		enabled := false
		update.Enabled = &enabled
	}

	rule, err := client.UpdateLogParsingRule(ruleID, update)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "json":
		return v.JSON(rule)
	case "plain":
		return v.Plain([][]string{
			{rule.ID, rule.Description, fmt.Sprintf("%t", rule.Enabled)},
		})
	default:
		v.Success("Log parsing rule updated successfully")
		v.Print("ID:          %s\n", rule.ID)
		v.Print("Description: %s\n", rule.Description)
		v.Print("Enabled:     %t\n", rule.Enabled)
		return nil
	}
}

// deleteRuleOptions holds options for the delete rule command
type deleteRuleOptions struct {
	*root.Options
	force bool
}

func newDeleteRuleCmd(opts *root.Options) *cobra.Command {
	deleteOpts := &deleteRuleOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "delete <rule-id>",
		Short: "Delete a log parsing rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeleteRule(deleteOpts, args[0])
		},
	}

	cmd.Flags().BoolVarP(&deleteOpts.force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func runDeleteRule(opts *deleteRuleOptions, ruleID string) error {
	v := opts.View()

	if !opts.force {
		p := &confirm.Prompter{
			In:  opts.Stdin,
			Out: opts.Stderr,
		}
		if !p.Confirm(fmt.Sprintf("Delete log parsing rule %s?", ruleID)) {
			v.Warning("Operation canceled")
			return nil
		}
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	if err := client.DeleteLogParsingRule(ruleID); err != nil {
		return err
	}

	v.Success("Log parsing rule %s deleted", ruleID)
	return nil
}
