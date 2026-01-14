package logs

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/confirm"
	"github.com/piekstra/newrelic-cli/internal/view"
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
	rulesCmd.AddCommand(newDeleteRuleCmd(opts))

	logsCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(logsCmd)
}

func newListRulesCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List log parsing rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListRules(opts)
		},
	}
}

func runListRules(opts *root.Options) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	rules, err := client.ListLogParsingRules()
	if err != nil {
		return err
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
