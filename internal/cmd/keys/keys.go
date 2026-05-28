package keys

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/confirm"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

// Register adds the keys commands to the root command
func Register(rootCmd *cobra.Command, opts *root.Options) {
	keysCmd := &cobra.Command{
		Use:     "keys",
		Aliases: []string{"key"},
		Short:   "Manage API keys",
		Long: `Manage New Relic API keys (user and ingest keys).

Wraps the NerdGraph apiAccess API to list, inspect, create, update,
and delete API keys without hand-crafting GraphQL.`,
	}

	keysCmd.AddCommand(newListCmd(opts))
	keysCmd.AddCommand(newGetCmd(opts))
	keysCmd.AddCommand(newCreateCmd(opts))
	keysCmd.AddCommand(newUpdateCmd(opts))
	keysCmd.AddCommand(newDeleteCmd(opts))

	rootCmd.AddCommand(keysCmd)
}

// --- list ---

type listOptions struct {
	*root.Options
	keyType string
	account int
	limit   int
}

func newListCmd(opts *root.Options) *cobra.Command {
	listOpts := &listOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API keys",
		Long: `List API keys for your account.

By default lists both user and ingest keys. Use --type to filter.`,
		Example: `  nrq keys list
  nrq keys list --type user
  nrq keys list --type ingest --account 12345`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(listOpts)
		},
	}

	cmd.Flags().StringVarP(&listOpts.keyType, "type", "t", "", "Filter by key type: user or ingest")
	cmd.Flags().IntVar(&listOpts.account, "account", 0, "Filter by account ID")
	cmd.Flags().IntVarP(&listOpts.limit, "limit", "l", 0, "Limit number of results (0 = no limit)")

	return cmd
}

func runList(opts *listOptions) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	var keyTypes []string
	if opts.keyType != "" {
		t := strings.ToUpper(opts.keyType)
		if t != "USER" && t != "INGEST" {
			return fmt.Errorf("invalid key type %q: must be user or ingest", opts.keyType)
		}
		keyTypes = []string{t}
	}

	keys, err := client.SearchAPIKeys(keyTypes, opts.account)
	if err != nil {
		return err
	}

	if opts.limit > 0 && len(keys) > opts.limit {
		keys = keys[:opts.limit]
	}

	v := opts.View()

	if len(keys) == 0 {
		v.Println("No API keys found")
		return nil
	}

	headers := []string{"ID", "NAME", "TYPE", "INGEST TYPE", "NOTES"}
	rows := make([][]string, len(keys))
	for i, k := range keys {
		rows[i] = []string{
			k.ID,
			view.Truncate(k.Name, 30),
			k.Type,
			k.IngestType,
			view.Truncate(k.Notes, 30),
		}
	}

	return v.Render(headers, rows)
}

// --- get ---

type getOptions struct {
	*root.Options
	keyType string
}

func newGetCmd(opts *root.Options) *cobra.Command {
	getOpts := &getOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "get <key-id>",
		Short: "Get details for an API key",
		Long: `Get details for a specific API key.

If --type is not specified, tries USER then INGEST to find the key.`,
		Example: `  nrq keys get NRAK-XXXXXXXXXXXX
  nrq keys get NRAK-XXXXXXXXXXXX --type user`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(getOpts, args[0])
		},
	}

	cmd.Flags().StringVarP(&getOpts.keyType, "type", "t", "", "Key type: user or ingest (auto-detected if omitted)")

	return cmd
}

func runGet(opts *getOptions, keyID string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	var key *api.ApiAccessKey

	if opts.keyType != "" {
		t := strings.ToUpper(opts.keyType)
		if t != "USER" && t != "INGEST" {
			return fmt.Errorf("invalid key type %q: must be user or ingest", opts.keyType)
		}
		key, err = client.GetAPIAccessKey(keyID, t)
	} else {
		key, err = client.FindAPIAccessKey(keyID)
	}
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "plain":
		return v.Plain([][]string{
			{key.ID, key.Name, key.Type, key.IngestType, key.Notes},
		})
	default:
		v.Print("ID:          %s\n", key.ID)
		v.Print("Name:        %s\n", key.Name)
		v.Print("Type:        %s\n", key.Type)
		if key.IngestType != "" {
			v.Print("Ingest Type: %s\n", key.IngestType)
		}
		if key.Key != "" {
			v.Print("Key:         %s\n", key.Key)
		}
		if key.Notes != "" {
			v.Print("Notes:       %s\n", key.Notes)
		}
		return nil
	}
}

// --- create ---

type createOptions struct {
	*root.Options
	keyType    string
	name       string
	notes      string
	account    int
	userID     int
	ingestType string
}

func newCreateCmd(opts *root.Options) *cobra.Command {
	createOpts := &createOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an API key",
		Long: `Create a new API key.

For user keys, the current user is used by default. Use --user-id to
create a key for a different user.

For ingest keys, --ingest-type is required (license or browser).`,
		Example: `  # Create a user key
  nrq keys create --type user --name "my-key" --notes "For automation"

  # Create a user key for a specific account
  nrq keys create --type user --name "my-key" --account 12345

  # Create an ingest (license) key
  nrq keys create --type ingest --ingest-type license --name "my-license-key"

  # Create a browser ingest key
  nrq keys create --type ingest --ingest-type browser --name "my-browser-key"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(createOpts)
		},
	}

	cmd.Flags().StringVarP(&createOpts.keyType, "type", "t", "", "Key type: user or ingest (required)")
	cmd.Flags().StringVarP(&createOpts.name, "name", "n", "", "Key name (required)")
	cmd.Flags().StringVar(&createOpts.notes, "notes", "", "Key notes/description")
	cmd.Flags().IntVar(&createOpts.account, "account", 0, "Account ID (defaults to configured account)")
	cmd.Flags().IntVar(&createOpts.userID, "user-id", 0, "User ID for user keys (defaults to current user)")
	cmd.Flags().StringVar(&createOpts.ingestType, "ingest-type", "", "Ingest type for ingest keys: license or browser")
	cmd.MarkFlagRequired("type")
	cmd.MarkFlagRequired("name")

	return cmd
}

func runCreate(opts *createOptions) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	keyType := strings.ToUpper(opts.keyType)
	if keyType != "USER" && keyType != "INGEST" {
		return fmt.Errorf("invalid key type %q: must be user or ingest", opts.keyType)
	}

	// Resolve account ID
	accountID := opts.account
	if accountID == 0 {
		accountID, err = client.GetAccountIDInt()
		if err != nil {
			return fmt.Errorf("no account ID specified and none configured: %w", err)
		}
	}

	var key *api.ApiAccessKey

	switch keyType {
	case "USER":
		userID := opts.userID
		if userID == 0 {
			userID, err = client.GetCurrentUserID()
			if err != nil {
				return fmt.Errorf("could not determine current user ID: %w", err)
			}
		}
		key, err = client.CreateUserAPIKey(accountID, userID, opts.name, opts.notes)
	case "INGEST":
		ingestType := strings.ToUpper(opts.ingestType)
		if ingestType != "LICENSE" && ingestType != "BROWSER" {
			return fmt.Errorf("--ingest-type is required for ingest keys: license or browser")
		}
		key, err = client.CreateIngestAPIKey(accountID, ingestType, opts.name, opts.notes)
	}
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "plain":
		return v.Plain([][]string{
			{key.ID, key.Name, key.Type, key.Key},
		})
	default:
		v.Success("API key created successfully")
		v.Print("ID:   %s\n", key.ID)
		v.Print("Name: %s\n", key.Name)
		v.Print("Type: %s\n", key.Type)
		if key.IngestType != "" {
			v.Print("Ingest Type: %s\n", key.IngestType)
		}
		if key.Key != "" {
			v.Print("Key:  %s\n", key.Key)
		}
		return nil
	}
}

// --- update ---

type updateOptions struct {
	*root.Options
	keyType string
	name    string
	notes   string
}

func newUpdateCmd(opts *root.Options) *cobra.Command {
	updateOpts := &updateOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "update <key-id>",
		Short: "Update an API key",
		Long: `Update an existing API key's name and/or notes.

If --type is not specified, the key type is auto-detected.
Only the specified fields will be modified.`,
		Example: `  nrq keys update NRAK-XXXXXXXXXXXX --name "new-name"
  nrq keys update NRAK-XXXXXXXXXXXX --name "new-name" --notes "updated notes"
  nrq keys update NRAK-XXXXXXXXXXXX --notes "new notes" --type user`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(updateOpts, args[0], cmd)
		},
	}

	cmd.Flags().StringVarP(&updateOpts.keyType, "type", "t", "", "Key type: user or ingest (auto-detected if omitted)")
	cmd.Flags().StringVarP(&updateOpts.name, "name", "n", "", "New key name")
	cmd.Flags().StringVar(&updateOpts.notes, "notes", "", "New key notes")

	return cmd
}

func runUpdate(opts *updateOptions, keyID string, cmd *cobra.Command) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	// Determine key type
	keyType := strings.ToUpper(opts.keyType)
	if keyType == "" {
		// Auto-detect by looking up the key
		existing, findErr := client.FindAPIAccessKey(keyID)
		if findErr != nil {
			return fmt.Errorf("could not determine key type (use --type to specify): %w", findErr)
		}
		keyType = existing.Type
	} else if keyType != "USER" && keyType != "INGEST" {
		return fmt.Errorf("invalid key type %q: must be user or ingest", opts.keyType)
	}

	// Build update
	update := api.ApiAccessKeyUpdate{}
	if cmd.Flags().Changed("name") {
		update.Name = &opts.name
	}
	if cmd.Flags().Changed("notes") {
		update.Notes = &opts.notes
	}

	key, err := client.UpdateAPIAccessKey(keyID, keyType, update)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "plain":
		return v.Plain([][]string{
			{key.ID, key.Name, key.Type},
		})
	default:
		v.Success("API key updated successfully")
		v.Print("ID:    %s\n", key.ID)
		v.Print("Name:  %s\n", key.Name)
		if key.Notes != "" {
			v.Print("Notes: %s\n", key.Notes)
		}
		return nil
	}
}

// --- delete ---

type deleteOptions struct {
	*root.Options
	keyType string
	force   bool
}

func newDeleteCmd(opts *root.Options) *cobra.Command {
	deleteOpts := &deleteOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "delete <key-id> [key-id...]",
		Short: "Delete one or more API keys",
		Long: `Delete one or more API keys.

If --type is specified, all keys are treated as that type.
Otherwise, each key is looked up to determine its type.`,
		Example: `  nrq keys delete NRAK-XXXXXXXXXXXX
  nrq keys delete NRAK-XXXXXXXXXXXX NRAK-YYYYYYYYYYYY
  nrq keys delete NRAK-XXXXXXXXXXXX --type user --force`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDelete(deleteOpts, args)
		},
	}

	cmd.Flags().StringVarP(&deleteOpts.keyType, "type", "t", "", "Key type: user or ingest (auto-detected if omitted)")
	cmd.Flags().BoolVarP(&deleteOpts.force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func runDelete(opts *deleteOptions, keyIDs []string) error {
	v := opts.View()

	if !opts.force {
		msg := fmt.Sprintf("Delete %d API key(s)?", len(keyIDs))
		if len(keyIDs) == 1 {
			msg = fmt.Sprintf("Delete API key %s?", keyIDs[0])
		}
		p := &confirm.Prompter{
			In:  opts.Stdin,
			Out: opts.Stderr,
		}
		if !p.Confirm(msg) {
			v.Warning("Operation canceled")
			return nil
		}
	}

	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	var userKeyIDs, ingestKeyIDs []string

	if opts.keyType != "" {
		t := strings.ToUpper(opts.keyType)
		if t != "USER" && t != "INGEST" {
			return fmt.Errorf("invalid key type %q: must be user or ingest", opts.keyType)
		}
		switch t {
		case "USER":
			userKeyIDs = keyIDs
		case "INGEST":
			ingestKeyIDs = keyIDs
		}
	} else {
		// Look up each key to determine its type
		for _, id := range keyIDs {
			key, findErr := client.FindAPIAccessKey(id)
			if findErr != nil {
				return fmt.Errorf("could not determine type for key %s (use --type to specify): %w", id, findErr)
			}
			switch key.Type {
			case "USER":
				userKeyIDs = append(userKeyIDs, id)
			case "INGEST":
				ingestKeyIDs = append(ingestKeyIDs, id)
			default:
				return fmt.Errorf("unexpected key type %q for key %s", key.Type, id)
			}
		}
	}

	deletedIDs, err := client.DeleteAPIAccessKeys(userKeyIDs, ingestKeyIDs)
	if err != nil {
		return err
	}

	if len(deletedIDs) == 1 {
		v.Success("API key %s deleted", deletedIDs[0])
	} else {
		v.Success("%d API keys deleted", len(deletedIDs))
	}
	return nil
}
