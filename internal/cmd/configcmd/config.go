// Package configcmd implements `nrq config …` plus the top-level
// `nrq set-credential` ingress command, reworked for the cli-common
// credstore single-key bundle per the Open CLI Collective Secret-Handling
// Standard §2.5. The API key lives only in the OS keyring; account_id and
// region are non-secret config.yml fields.
package configcmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
	"github.com/open-cli-collective/newrelic-cli/internal/validate"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

// Register adds `config` (with subcommands) and the top-level
// `set-credential` ingress command to the root command.
func Register(rootCmd *cobra.Command, opts *root.Options) {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configure nrq (non-secret config.yml + credential diagnostics)",
	}
	configCmd.AddCommand(newSetCmd(opts))
	configCmd.AddCommand(newSetAccountIDAliasCmd(opts))
	configCmd.AddCommand(newSetRegionAliasCmd(opts))
	configCmd.AddCommand(newSetAPIKeyDeprecatedCmd(opts))
	configCmd.AddCommand(newShowCmd(opts))
	configCmd.AddCommand(newTestCmd(opts))
	configCmd.AddCommand(newClearCmd(opts))

	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(newSetCredentialCmd(opts))
}

// ---- nrq set-credential (§1.5.2 ingress) -----------------------------------

type setCredentialOptions struct {
	*root.Options
	ref       string
	key       string
	stdin     bool
	fromEnv   string
	overwrite bool
}

func newSetCredentialCmd(opts *root.Options) *cobra.Command {
	o := &setCredentialOptions{Options: opts}
	cmd := &cobra.Command{
		Use:   "set-credential --key api_key (--stdin | --from-env VAR)",
		Short: "Store a secret in the OS keyring (low-level scripted ingress)",
		Long: `set-credential is the low-level, single-secret, scriptable ingress
path (§1.5.2). It writes one key to the OS keyring. The value is read from
stdin or a named environment variable — NEVER from a flag or positional
argument (those leak via ps / shell history).

Examples:
  op read "op://Vault/New Relic/api key" | nrq set-credential --key api_key --stdin
  nrq set-credential --key api_key --from-env NEWRELIC_API_KEY
  nrq set-credential --ref newrelic-cli/default --key api_key --stdin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSetCredential(o)
		},
	}
	cmd.Flags().StringVar(&o.ref, "ref", "", "Credential ref (default: config.yml credential_ref)")
	cmd.Flags().StringVar(&o.key, "key", "", "Bundle key to set (only \"api_key\" is allowed)")
	cmd.Flags().BoolVar(&o.stdin, "stdin", false, "Read the secret value from stdin")
	cmd.Flags().StringVar(&o.fromEnv, "from-env", "", "Read the secret value from this environment variable")
	cmd.Flags().BoolVar(&o.overwrite, "overwrite", false, "Replace an existing keyring value (refuses by default)")
	return cmd
}

func runSetCredential(o *setCredentialOptions) error {
	v := o.View()

	if o.key != keychain.KeyAPIKey {
		return fmt.Errorf("unsupported --key %q: nrq's only bundle key is %q (§1.5.2)",
			o.key, keychain.KeyAPIKey)
	}
	if o.stdin == (o.fromEnv != "") {
		return errors.New("provide exactly one of --stdin or --from-env (the value is never a flag/positional — §1.5)")
	}
	// --ref is optional: when omitted, OpenRef("") inherits config.yml's
	// credential_ref, or DefaultCredentialRef when there is no config.yml
	// (the §1.10 fresh-install automation primitive — `op read | nrq
	// set-credential --key api_key --stdin` must work with no prior
	// config). When provided, validate it up front so an invalid value
	// fails with a message naming the --ref flag, not deep inside OpenRef.
	if o.ref != "" {
		if _, _, err := credstore.ParseRef(o.ref); err != nil {
			return fmt.Errorf("invalid --ref %q: %w (expected <service>/<profile>, e.g. %s)",
				o.ref, err, config.DefaultCredentialRef)
		}
	}

	var secret string
	if o.stdin {
		b, err := io.ReadAll(o.Stdin)
		if err != nil {
			return fmt.Errorf("read secret from stdin: %w", err)
		}
		secret = strings.TrimRight(string(b), "\r\n")
	} else {
		secret = os.Getenv(o.fromEnv)
		if secret == "" {
			return fmt.Errorf("environment variable %s is empty or unset", o.fromEnv)
		}
	}
	if warning, err := validate.APIKey(secret); err != nil {
		return err
	} else if warning != "" {
		v.Warning("%s", warning)
	}

	st, err := keychain.OpenRef(o.ref) // pure ingress: no migration
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	// No-clobber by default (§1.5/§1.11): an existing keyring value is never
	// silently replaced — the user must pass --overwrite.
	if st.HasAPIKey() && !o.overwrite {
		return fmt.Errorf("%s already set at %s; pass --overwrite to replace it", o.key, st.Ref())
	}
	if o.overwrite {
		err = st.SetAPIKeyOverwrite(secret)
	} else {
		err = st.SetAPIKey(secret)
	}
	if err != nil {
		if errors.Is(err, credstore.ErrExists) {
			return fmt.Errorf("%s already set at %s; pass --overwrite to replace it", o.key, st.Ref())
		}
		return err
	}
	v.Success("Stored %s in the OS keyring at %s", o.key, st.Ref())
	return nil
}

// ---- config set / aliases (non-secret config.yml) --------------------------

type setOptions struct {
	*root.Options
	accountID string
	region    string
}

func newSetCmd(opts *root.Options) *cobra.Command {
	o := &setOptions{Options: opts}
	cmd := &cobra.Command{
		Use:   "set [--account-id ID] [--region US|EU]",
		Short: "Set non-secret config (account ID, region) in config.yml",
		Long: `Write non-secret configuration to config.yml. These are not
credentials, so flag/positional values are fine (only secret-bearing
ingress is restricted — §1.5). For the API key use 'nrq init' or
'nrq set-credential'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSet(o.Options, o.accountID, o.region)
		},
	}
	cmd.Flags().StringVar(&o.accountID, "account-id", "", "New Relic account ID")
	cmd.Flags().StringVar(&o.region, "region", "", "New Relic region (US or EU)")
	return cmd
}

func runSet(opts *root.Options, accountID, region string) error {
	v := opts.View()
	if accountID == "" && region == "" {
		return errors.New("nothing to set: pass --account-id and/or --region")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if accountID != "" {
		if err := validate.AccountID(accountID); err != nil {
			return err
		}
		cfg.AccountID = accountID
	}
	if region != "" {
		region = strings.ToUpper(region)
		if err := validate.Region(region); err != nil {
			return err
		}
		cfg.Region = region
	}
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if accountID != "" {
		v.Success("account_id set to %s in %s", accountID, config.Path())
	}
	if region != "" {
		v.Success("region set to %s in %s", strings.ToUpper(region), config.Path())
	}
	return nil
}

// set-account-id / set-region: thin deprecating aliases of `config set`,
// retained for one deprecation cycle (§2.5). Non-secret, so positional args
// are fine.
func newSetAccountIDAliasCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:        "set-account-id <account-id>",
		Short:      "Deprecated: use `nrq config set --account-id`",
		Deprecated: "use `nrq config set --account-id <id>`",
		Args:       cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSet(opts, args[0], "")
		},
	}
}

func newSetRegionAliasCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:        "set-region <region>",
		Short:      "Deprecated: use `nrq config set --region`",
		Deprecated: "use `nrq config set --region <US|EU>`",
		Args:       cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSet(opts, "", args[0])
		},
	}
}

// ---- config set-api-key: hard-deprecated (§1.5 / §2.5) ---------------------

// newSetAPIKeyDeprecatedCmd accepts no value by ANY path — positional, flag,
// or the old no-arg interactive prompt. Every invocation exits nonzero with
// the migration message. Positional secret ingress is banned alongside
// flag-passed (§1.5).
func newSetAPIKeyDeprecatedCmd(opts *root.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:                "set-api-key",
		Short:              "Removed: the API key now lives in the OS keyring",
		DisableFlagParsing: true, // a stray --api-key=... must not look valid
		RunE: func(cmd *cobra.Command, _ []string) error {
			return setAPIKeyRemovedErr()
		},
	}
	return cmd
}

func setAPIKeyRemovedErr() error {
	return errors.New(
		"`nrq config set-api-key` is removed: the API key is no longer stored on disk " +
			"or accepted as a positional/flag/prompted value (§1.5). Ingest it via the keyring instead:\n" +
			"  nrq set-credential --ref " + config.DefaultCredentialRef + " --key api_key --stdin\n" +
			"  op read \"op://Vault/New Relic/api key\" | nrq set-credential --key api_key --stdin\n" +
			"  nrq init")
}

// ---- config show (§2.5 diagnostic; never the secret value) -----------------

type showStatus struct {
	CredentialRef    string `json:"credential_ref"`
	Backend          string `json:"backend"`
	BackendSource    string `json:"backend_source"`
	PassphraseSource string `json:"passphrase_source,omitempty"`
	APIKeyPresent    bool   `json:"api_key_present"`
	AccountID        string `json:"account_id,omitempty"`
	AccountIDSource  string `json:"account_id_source"`
	Region           string `json:"region"`
	RegionSource     string `json:"region_source"`
}

func newShowCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show credential/config status (no secret values)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runShow(opts)
		},
	}
}

func runShow(opts *root.Options) error {
	v := opts.View()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// OpenNoMigrate: show is the diagnostic and must stay usable during an
	// unresolved §1.8 conflict (running migration first would fail it and
	// hide the very state the user needs to see to remediate).
	st, err := keychain.OpenNoMigrate()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	backend, bsrc := st.Backend()
	accountID, aSrc := cfg.ResolveAccountID()
	region, rSrc := cfg.ResolveRegion()
	status := showStatus{
		CredentialRef:   st.Ref(),
		Backend:         string(backend),
		BackendSource:   string(bsrc),
		APIKeyPresent:   st.HasAPIKey(),
		AccountID:       accountID,
		AccountIDSource: string(aSrc),
		Region:          region,
		RegionSource:    string(rSrc),
	}
	if backend == credstore.BackendFile {
		status.PassphraseSource = keychain.PassphraseSource(st.Service())
	}

	if v.Format == view.FormatJSON {
		return v.JSON(status)
	}

	v.Println("Configuration status:")
	v.Println("")
	v.Print("  Credential ref: %s\n", status.CredentialRef)
	v.Print("  Backend:        %s (%s)\n", status.Backend, status.BackendSource)
	if status.PassphraseSource != "" {
		v.Print("  Passphrase:     %s\n", status.PassphraseSource)
	}
	if status.APIKeyPresent {
		v.Println("  API key:        present (in keyring)")
	} else {
		v.Println("  API key:        not set — run `nrq init` or `nrq set-credential`")
	}
	if status.AccountID != "" {
		v.Print("  Account ID:     %s (%s)\n", status.AccountID, status.AccountIDSource)
	} else {
		v.Println("  Account ID:     not set")
	}
	v.Print("  Region:         %s (%s)\n", status.Region, status.RegionSource)
	return nil
}

// ---- config test (connection smoke; routes through the lazy resolver) ------

type connectionTestStatus struct {
	Success       bool   `json:"success"`
	APIKeyValid   bool   `json:"api_key_valid"`
	AccountAccess bool   `json:"account_access,omitempty"`
	AccountID     int    `json:"account_id,omitempty"`
	AccountName   string `json:"account_name,omitempty"`
	UserEmail     string `json:"user_email,omitempty"`
	Region        string `json:"region"`
	Error         string `json:"error,omitempty"`
}

func newTestCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Test connection to New Relic",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTest(opts)
		},
	}
}

func runTest(opts *root.Options) error {
	v := opts.View()
	client, err := opts.APIClient() // lazy resolver: opens keyring, runs §1.8
	if err != nil {
		v.Error("Failed to create client: %v", err)
		return err
	}
	result, err := client.TestConnection()
	if err != nil {
		v.Error("Test failed: %v", err)
		return err
	}
	status := connectionTestStatus{
		Success:       result.APIKeyValid && (result.AccountAccess || client.AccountID.IsEmpty()),
		APIKeyValid:   result.APIKeyValid,
		AccountAccess: result.AccountAccess,
		AccountID:     result.AccountID,
		AccountName:   result.AccountName,
		UserEmail:     result.UserEmail,
		Region:        result.Region,
	}
	if result.Error != nil {
		status.Error = result.ErrorMessage
	}
	if v.Format == view.FormatJSON {
		return v.JSON(status)
	}
	if result.APIKeyValid {
		v.Success("API key valid")
		if result.UserEmail != "" {
			v.Print("  User: %s\n", result.UserEmail)
		}
	} else {
		v.Error("API key invalid or expired")
		if result.ErrorMessage != "" {
			v.Println("Error: " + result.ErrorMessage)
		}
		v.Println("Reconfigure with: nrq init")
		return errors.New("API key validation failed")
	}
	if !client.AccountID.IsEmpty() {
		if result.AccountAccess {
			v.Success("Account %d accessible", result.AccountID)
		} else {
			v.Error("Account not accessible")
			return errors.New("account access failed")
		}
	}
	v.Success("Connection test passed!")
	return nil
}

// ---- config clear (§1.7: idempotent, non-interactive) ----------------------

type clearOptions struct {
	*root.Options
	all    bool
	dryRun bool
}

func newClearCmd(opts *root.Options) *cobra.Command {
	o := &clearOptions{Options: opts}
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Remove the stored API key (and with --all, config.yml too)",
		Long: `Remove credentials. Idempotent and non-interactive (exit 0 even
if nothing was stored) — safe for automation.

  clear         removes the active ref's keyring keys (the api_key).
  clear --all   also removes config.yml (account_id, region, credential_ref).
  clear --dry-run  reports what would be removed, changes nothing.

nrq has no cache directories, so --all scope is exactly {keyring bundle,
config.yml}.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClear(o)
		},
	}
	cmd.Flags().BoolVar(&o.all, "all", false, "Also remove config.yml")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "Report what would be removed; change nothing")
	return cmd
}

func runClear(o *clearOptions) error {
	v := o.View()
	// OpenNoMigrate: clear is the advertised §1.8 conflict remediation; if
	// migration ran first it would fail with the conflict error before clear
	// could delete the keyring entry, leaving the user no way out.
	st, err := keychain.OpenNoMigrate()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	if o.dryRun {
		if st.HasAPIKey() {
			v.Println("would remove: api_key from keyring " + st.Ref())
		} else {
			v.Println("would remove: (no api_key in keyring)")
		}
		if o.all {
			if _, statErr := os.Stat(config.Path()); statErr == nil {
				v.Println("would remove: " + config.Path())
			} else {
				v.Println("would remove: (no config.yml)")
			}
			if _, statErr := os.Stat(config.LegacyCredentialsPath()); statErr == nil {
				v.Println("would remove: " + config.LegacyCredentialsPath() + " (legacy plaintext)")
			}
		}
		return nil
	}

	removed, err := st.Clear()
	if err != nil {
		return fmt.Errorf("clear keyring bundle: %w", err)
	}
	if len(removed) > 0 {
		v.Success("Removed %d key(s) from keyring %s", len(removed), st.Ref())
	} else {
		v.Println("No keyring keys to remove (already clear)")
	}

	if o.all {
		if err := os.Remove(config.Path()); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("remove %s: %w", config.Path(), err)
			}
			v.Println("No config.yml to remove (already clear)")
		} else {
			v.Success("Removed %s", config.Path())
		}
		// Also scrub the legacy plaintext credentials file. Without this a
		// `clear --all` on a workstation that never ran the §1.8 migration
		// leaves the legacy secret on disk, and the next Open() re-migrates
		// it back into the keyring — silently undoing the wipe.
		if lp := config.LegacyCredentialsPath(); lp != "" {
			if err := os.Remove(lp); err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf("remove %s: %w", lp, err)
				}
			} else {
				v.Success("Removed %s (legacy plaintext)", lp)
			}
		}
	}
	return nil
}
