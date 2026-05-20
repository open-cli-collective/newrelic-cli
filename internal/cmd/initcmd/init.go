// Package initcmd implements `nrq init`, the interactive/scripted first-time
// setup. Per the Open CLI Collective Secret-Handling Standard §1.5.1 the API
// key is ingested ONLY via a named env var, single-secret stdin, or an
// interactive no-echo prompt — never `--api-key=<literal>` and never a
// plaintext echo. account_id/region are non-secret config.yml fields.
package initcmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
	"github.com/open-cli-collective/newrelic-cli/internal/validate"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

type initOptions struct {
	*root.Options
	apiKeyEnv      string // --api-key-from-env NAME
	apiKeyStdin    bool   // --api-key-stdin
	accountID      string // --account-id (non-secret literal)
	accountIDEnv   string // --account-id-from-env NAME (non-secret env-bridge)
	region         string // non-secret
	overwrite      bool   // resolve a §1.8 legacy/keyring conflict
	nonInteractive bool   // fail loud instead of prompting (installer; §1.3)
	noVerify       bool
}

func (o *initOptions) secretFromFlags() bool { return o.apiKeyStdin || o.apiKeyEnv != "" }

// Register adds the init command to the root command.
func Register(rootCmd *cobra.Command, opts *root.Options) {
	o := &initOptions{Options: opts}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "First-time setup (stores the API key in the OS keyring)",
		Long: `Configure nrq. The API key is stored in the OS keyring (never in
plaintext, never in config.yml) and is ingested ONLY via stdin, a named env
var, or an interactive no-echo prompt — never as a flag/positional literal
(§1.5.1). account_id and region are non-secret and written to config.yml.`,
		Example: `  # Interactive (no-echo API key prompt)
  nrq init

  # Scripted ingress
  op read "op://Vault/New Relic/api key" | nrq init --api-key-stdin --account-id 12345 --region US
  nrq init --api-key-from-env NEWRELIC_API_KEY --account-id 12345

  # Fully non-interactive (central installer: op -> env -> --*-from-env)
  nrq init --region US --api-key-from-env NEWRELIC_API_KEY \
    --account-id-from-env NEWRELIC_ACCOUNT_ID --non-interactive

  # Resolve a one-time migration conflict by forcing the legacy value
  # (no ingress flag — stdin/env would replace the forced legacy value)
  nrq init --overwrite`,
		Args: root.NoPositionalArgs, // never echo a fat-fingered API key (§1.12)
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(o)
		},
	}
	cmd.Flags().StringVar(&o.apiKeyEnv, "api-key-from-env", "", "Read the API key from this environment variable")
	cmd.Flags().BoolVar(&o.apiKeyStdin, "api-key-stdin", false, "Read the API key from stdin")
	cmd.Flags().StringVar(&o.accountID, "account-id", "", "New Relic account ID (non-secret)")
	cmd.Flags().StringVar(&o.accountIDEnv, "account-id-from-env", "", "Read the (non-secret) account ID from this environment variable")
	cmd.Flags().StringVar(&o.region, "region", "", "New Relic region: US or EU (non-secret)")
	cmd.Flags().BoolVar(&o.overwrite, "overwrite", false, "Resolve a legacy/keyring migration conflict by forcing the legacy value")
	cmd.Flags().BoolVar(&o.nonInteractive, "non-interactive", false, "Never prompt; fail loudly if a required value is missing (for scripted/installer use)")
	cmd.Flags().BoolVar(&o.noVerify, "no-verify", false, "Skip connection verification")
	rootCmd.AddCommand(cmd)
}

func runInit(opts *initOptions) error {
	v := opts.View()

	if opts.apiKeyStdin && opts.apiKeyEnv != "" {
		return errors.New("provide at most one of --api-key-stdin / --api-key-from-env")
	}
	if opts.accountID != "" && opts.accountIDEnv != "" {
		return errors.New("provide at most one of --account-id / --account-id-from-env")
	}

	// MON-5373 relocation gate: runs BEFORE keychain.OpenForInit so a
	// divergent old↔new config aborts BEFORE the §1.8 migration could scrub
	// the legacy plaintext file or write the canonical config. On an
	// old-only-readable surface we copy old→new (leave-old) so subsequent
	// loads see the canonical location.
	if reloc, err := config.DetectConfigRelocation(); err != nil {
		return fmt.Errorf("detecting config relocation: %w", err)
	} else if reloc.CopyNeeded {
		if err := config.ApplyConfigRelocation(reloc); err != nil {
			return fmt.Errorf("relocating config from %s to %s: %w", reloc.OldPath, reloc.NewPath, err)
		}
	}

	// wantPrompt gates every interactive fallback. --non-interactive forces
	// fail-loud (cli-deployment-manifest §1.3) so the central installer's
	// `nrq init` is deterministic regardless of TTY.
	wantPrompt := !opts.nonInteractive && isTerminal(opts.Stdin)

	// Open the keyring. This runs the one-time §1.8 migration (legacy
	// keychain / credentials file → keyring + config.yml). --overwrite forces
	// a legacy value over an existing keyring entry to resolve a conflict.
	// The non-interactive policy is plumbed in so the file backend never
	// prompts for a passphrase on a TTY under --non-interactive.
	st, err := keychain.OpenForInit(opts.overwrite, opts.nonInteractive)
	if err != nil {
		return err // includes the actionable §1.8 conflict / passphrase error
	}
	stClosed := false
	closeStore := func() {
		if !stClosed {
			stClosed = true
			_ = st.Close()
		}
	}
	defer closeStore()

	// Post-migration the keyring is authoritative (§1.8 ingress-after-
	// migration): decide presence from the keyring, never by re-reading a
	// plaintext source the migration may have just scrubbed.
	hadKey := st.HasAPIKey()

	switch {
	case opts.secretFromFlags():
		// No-clobber by default (§1.5/§1.11): a scripted ingress must not
		// silently replace an existing keyring value — require --overwrite.
		if hadKey && !opts.overwrite {
			return errors.New(
				"an API key is already in the keyring; re-run with --overwrite to " +
					"replace it, or omit --api-key-stdin/--api-key-from-env to keep it")
		}
		secret, err := readSecret(opts)
		if err != nil {
			return err
		}
		if err := storeSecret(v, st, secret, opts.overwrite); err != nil {
			return err
		}
	case hadKey:
		v.Println("API key already present in the keyring (kept).")
	default:
		// No key anywhere and no scripted ingress. Interactive: no-echo
		// prompt. Non-interactive (or non-TTY): a hard, actionable error
		// (never a silent empty key).
		if !wantPrompt {
			return errors.New(
				"no API key in the keyring and no ingress flag: pass " +
					"--api-key-stdin or --api-key-from-env NEWRELIC_API_KEY (§1.5.1)")
		}
		secret, err := promptSecret(opts, "API key (NRAK-…): ")
		if err != nil {
			return err
		}
		if err := storeSecret(v, st, secret, false); err != nil {
			return err
		}
	}

	// Non-secret account_id / region → config.yml. Load AFTER migration so
	// any folded legacy values are visible; only overwrite when the user
	// supplied a value (flag or interactive prompt).
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// account_id is non-secret: --account-id-from-env reads it from the
	// named env var (the same op→env→--*-from-env channel the installer
	// uses for the secret, §1.5.1 shape) but the resolved value goes to
	// config.yml, NEVER the keyring (§2.5). Empty/unset env is a hard
	// error, mirroring readSecret's env path.
	accountID := opts.accountID
	if opts.accountIDEnv != "" {
		accountID = os.Getenv(opts.accountIDEnv)
		if accountID == "" {
			return fmt.Errorf("--account-id-from-env %s is empty or unset", opts.accountIDEnv)
		}
	}
	if accountID == "" && wantPrompt {
		accountID = prompt(opts, fmt.Sprintf("Account ID [%s]: ", cfg.AccountID))
	}
	if accountID != "" {
		if err := validate.AccountID(accountID); err != nil {
			return err
		}
		cfg.AccountID = accountID
	}
	region := opts.region
	if region == "" && wantPrompt {
		def := cfg.Region
		if def == "" {
			def = config.DefaultRegion
		}
		region = prompt(opts, fmt.Sprintf("Region (US/EU) [%s]: ", def))
	}
	if region != "" {
		region = strings.ToUpper(region)
		if err := validate.Region(region); err != nil {
			return err
		}
		cfg.Region = region
	}
	// Only write config.yml when a non-secret field was actually supplied,
	// OR config.yml already exists (keep it consistent / persist a folded
	// migration). A secret-only ingress in a pipeline must not create or
	// touch config.yml just to restate the default credential_ref.
	cfgPath, perr := config.Path()
	if perr != nil {
		return perr
	}
	_, statErr := os.Stat(cfgPath)
	if accountID != "" || region != "" || statErr == nil {
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
	}

	if !opts.noVerify {
		// Release our keyring handle before the verify path opens its own
		// (opts.APIClient() → keychain.Open()). A strict file-backend lock
		// could otherwise reject the second concurrent open and fail
		// verification spuriously after a successful credential write.
		closeStore()
		client, err := opts.APIClient()
		if err != nil {
			v.Error("Failed to create client: %v", err)
			v.Println("Configuration saved; test later with: nrq config test")
			return nil
		}
		result, err := client.TestConnection()
		if err != nil {
			v.Error("Connection test error: %v", err)
			return nil
		}
		if result.APIKeyValid {
			v.Success("API key valid")
		} else {
			v.Error("API key invalid or expired")
			if result.ErrorMessage != "" {
				v.Println("Error: " + result.ErrorMessage)
			}
			return nil
		}
		if !client.AccountID.IsEmpty() {
			if result.AccountAccess {
				v.Success("Account %d accessible", result.AccountID)
			} else {
				v.Error("Account not accessible")
			}
		}
	}

	v.Success("Configuration saved.")
	v.Println("Try:  nrq apps list")
	return nil
}

func storeSecret(v *view.View, st *keychain.Store, secret string, overwrite bool) error {
	if warning, err := validate.APIKey(secret); err != nil {
		return err
	} else if warning != "" {
		v.Warning("%s", warning)
	}
	if overwrite {
		return st.SetAPIKeyOverwrite(secret)
	}
	if err := st.SetAPIKey(secret); err != nil {
		if errors.Is(err, credstore.ErrExists) {
			// HasAPIKey() said no *usable* key yet a physical entry exists:
			// it is present-but-empty (corrupted — §APIKey). Repairing an
			// unusable entry is not a clobber of a real credential, so
			// overwrite it without demanding --overwrite. A real (non-empty)
			// key never reaches here in the no-clobber path (HasAPIKey() is
			// true → guarded in runInit); a TOCTOU race that wrote a genuine
			// key still surfaces the actionable hint below.
			if _, apErr := st.APIKey(); errors.Is(apErr, keychain.ErrCorruptedAPIKey) {
				return st.SetAPIKeyOverwrite(secret)
			}
			return errors.New(
				"an API key is already in the keyring; re-run with --overwrite to replace it")
		}
		return err
	}
	return nil
}

func readSecret(o *initOptions) (string, error) {
	if o.apiKeyStdin {
		b, err := io.ReadAll(o.Stdin)
		if err != nil {
			return "", fmt.Errorf("read API key from stdin: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	v := os.Getenv(o.apiKeyEnv)
	if v == "" {
		return "", fmt.Errorf("--api-key-from-env %s is empty or unset", o.apiKeyEnv)
	}
	return v, nil
}

func promptSecret(o *initOptions, label string) (string, error) {
	fmt.Fprint(o.Stderr, label)
	if f, ok := o.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(o.Stderr)
		if err != nil {
			return "", fmt.Errorf("read API key: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	// Non-TTY but interactive() said terminal — defensive fallback (tests
	// inject a non-*os.File reader): plain read, never echoed by us.
	line, _ := bufio.NewReader(o.Stdin).ReadString('\n')
	return strings.TrimSpace(line), nil
}

func prompt(o *initOptions, label string) string {
	// Prompts go to stderr (like promptSecret): stdout is the data channel
	// (`nrq init -o json > out`, CI, 1Password shell plugin) and a prompt
	// on stdout would corrupt the captured stream.
	fmt.Fprint(o.Stderr, label)
	line, _ := bufio.NewReader(o.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
