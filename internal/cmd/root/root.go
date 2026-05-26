package root

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	cccredstore "github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
	"github.com/open-cli-collective/newrelic-cli/internal/output"
	"github.com/open-cli-collective/newrelic-cli/internal/version"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

// RegisterFunc registers a command tree onto a root command.
type RegisterFunc func(rootCmd *cobra.Command, opts *Options)

// Options contains global command options.
type Options struct {
	Output  string
	NoColor bool
	Verbose bool
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// DefaultOptions returns options with defaults.
func DefaultOptions() *Options {
	return &Options{
		Output: "table",
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

// View returns a configured view from options.
func (o *Options) View() *view.View {
	v := view.New(o.Stdout, o.Stderr)
	v.Format = view.Format(o.Output)
	v.NoColor = o.NoColor
	return v
}

// APIClient is the single lazy chokepoint for runtime credential resolution
// (§2.5 / §1.11). It is invoked ONLY by commands that actually need an API
// client — never from PersistentPreRunE — so `init`, `set-credential`,
// `config *`, `--help`, and no-credential paths never force keyring access
// or the §1.8 migration. Because it is the one place that opens the keyring,
// the migration runs at a single deterministic point: the stderr/_migration
// signal, non-zero-exit behavior, and §1.8 ingress-after-migration ordering
// are all deterministic.
func (o *Options) APIClient() (*api.Client, error) {
	store, err := keychain.Open() // runs the one-time §1.8 migration
	if err != nil {
		return nil, err
	}
	defer func() { _ = store.Close() }()

	apiKey, err := store.APIKey()
	if err != nil {
		return nil, err // ErrMissingAPIKey: actionable, no leak
	}

	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	accountID, _ := cfg.ResolveAccountID() // optional; env > config
	region, _ := cfg.ResolveRegion()       // env > config > "US"

	return api.NewWithConfig(api.ClientConfig{
		APIKey:    apiKey,
		AccountID: accountID,
		Region:    region,
		Verbose:   o.Verbose,
		Stderr:    o.Stderr,
	}), nil
}

const rootLong = `nrq is a command-line interface for New Relic.

It provides commands for managing applications, dashboards, alerts,
users, and other New Relic resources.

First-time setup (API key in the OS keyring — never plaintext, never in config.yml):
  nrq init

Non-interactive credential ingress:
  op read "op://vault/New Relic/api key" | nrq set-credential --key api_key --stdin
  nrq set-credential --key api_key --from-env NEWRELIC_API_KEY

Set the non-secret account ID / region (written to config.yml):
  nrq config set --account-id <id> --region US

Non-secret runtime overrides (precedence: env > config.yml):
  NEWRELIC_ACCOUNT_ID, NEWRELIC_REGION

NEWRELIC_API_KEY is accepted ONLY as setup ingress (init/set-credential
--from-env); it is no longer read at runtime (§1.11).`

// NewRootCmd builds a fresh root command and its Options. Returning a new
// tree per call (no package globals) is what makes the §1.11.6
// real-entrypoint acceptance tests isolated — repeated Execute() runs in one
// test process cannot bleed flag/output/migration state.
func NewRootCmd() (*cobra.Command, *Options) {
	opts := DefaultOptions()

	cmd := &cobra.Command{
		Use:     "nrq",
		Short:   "A CLI tool for interacting with New Relic",
		Long:    rootLong,
		Version: version.Info(),
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := view.ValidateFormat(opts.Output); err != nil {
				return err
			}
			// Mirror the resolved format so the §1.8 migration can choose
			// the stderr line vs the _migration JSON splice. The deprecated
			// --json bool still forces JSON.
			format := opts.Output
			if jsonFlag, _ := cmd.Flags().GetBool("json"); jsonFlag {
				format = "json"
				opts.Output = "json"
			}
			output.OutputFormat = format
			return WireBackendSelection(cmd)
		},
	}

	cmd.PersistentFlags().StringVarP(&opts.Output, "output", "o", "table",
		"Output format: table, json, or plain")
	cmd.PersistentFlags().BoolVar(&opts.NoColor, "no-color", false,
		"Disable colored output")
	cmd.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false,
		"Enable verbose output (shows API requests)")
	cmd.PersistentFlags().Bool("json", false, "Output in JSON format (deprecated: use -o json)")
	_ = cmd.PersistentFlags().MarkDeprecated("json", "use --output json instead")
	cmd.PersistentFlags().String(cccredstore.BackendFlagName, "", cccredstore.BackendFlagUsage())

	return cmd, opts
}

// WireBackendSelection validates the --backend flag and records it for
// the next keychain.Open* call. Cobra-layer only: it does NOT load
// config; openWith binds the flag pair against cfg.Keyring.Backend at
// the single credstore.Open call site.
//
// Exported so any subcommand that defines its own PersistentPreRunE
// can call it explicitly — cobra does NOT chain PersistentPreRunE, so a
// shadower silently loses the wiring without this hook. nrq has no
// shadowers today; the regression test guards the pattern.
func WireBackendSelection(cmd *cobra.Command) error {
	var value string
	var changed bool
	if bf := cmd.Flag(cccredstore.BackendFlagName); bf != nil {
		value = bf.Value.String()
		changed = bf.Changed
	}
	if err := cccredstore.BindBackendFlag(&cccredstore.Options{}, value, changed, ""); err != nil {
		return fmt.Errorf("--%s: %w", cccredstore.BackendFlagName, err)
	}
	keychain.SetBackendFlagOverride(value, changed)
	return nil
}

// RegisterAll applies the given register functions to cmd/opts. Used by both
// the real entrypoint and the §1.11.6 acceptance tests.
func RegisterAll(cmd *cobra.Command, opts *Options, fns ...RegisterFunc) {
	for _, fn := range fns {
		fn(cmd, opts)
	}
}

// NoPositionalArgs is a cobra Args validator for the secret-ingress commands
// (init, set-credential). cobra.NoArgs formats its error as
// `unknown command %q for %q`, quoting args[0] — so `nrq init NRAK-xxx`
// would echo the fat-fingered API key to stderr and any logs (§1.12). This
// rejects positional args with a STATIC message that never contains the
// argument value.
func NoPositionalArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errNoPositionalArgs
	}
	return nil
}

var errNoPositionalArgs = errors.New(
	"this command takes no positional arguments; a secret must be provided " +
		"via stdin, a named environment variable, or an interactive prompt — " +
		"never as a command-line argument (see --help; §1.5.1)")
