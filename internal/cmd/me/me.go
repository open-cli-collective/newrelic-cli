// Package me implements `nrq me`: a minimal identity / access check used
// by the central installer's `verify: "me"` step and by humans to confirm
// their credential resolves. It validates the API key and (when an account
// is configured) account access, reusing the existing TestConnection API —
// no new api/ surface. The API key is never printed (§1.12).
package me

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/view"
)

// Register adds the me command to the root command.
func Register(rootCmd *cobra.Command, opts *root.Options) {
	cmd := &cobra.Command{
		Use:   "me",
		Short: "Show the authenticated user and account (verifies the API key)",
		Long: `Resolve the API key from the OS keyring and report the
authenticated New Relic user and, when an account ID is configured, account
access. Exits non-zero if the key is invalid or the configured account is
not accessible — so it doubles as a scripted health check. The API key
itself is never displayed (§1.12).`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runMe(opts)
		},
	}
	rootCmd.AddCommand(cmd)
}

// identity is the JSON shape. It deliberately has no api_key field — the
// secret is never serialized (§1.12).
type identity struct {
	UserID        string `json:"user_id,omitempty"`
	UserEmail     string `json:"user_email,omitempty"`
	AccountID     int    `json:"account_id,omitempty"`
	AccountName   string `json:"account_name,omitempty"`
	Region        string `json:"region,omitempty"`
	APIKeyValid   bool   `json:"api_key_valid"`
	AccountAccess bool   `json:"account_access"`
}

func runMe(opts *root.Options) error {
	// Single credential chokepoint: opts.APIClient() resolves the key from
	// the keyring and runs the one-time §1.8 migration. No client injection.
	client, err := opts.APIClient()
	if err != nil {
		return err // ErrMissingAPIKey is already actionable, no leak
	}
	res, err := client.TestConnection()
	if err != nil {
		return err
	}
	accountConfigured := !client.AccountID.IsEmpty()

	if rerr := renderMe(opts.View(), res, accountConfigured); rerr != nil {
		return rerr
	}
	return evaluate(res, accountConfigured)
}

// evaluate is the pure success predicate, mirroring `config test` exactly:
// a valid key, and — when an account is configured — actual account access.
// `nrq me` must NOT exit 0 on a valid key with a broken configured account,
// or the installer's verify:"me" would pass on a misconfigured install.
// Returned non-nil → non-zero process exit.
func evaluate(res *api.ConnectionTestResult, accountConfigured bool) error {
	if !res.APIKeyValid {
		if res.ErrorMessage != "" {
			return fmt.Errorf("API key invalid: %s", res.ErrorMessage)
		}
		return errors.New("API key invalid or expired")
	}
	if accountConfigured && !res.AccountAccess {
		if res.ErrorMessage != "" {
			return fmt.Errorf("account not accessible: %s", res.ErrorMessage)
		}
		return errors.New("configured account is not accessible with this API key")
	}
	return nil
}

// renderMe is pure (no I/O beyond the View writer): unit-tested directly
// with synthetic results across table/json/plain. It never emits the
// api_key (§1.12).
func renderMe(v *view.View, res *api.ConnectionTestResult, accountConfigured bool) error {
	id := identity{
		UserID:        res.UserID,
		UserEmail:     res.UserEmail,
		Region:        res.Region,
		APIKeyValid:   res.APIKeyValid,
		AccountAccess: res.AccountAccess,
	}
	rows := [][]string{
		{"User ID", res.UserID},
		{"User email", res.UserEmail},
		{"Region", res.Region},
		{"API key valid", fmt.Sprintf("%t", res.APIKeyValid)},
	}
	if accountConfigured {
		id.AccountID = res.AccountID
		id.AccountName = res.AccountName
		rows = append(rows,
			[]string{"Account ID", fmt.Sprintf("%d", res.AccountID)},
			[]string{"Account name", res.AccountName},
			[]string{"Account access", fmt.Sprintf("%t", res.AccountAccess)},
		)
	}
	return v.Render([]string{"FIELD", "VALUE"}, rows, id)
}
