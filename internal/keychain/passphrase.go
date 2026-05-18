package keychain

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// passphraseEnvVar is the §1.4 named exception: <SERVICE>_KEYRING_PASSPHRASE,
// SERVICE being the upper-snake-cased service segment of the credential_ref
// (newrelic-cli -> NEWRELIC_CLI_KEYRING_PASSPHRASE). Service segments are
// [A-Za-z0-9_-], so only '-' needs translating.
func passphraseEnvVar(service string) string {
	return strings.ToUpper(strings.ReplaceAll(service, "-", "_")) + "_KEYRING_PASSPHRASE"
}

// passphraseFunc is credstore Options.FilePassphrase: consulted only for the
// encrypted-file backend, and only after credstore has already checked
// <SERVICE>_KEYRING_PASSPHRASE itself. So this is the interactive fallback:
// a no-echo TTY prompt. Headless with no env var set is a hard, actionable
// error — never a silent empty passphrase (that would create an
// effectively-unencrypted keyring).
//
// When nonInteractive is set (`nrq init --non-interactive`) the prompt is
// suppressed even on a TTY: the passphrase must come from the env var or
// the call fails loud, so the installer's non-interactive init is
// deterministic (cli-deployment-manifest §1.3).
func passphraseFunc(service string, nonInteractive bool) func() (string, error) {
	return func() (string, error) {
		if nonInteractive || !term.IsTerminal(int(os.Stdin.Fd())) {
			hint := ", or run interactively"
			if nonInteractive {
				hint = " (required with --non-interactive)"
			}
			return "", fmt.Errorf(
				"file keyring backend needs a passphrase: set %s%s",
				passphraseEnvVar(service), hint)
		}
		fmt.Fprintf(os.Stderr, "Passphrase for the %s file keyring: ", service)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		p := strings.TrimRight(string(b), "\r\n")
		if p == "" {
			return "", fmt.Errorf("empty passphrase rejected")
		}
		return p, nil
	}
}

// PassphraseSource describes, for `config show`, where the file-backend
// passphrase would come from (§1.4: the user must understand their posture).
// Only meaningful when the file backend is in use.
func PassphraseSource(service string) string {
	if os.Getenv(passphraseEnvVar(service)) != "" {
		return "env (" + passphraseEnvVar(service) + ")"
	}
	return "interactive prompt"
}
