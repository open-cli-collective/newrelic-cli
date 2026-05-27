package keychain

import (
	"testing"

	"github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
)

func resetOverride(t *testing.T) {
	t.Helper()
	SetBackendFlagOverride("", false)
	t.Cleanup(func() { SetBackendFlagOverride("", false) })
}

// TestOpenWith_ConfigOnlyMemoryBackend proves openWith consumes
// cfg.Keyring.Backend via BindBackendFlag. Memory backend keeps this
// platform-/passphrase-free.
func TestOpenWith_ConfigOnlyMemoryBackend(t *testing.T) {
	resetOverride(t)
	t.Setenv("NEWRELIC_CLI_KEYRING_BACKEND", "")

	cfg := &config.Config{
		CredentialRef: config.DefaultCredentialRef,
		Keyring:       config.KeyringConfig{Backend: string(credstore.BackendMemory)},
	}
	st, err := openWith(cfg, false, false, true)
	if err != nil {
		t.Fatalf("openWith: %v", err)
	}
	defer func() { _ = st.Close() }()

	b, src := st.Backend()
	if b != credstore.BackendMemory {
		t.Errorf("Backend = %q, want %q", b, credstore.BackendMemory)
	}
	if src != credstore.SourceConfig {
		t.Errorf("Source = %q, want %q", src, credstore.SourceConfig)
	}
}

// TestOpenWith_FlagOverridesConfig proves --backend wins over
// keyring.backend. Flag is set to memory; config-side is file (which
// would otherwise fail without a passphrase), so a regression where
// the flag is dropped would surface as a passphrase error rather than
// silent success.
func TestOpenWith_FlagOverridesConfig(t *testing.T) {
	resetOverride(t)
	t.Setenv("NEWRELIC_CLI_KEYRING_BACKEND", "")
	SetBackendFlagOverride(string(credstore.BackendMemory), true)

	cfg := &config.Config{
		CredentialRef: config.DefaultCredentialRef,
		Keyring:       config.KeyringConfig{Backend: string(credstore.BackendFile)},
	}
	st, err := openWith(cfg, false, false, true)
	if err != nil {
		t.Fatalf("openWith: %v", err)
	}
	defer func() { _ = st.Close() }()

	b, src := st.Backend()
	if b != credstore.BackendMemory {
		t.Errorf("Backend = %q, want %q (flag should override config)", b, credstore.BackendMemory)
	}
	if src != credstore.SourceExplicit {
		t.Errorf("Source = %q, want %q", src, credstore.SourceExplicit)
	}
}
