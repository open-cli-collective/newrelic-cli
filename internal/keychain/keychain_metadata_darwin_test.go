//go:build darwin && cgo

package keychain

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/byteness/keyring"
	"github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

func TestKeychainMetadataGated(t *testing.T) {
	if os.Getenv("NRQ_KEYCHAIN_METADATA_TEST") != "1" {
		t.Skip("set NRQ_KEYCHAIN_METADATA_TEST=1 to write to the real macOS Keychain")
	}

	home := os.Getenv("HOME")
	testutil.Setup(t)
	// testutil.Setup isolates HOME for config tests, but the real macOS
	// Keychain backend uses HOME to find the user's default login keychain.
	t.Setenv("HOME", home)
	SetBackendFlagOverride(string(credstore.BackendKeychain), true)
	t.Cleanup(func() { SetBackendFlagOverride("", false) })

	profile := "metadata-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	ref := "newrelic-cli/" + profile
	account := profile + "/" + KeyAPIKey
	t.Logf("using synthetic Keychain ref %q account %q", ref, account)

	st, err := openWith(&config.Config{CredentialRef: ref}, false, false, false)
	if err != nil {
		t.Fatalf("openWith(%q): %v", ref, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t.Cleanup(func() { _ = st.DeleteAPIKey() })

	kr, err := keyring.Open(keyring.Config{
		ServiceName:              "newrelic-cli",
		AllowedBackends:          []keyring.BackendType{keyring.KeychainBackend},
		KeychainTrustApplication: true,
	})
	if err != nil {
		t.Fatalf("open ByteNess Keychain backend: %v", err)
	}
	t.Cleanup(func() { _ = kr.Remove(account) })

	wantLabel := "newrelic-cli " + account
	wantDescription := "Credential for newrelic-cli " + account

	if err := kr.Set(keyring.Item{Key: account, Data: []byte("legacy")}); err != nil {
		t.Fatalf("seed stale metadata item: %v", err)
	}
	seeded, err := kr.GetMetadata(account)
	if err != nil {
		t.Fatalf("GetMetadata(%q) after seed: %v", account, err)
	}
	if seeded.Item == nil {
		t.Fatalf("GetMetadata(%q) after seed returned nil item", account)
	}
	if seeded.Label == wantLabel && seeded.Description == wantDescription {
		t.Fatalf("seeded item already has target metadata label=%q description=%q", seeded.Label, seeded.Description)
	}

	if err := st.SetAPIKeyOverwrite("NRAK-metadata-test"); err != nil {
		t.Fatalf("SetAPIKeyOverwrite: %v", err)
	}

	md, err := kr.GetMetadata(account)
	if err != nil {
		t.Fatalf("GetMetadata(%q): %v", account, err)
	}
	if md.Item == nil {
		t.Fatalf("GetMetadata(%q) returned nil item", account)
	}

	if md.Label != wantLabel {
		t.Fatalf("metadata label = %q, want %q", md.Label, wantLabel)
	}

	if md.Description != wantDescription {
		t.Fatalf("metadata description = %q, want %q", md.Description, wantDescription)
	}
}
