package configcmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

// newCapturedOpts returns a root.Options wired to a byte buffer so the
// test can inspect what runShow wrote.
func newCapturedOpts(format string) (*root.Options, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return &root.Options{
		Output: format,
		Stdout: buf,
		Stderr: &bytes.Buffer{},
	}, buf
}

// TestRunShow_ReportsKeyringBackendSelector seeds keyring.backend in
// config.yml and asserts both the text output and the JSON status
// carry the selector — proves the showStatus.KeyringBackend wiring is
// reachable through runShow.
func TestRunShow_ReportsKeyringBackendSelector(t *testing.T) {
	testutil.Setup(t)
	// Setup forces the file backend via env; persist a different
	// selector in config.yml so the new line is non-empty.
	cfg, err := config.LoadForRuntime()
	if err != nil {
		t.Fatalf("LoadForRuntime: %v", err)
	}
	cfg.Keyring.Backend = "file"
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// text output
	opts, out := newCapturedOpts("table")
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow text: %v", err)
	}
	if !strings.Contains(out.String(), "keyring.backend: file (config.yml)") {
		t.Errorf("text show missing selector line:\n%s", out.String())
	}

	// JSON output
	opts, jsonOut := newCapturedOpts("json")
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow json: %v", err)
	}
	var st showStatus
	if err := json.Unmarshal(jsonOut.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, jsonOut.String())
	}
	if st.KeyringBackend != "file" {
		t.Errorf("KeyringBackend = %q, want %q", st.KeyringBackend, "file")
	}
}

// TestRunShow_OmitsKeyringBackendWhenUnset asserts the omitempty path:
// no config.yml selector → no `keyring.backend:` line in text, no
// `keyring_backend` key in JSON.
func TestRunShow_OmitsKeyringBackendWhenUnset(t *testing.T) {
	testutil.Setup(t)
	// Default config has Keyring.Backend == "".

	opts, out := newCapturedOpts("table")
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow text: %v", err)
	}
	if strings.Contains(out.String(), "keyring.backend:") {
		t.Errorf("text show emitted selector line when unset:\n%s", out.String())
	}

	opts, jsonOut := newCapturedOpts("json")
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow json: %v", err)
	}
	if strings.Contains(jsonOut.String(), `"keyring_backend"`) {
		t.Errorf("json show emitted keyring_backend when unset: %s", jsonOut.String())
	}
}
