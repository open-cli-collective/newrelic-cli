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

// newShowOpts returns a showOptions wired to a byte buffer so the test can
// inspect what runShow wrote.
func newShowOpts(jsonFlag bool) (*showOptions, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return &showOptions{
		Options: &root.Options{
			Output: "table",
			Stdout: buf,
			Stderr: &bytes.Buffer{},
		},
		json: jsonFlag,
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
	opts, out := newShowOpts(false)
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow text: %v", err)
	}
	if !strings.Contains(out.String(), "keyring.backend: file (config.yml)") {
		t.Errorf("text show missing selector line:\n%s", out.String())
	}

	// JSON output via local --json flag (cli-common §2 carve-out).
	opts, jsonOut := newShowOpts(true)
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

	opts, out := newShowOpts(false)
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow text: %v", err)
	}
	if strings.Contains(out.String(), "keyring.backend:") {
		t.Errorf("text show emitted selector line when unset:\n%s", out.String())
	}

	opts, jsonOut := newShowOpts(true)
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow json: %v", err)
	}
	if strings.Contains(jsonOut.String(), `"keyring_backend"`) {
		t.Errorf("json show emitted keyring_backend when unset: %s", jsonOut.String())
	}
}

// TestRunShow_JSONFlagOverridesGlobalOutput pins the carve-out composition
// rule (the slck lesson): the subcommand-local --json flag wins even when
// the global -o table is set. This proves config show --json is a true
// local carve-out, not a re-route through the global output selector.
func TestRunShow_JSONFlagOverridesGlobalOutput(t *testing.T) {
	testutil.Setup(t)

	buf := &bytes.Buffer{}
	opts := &showOptions{
		Options: &root.Options{
			Output: "table", // global says table
			Stdout: buf,
			Stderr: &bytes.Buffer{},
		},
		json: true, // local says JSON — local must win
	}
	if err := runShow(opts); err != nil {
		t.Fatalf("runShow: %v", err)
	}
	var st showStatus
	if err := json.Unmarshal(buf.Bytes(), &st); err != nil {
		t.Fatalf("local --json must produce JSON when -o table is also set; got: %s\nerr: %v", buf.String(), err)
	}
}
