// Package output owns the §1.8 machine-readable migration signal for nrq.
// It is a leaf package (imported by internal/keychain's migration and by
// internal/view's JSON path) holding only: the run's output-format mirror so
// the migration can decide stderr-vs-_migration, and a consume-once recorder
// for the `_migration` block so it appears in exactly one JSON response and
// never bleeds into a later one or a parallel test.
package output

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

// OutputFormat mirrors the resolved --output value. Set once by root's
// PersistentPreRunE before any command runs. The §1.8 migration consults
// IsJSON() to choose the stderr line vs the _migration JSON splice.
var OutputFormat string

// IsJSON reports whether the run emits JSON (so the migration records the
// _migration block instead of printing the stderr line).
func IsJSON() bool { return OutputFormat == "json" }

var (
	migMu      sync.Mutex
	migPending []byte // marshaled migration block value, or nil if none
)

// RecordMigration stores the §1.8 block (anything that marshals to the
// `_migration` value, e.g. credstore.MigrationBlock). nil/empty changes must
// not call this — absence means "no migration this run".
func RecordMigration(block interface{}) {
	b, err := json.Marshal(block)
	if err != nil {
		return // a marshal failure here must not break the actual command
	}
	migMu.Lock()
	migPending = b
	migMu.Unlock()
}

// takeMigration returns the pending block and clears it (consume-once).
func takeMigration() []byte {
	migMu.Lock()
	defer migMu.Unlock()
	b := migPending
	migPending = nil
	return b
}

// ResetMigration drops any pending block without emitting it. Test hook so
// one test's recorded migration can never bleed into another.
func ResetMigration() {
	migMu.Lock()
	migPending = nil
	migMu.Unlock()
}

// MarshalWithMigration marshals data to indented JSON; if a §1.8 block was
// recorded this run it is spliced in as the first top-level field (object
// responses) or wraps a non-object response as {"_migration":..,"data":..},
// consume-once. Returns the bytes the JSON writer should emit.
func MarshalWithMigration(data interface{}) ([]byte, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	mig := takeMigration()
	if mig == nil {
		var buf bytes.Buffer
		if err := json.Indent(&buf, body, "", "  "); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, spliceMigration(body, mig), "", "  "); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FlushMigrationJSONOnError writes the standalone {"_migration":{…}} object
// to w iff the run is JSON and a block is still pending (consume-once). The
// real entrypoint calls this on a non-zero exit so a migration that
// succeeded before the command failed is still surfaced — §1.8/§1.11.6: the
// one-time signal must survive a non-zero exit. On the success path
// View.JSON already consumed the block, so this is a no-op there.
func FlushMigrationJSONOnError(w io.Writer) {
	if !IsJSON() {
		return
	}
	mig := takeMigration()
	if mig == nil {
		return
	}
	_, _ = w.Write([]byte(`{"_migration":` + string(mig) + "}\n"))
}

// spliceMigration applies the object-merge / non-object-wrap policy to an
// already-marshaled response body, returning compact JSON.
func spliceMigration(body, mig []byte) []byte {
	t := bytes.TrimSpace(body)
	if len(t) > 0 && t[0] == '{' && t[len(t)-1] == '}' {
		inner := bytes.TrimSpace(t[1 : len(t)-1])
		if len(inner) == 0 {
			return []byte(`{"_migration":` + string(mig) + `}`)
		}
		return []byte(`{"_migration":` + string(mig) + `,` + string(inner) + `}`)
	}
	return []byte(`{"_migration":` + string(mig) + `,"data":` + string(t) + `}`)
}
