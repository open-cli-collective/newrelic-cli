package output

import (
	"strings"
	"testing"
)

// M2: a non-object response (e.g. a JSON array) with a recorded migration
// must be wrapped as {"_migration":…,"data":<original>} (the documented
// non-object policy), not silently dropped or corrupted.
func TestMarshalWithMigration_NonObjectWrap(t *testing.T) {
	t.Cleanup(ResetMigration)
	ResetMigration()
	RecordMigration(map[string]any{"version": 1, "changes": []any{}})

	b, err := MarshalWithMigration([]string{"a", "b"})
	if err != nil {
		t.Fatalf("MarshalWithMigration: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, `"_migration"`) {
		t.Errorf("missing _migration in non-object wrap: %s", got)
	}
	if !strings.Contains(got, `"data"`) {
		t.Errorf("non-object body must be wrapped under data: %s", got)
	}
	if !strings.Contains(got, `"a"`) || !strings.Contains(got, `"b"`) {
		t.Errorf("original array contents lost: %s", got)
	}
}

// Object responses merge _migration as a top-level field, preserving the
// original fields; and the block is consume-once.
func TestMarshalWithMigration_ObjectMerge_ConsumeOnce(t *testing.T) {
	t.Cleanup(ResetMigration)
	ResetMigration()
	RecordMigration(map[string]any{"version": 1})

	b, err := MarshalWithMigration(map[string]string{"ok": "yes"})
	if err != nil {
		t.Fatalf("MarshalWithMigration: %v", err)
	}
	if !strings.Contains(string(b), `"_migration"`) || !strings.Contains(string(b), `"ok"`) {
		t.Errorf("object merge lost a field: %s", b)
	}
	// Consume-once: a second marshal has no block.
	b2, err := MarshalWithMigration(map[string]string{"ok": "yes"})
	if err != nil {
		t.Fatalf("second MarshalWithMigration: %v", err)
	}
	if strings.Contains(string(b2), `"_migration"`) {
		t.Errorf("migration block must be consumed once, got: %s", b2)
	}
}
