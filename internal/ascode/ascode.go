// Package ascode prints a one-time stderr note when nrq is about to write a
// New Relic resource that teams commonly manage as code (Terraform, a
// dashboards repository or similar). A direct write to such a resource is
// silently reverted by the next deploy from its source, so the note asks the
// caller to check for a source of truth first.
//
// The note never blocks, prompts, or touches stdout or the exit code: per
// cli-common docs/output-and-rendering.md §5 it is side-channel chatter, and
// JSON passthrough output (`nrq nerdgraph query`) must stay machine-parseable.
package ascode

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// DisableEnv silences the note when set to a true value ("1", "true").
const DisableEnv = "NEWRELIC_CLI_NO_AS_CODE_NOTICE"

// Kind is a resource kind that teams commonly manage as code.
type Kind int

// Kinds in the order the note names them.
const (
	Dashboard Kind = iota + 1
	AlertPolicy
	AlertCondition
	SyntheticMonitor
)

func (k Kind) plural() string {
	switch k {
	case Dashboard:
		return "dashboards"
	case AlertPolicy:
		return "alert policies"
	case AlertCondition:
		return "alert conditions"
	case SyntheticMonitor:
		return "synthetic monitors"
	default:
		return "resources"
	}
}

// Disabled reports whether DisableEnv silences the note.
func Disabled() bool {
	on, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(DisableEnv)))
	return err == nil && on
}

// Notify writes the note for kinds to w, unless kinds is empty or the note is
// disabled. Callers invoke it once per command, before the write is sent, so
// the note is visible even when the write fails.
func Notify(w io.Writer, kinds ...Kind) {
	if len(kinds) == 0 || Disabled() {
		return
	}
	fmt.Fprint(w, Message(kinds...))
}

// Message returns the note text for kinds, deduplicated and in Kind order.
func Message(kinds ...Kind) string {
	seen := make(map[Kind]bool, len(kinds))
	for _, k := range kinds {
		seen[k] = true
	}
	var names []string
	for _, k := range []Kind{Dashboard, AlertPolicy, AlertCondition, SyntheticMonitor} {
		if seen[k] {
			names = append(names, k.plural())
		}
	}
	return fmt.Sprintf("Note: %s are often managed as code (Terraform, a repository or similar), "+
		"and the next deploy from that source can overwrite a direct change.\n"+
		"Check for a source of truth before making this change. Set %s=1 to hide this note.\n",
		joinNames(names), DisableEnv)
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return Kind(0).plural()
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}
