package ascode

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMutationKinds(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []Kind
	}{
		{
			name: "dashboard create",
			doc:  `mutation { dashboardCreate(accountId: 1, dashboard: {name: "x"}) { entityResult { guid } } }`,
			want: []Kind{Dashboard},
		},
		{
			name: "named mutation with variables and directives",
			doc: `mutation UpdateIt($guid: EntityGuid!, $d: DashboardInput!) @trace {
				dashboardUpdate(guid: $guid, dashboard: $d) { errors { description } }
			}`,
			want: []Kind{Dashboard},
		},
		{
			name: "every dashboard write",
			doc: `mutation {
				a: dashboardUpdateWidgetsInPage(guid: "g", widgets: []) { errors { type } }
				b: dashboardAddWidgetsToPage(guid: "g", widgets: []) { errors { type } }
				c: dashboardDelete(guid: "g") { status }
				d: dashboardUndelete(guid: "g") { errors { type } }
				e: dashboardUpdatePage(guid: "g", page: {}) { errors { type } }
			}`,
			want: []Kind{Dashboard},
		},
		{
			name: "alias resolves to the real field",
			doc:  `mutation { snapshot: dashboardCreateSnapshotUrl(guid: "g") ok: dashboardDelete(guid: "g") { status } }`,
			want: []Kind{Dashboard},
		},
		{
			name: "alias named like a write does not match",
			doc:  `mutation { dashboardCreate: dashboardCreateSnapshotUrl(guid: "g") }`,
			want: nil,
		},
		{
			name: "multiple kinds in one document",
			doc: `mutation {
				syntheticsDeleteMonitor(guid: "g") { deletedGuid }
				alertsNrqlConditionStaticUpdate(accountId: 1, id: 2, condition: {}) { id }
				alertsPolicyCreate(accountId: 1, policy: {name: "p", incidentPreference: PER_POLICY}) { id }
				dashboardCreate(accountId: 1, dashboard: {}) { entityResult { guid } }
			}`,
			want: []Kind{Dashboard, AlertPolicy, AlertCondition, SyntheticMonitor},
		},
		{
			name: "alert policy update and delete",
			doc:  `mutation { alertsPolicyUpdate(accountId: 1, id: 2, policy: {}) { id } alertsPolicyDelete(accountId: 1, id: 2) { id } }`,
			want: []Kind{AlertPolicy},
		},
		{
			name: "alert condition delete and baseline create",
			doc:  `mutation { alertsConditionDelete(accountId: 1, id: 2) { id } alertsNrqlConditionBaselineCreate(accountId: 1, policyId: 3, condition: {}) { id } }`,
			want: []Kind{AlertCondition},
		},
		{
			name: "synthetics monitor writes",
			doc: `mutation {
				syntheticsCreateSimpleMonitor(accountId: 1, monitor: {}) { errors { type } }
				syntheticsUpdateScriptApiMonitor(guid: "g", monitor: {}) { errors { type } }
				syntheticsUpdateScript(guid: "g", script: {}) { errors { type } }
			}`,
			want: []Kind{SyntheticMonitor},
		},
		{
			name: "fragment spread on Mutation",
			doc: `mutation { ...Writes }
			fragment Writes on Mutation { dashboardDelete(guid: "g") { status } }`,
			want: []Kind{Dashboard},
		},
		{
			name: "fragment defined before use and spread twice",
			doc: `fragment W on Mutation { alertsPolicyDelete(accountId: 1, id: 2) { id } ...W }
			mutation { ...W ...W }`,
			want: []Kind{AlertPolicy},
		},
		{
			name: "inline fragment with and without type condition",
			doc:  `mutation { ... on Mutation { dashboardCreate(accountId: 1, dashboard: {}) { entityResult { guid } } } ... @include(if: true) { syntheticsDeleteMonitor(guid: "g") { deletedGuid } } }`,
			want: []Kind{Dashboard, SyntheticMonitor},
		},
		{
			name: "comments, commas and block strings around a write",
			doc: `# a comment mentioning query { }
			mutation { # trailing comment }
				dashboardDelete(guid: "g",) { status, errors { type } }
				description: x(text: """ a "quoted" } block """)
			}`,
			want: []Kind{Dashboard},
		},
		{
			name: "read-only query",
			doc:  `{ actor { entitySearch(query: "type = 'DASHBOARD'") { results { entities { guid } } } } }`,
			want: nil,
		},
		{
			name: "named query whose fields share write names",
			doc:  `query dashboardCreate { actor { dashboardCreate: user { name } } }`,
			want: nil,
		},
		{
			name: "write name only in a comment",
			doc: `# mutation { dashboardDelete(guid: "g") }
			{ actor { user { email } } }`,
			want: nil,
		},
		{
			name: "write name only in a string literal",
			doc:  `{ actor { account(id: 1) { nrql(query: "mutation { dashboardDelete(guid: \"g\") }") { results } } } }`,
			want: nil,
		},
		{
			name: "write name only in a block string",
			doc:  `{ actor { account(id: 1) { nrql(query: """ mutation { alertsPolicyDelete } """) { results } } } }`,
			want: nil,
		},
		{
			name: "write name nested below the top level of a mutation",
			doc:  `mutation { taggingAddTagsToEntity(guid: "g", tags: []) { errors { dashboardCreate } } }`,
			want: nil,
		},
		{
			name: "other dashboard and alert mutations",
			doc: `mutation {
				dashboardCreateSnapshotUrl(guid: "g")
				alertsPolicyAddNotificationChannels(accountId: 1, id: 2) { errors { type } }
				alertsMutingRuleCreate(accountId: 1, rule: {}) { id }
				syntheticsCreateSecureCredential(accountId: 1, key: "K", value: "v") { errors { type } }
				syntheticsStartAutomatedTest { batchId }
			}`,
			want: nil,
		},
		{
			name: "fragment with write fields that no mutation spreads",
			doc: `query { actor { user { name } } }
			fragment W on Mutation { dashboardDelete(guid: "g") { status } }`,
			want: nil,
		},
		{
			name: "subscription is not a mutation",
			doc:  `subscription { dashboardCreate }`,
			want: nil,
		},
		{
			name: "empty document",
			doc:  ``,
			want: nil,
		},
		{
			name: "unterminated document still finds the write",
			doc:  `mutation { dashboardDelete(guid: "g") { status `,
			want: []Kind{Dashboard},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MutationKinds(tt.doc))
		})
	}
}

func TestMessage(t *testing.T) {
	one := Message(Dashboard)
	assert.True(t, strings.HasPrefix(one, "Note: dashboards are often managed as code"), one)
	assert.Contains(t, one, DisableEnv+"=1")
	assert.Equal(t, 2, strings.Count(one, "\n"), "the note is two lines")

	assert.Contains(t, Message(SyntheticMonitor, AlertPolicy), "Note: alert policies and synthetic monitors are")
	assert.Contains(t, Message(SyntheticMonitor, Dashboard, AlertCondition, AlertPolicy, Dashboard),
		"Note: dashboards, alert policies, alert conditions and synthetic monitors are")

	assert.NotContains(t, Message(Dashboard, AlertPolicy, AlertCondition, SyntheticMonitor), "—",
		"the note must not contain an em dash")
}

func TestNotify(t *testing.T) {
	t.Run("writes the note", func(t *testing.T) {
		t.Setenv(DisableEnv, "")
		var buf bytes.Buffer
		Notify(&buf, Dashboard)
		assert.Equal(t, Message(Dashboard), buf.String())
	})
	t.Run("no kinds writes nothing", func(t *testing.T) {
		t.Setenv(DisableEnv, "")
		var buf bytes.Buffer
		Notify(&buf)
		assert.Empty(t, buf.String())
	})
	for _, v := range []string{"1", "true", "TRUE", " 1 "} {
		t.Run("silenced by "+v, func(t *testing.T) {
			t.Setenv(DisableEnv, v)
			var buf bytes.Buffer
			Notify(&buf, Dashboard)
			assert.Empty(t, buf.String())
		})
	}
	for _, v := range []string{"0", "false", "no"} {
		t.Run("not silenced by "+v, func(t *testing.T) {
			t.Setenv(DisableEnv, v)
			var buf bytes.Buffer
			Notify(&buf, Dashboard)
			assert.NotEmpty(t, buf.String())
		})
	}
}

func TestAllKindsHavePlurals(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range allKinds {
		p := k.plural()
		assert.NotEqual(t, Kind(0).plural(), p, "kind %d needs a case in plural", k)
		assert.False(t, seen[p], "duplicate plural %q", p)
		seen[p] = true
	}
}
