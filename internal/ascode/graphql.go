package ascode

import "strings"

// MutationKinds returns the managed-as-code kinds that a GraphQL document's
// mutation operations create, update or delete, in Kind order. Read-only
// operations, other mutations, and text inside comments or string literals
// never match. Top-level fields reached through inline fragments and named
// fragment spreads count. The scan is lenient: a malformed document yields
// whatever it could recognize, and NerdGraph reports the syntax error.
func MutationKinds(document string) []Kind {
	p := &gqlParser{toks: lexGraphQL(document)}
	fragments, mutations := p.parseDocument()

	seen := map[Kind]bool{}
	visited := map[string]bool{}
	var walk func([]gqlSelection)
	walk = func(sels []gqlSelection) {
		for _, s := range sels {
			switch {
			case s.spread != "":
				if !visited[s.spread] {
					visited[s.spread] = true
					walk(fragments[s.spread])
				}
			case s.inline != nil:
				walk(s.inline)
			default:
				if k, ok := classifyMutationField(s.field); ok {
					seen[k] = true
				}
			}
		}
	}
	for _, m := range mutations {
		walk(m)
	}

	var kinds []Kind
	for _, k := range allKinds {
		if seen[k] {
			kinds = append(kinds, k)
		}
	}
	return kinds
}

var dashboardMutations = map[string]bool{
	"dashboardCreate":              true,
	"dashboardUpdate":              true,
	"dashboardUpdatePage":          true,
	"dashboardUpdateWidgetsInPage": true,
	"dashboardAddWidgetsToPage":    true,
	"dashboardDelete":              true,
	"dashboardUndelete":            true,
}

var alertPolicyMutations = map[string]bool{
	"alertsPolicyCreate": true,
	"alertsPolicyUpdate": true,
	"alertsPolicyDelete": true,
}

// classifyMutationField maps a NerdGraph mutation field name to the kind it
// writes. The field names come from the Mutation type of the NerdGraph schema
// (https://api.newrelic.com/graphiql). When changing this package, check that
// type for new dashboard*, alerts* and synthetics* fields that create, update
// or delete these resources and add them here with a test case. Dashboard and
// policy fields are an explicit list because sibling mutations
// (dashboardCreateSnapshotUrl, alertsPolicyAddNotificationChannels) do not
// change the resource definition.
func classifyMutationField(name string) (Kind, bool) {
	switch {
	case dashboardMutations[name]:
		return Dashboard, true
	case alertPolicyMutations[name]:
		return AlertPolicy, true
	case strings.HasPrefix(name, "alertsNrqlCondition"), name == "alertsConditionDelete":
		return AlertCondition, true
	case isSyntheticsMonitorWrite(name):
		return SyntheticMonitor, true
	}
	return 0, false
}

func isSyntheticsMonitorWrite(name string) bool {
	if name == "syntheticsUpdateScript" {
		return true
	}
	for _, verb := range []string{"syntheticsCreate", "syntheticsUpdate", "syntheticsDelete"} {
		if strings.HasPrefix(name, verb) && strings.HasSuffix(name, "Monitor") {
			return true
		}
	}
	return false
}

type gqlTokenKind int

const (
	tokName gqlTokenKind = iota + 1
	tokPunct
	tokSpread
	tokValue // string or number literal; its content is irrelevant here
)

type gqlToken struct {
	kind gqlTokenKind
	text string
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

// lexGraphQL tokenizes a GraphQL document, dropping whitespace, commas,
// comments and the contents of string literals.
func lexGraphQL(src string) []gqlToken {
	var toks []gqlToken
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '#':
			for i < len(src) && src[i] != '\n' && src[i] != '\r' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case strings.HasPrefix(src[i:], `"""`):
			i += 3
			for i < len(src) && !strings.HasPrefix(src[i:], `"""`) {
				if strings.HasPrefix(src[i:], `\"""`) {
					i += 4
					continue
				}
				i++
			}
			i += 3
			toks = append(toks, gqlToken{kind: tokValue})
		case c == '"':
			i++
			for i < len(src) && src[i] != '"' && src[i] != '\n' {
				if src[i] == '\\' {
					i++
				}
				i++
			}
			i++
			toks = append(toks, gqlToken{kind: tokValue})
		case strings.HasPrefix(src[i:], "..."):
			i += 3
			toks = append(toks, gqlToken{kind: tokSpread, text: "..."})
		case isNameStart(c):
			start := i
			for i < len(src) && isNameChar(src[i]) {
				i++
			}
			toks = append(toks, gqlToken{kind: tokName, text: src[start:i]})
		case c == '-' || (c >= '0' && c <= '9'):
			i++
			for i < len(src) && (isNameChar(src[i]) || src[i] == '.' || src[i] == '+' || src[i] == '-') {
				i++
			}
			toks = append(toks, gqlToken{kind: tokValue})
		default:
			toks = append(toks, gqlToken{kind: tokPunct, text: string(c)})
			i++
		}
	}
	return toks
}

// gqlSelection is one top-level selection: a field name, a named fragment
// spread, or an inline fragment's own selections.
type gqlSelection struct {
	field  string
	spread string
	inline []gqlSelection
}

type gqlParser struct {
	toks []gqlToken
	pos  int
}

func (p *gqlParser) peek(offset int) gqlToken {
	if p.pos+offset < len(p.toks) {
		return p.toks[p.pos+offset]
	}
	return gqlToken{}
}

func (p *gqlParser) isPunct(text string) bool {
	t := p.peek(0)
	return t.kind == tokPunct && t.text == text
}

func (p *gqlParser) done() bool { return p.pos >= len(p.toks) }

// parseDocument returns named fragment selections and the top-level
// selections of each mutation operation.
func (p *gqlParser) parseDocument() (map[string][]gqlSelection, [][]gqlSelection) {
	fragments := map[string][]gqlSelection{}
	var mutations [][]gqlSelection
	for !p.done() {
		t := p.peek(0)
		switch {
		case t.kind == tokPunct && t.text == "{":
			p.parseSelectionSet()
		case t.kind == tokName && (t.text == "query" || t.text == "mutation" || t.text == "subscription"):
			p.pos++
			if p.peek(0).kind == tokName {
				p.pos++
			}
			p.skipBalanced("(", ")")
			p.skipDirectives()
			if !p.isPunct("{") {
				continue
			}
			sels := p.parseSelectionSet()
			if t.text == "mutation" {
				mutations = append(mutations, sels)
			}
		case t.kind == tokName && t.text == "fragment":
			p.pos++
			name := p.peek(0).text
			p.pos++
			if p.peek(0).kind == tokName && p.peek(0).text == "on" {
				p.pos += 2
			}
			p.skipDirectives()
			if p.isPunct("{") {
				fragments[name] = p.parseSelectionSet()
			}
		default:
			p.pos++
		}
	}
	return fragments, mutations
}

// parseSelectionSet consumes a `{ ... }` block and returns its top-level
// selections. Nested sub-selections are skipped.
func (p *gqlParser) parseSelectionSet() []gqlSelection {
	var sels []gqlSelection
	p.pos++ // "{"
	for !p.done() && !p.isPunct("}") {
		t := p.peek(0)
		switch t.kind {
		case tokSpread:
			p.pos++
			next := p.peek(0)
			if next.kind == tokName && next.text != "on" {
				p.pos++
				p.skipDirectives()
				sels = append(sels, gqlSelection{spread: next.text})
				continue
			}
			if next.kind == tokName && next.text == "on" {
				p.pos += 2
			}
			p.skipDirectives()
			if p.isPunct("{") {
				sels = append(sels, gqlSelection{inline: p.parseSelectionSet()})
			}
		case tokName:
			name := t.text
			p.pos++
			if p.isPunct(":") && p.peek(1).kind == tokName {
				name = p.peek(1).text
				p.pos += 2
			}
			p.skipBalanced("(", ")")
			p.skipDirectives()
			p.skipBalanced("{", "}")
			sels = append(sels, gqlSelection{field: name})
		default:
			p.pos++
		}
	}
	p.pos++ // "}"
	return sels
}

func (p *gqlParser) skipDirectives() {
	for p.isPunct("@") {
		p.pos++
		if p.peek(0).kind == tokName {
			p.pos++
		}
		p.skipBalanced("(", ")")
	}
}

// skipBalanced consumes a balanced open/close group when the next token is
// open; otherwise it does nothing.
func (p *gqlParser) skipBalanced(open, closer string) {
	if !p.isPunct(open) {
		return
	}
	depth := 0
	for !p.done() {
		t := p.peek(0)
		p.pos++
		if t.kind != tokPunct {
			continue
		}
		switch t.text {
		case open:
			depth++
		case closer:
			depth--
			if depth == 0 {
				return
			}
		}
	}
}
