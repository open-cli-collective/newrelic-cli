# CLAUDE.md

This file provides guidance for AI agents working with the newrelic-cli codebase.

## Project Overview

newrelic-cli is a command-line interface for New Relic written in Go. It uses the Cobra framework for commands and provides a public `api/` package that can be imported as a Go library. The CLI supports multiple output formats (table, JSON, plain) and stores credentials securely via macOS Keychain or Linux config files.

## Quick Commands

```bash
# Build
make build

# Run tests
make test

# Run tests with coverage
make test-cover

# Lint
make lint

# Format code
make fmt

# All checks (format, lint, test)
make verify

# Install locally
make install

# Clean build artifacts
make clean
```

## Architecture

```
newrelic-cli/
├── cmd/newrelic-cli/main.go    # Entry point - registers commands, calls Execute()
├── api/                         # Public Go library (importable)
│   ├── client.go               # Client struct, New(), NewWithConfig(), HTTP helpers
│   ├── types.go                # All data types (Application, AlertPolicy, etc.)
│   ├── errors.go               # Error types: APIError, ErrNotFound, ErrUnauthorized
│   ├── applications.go         # ListApplications, GetApplication, ListApplicationMetrics
│   ├── alerts.go               # ListAlertPolicies, GetAlertPolicy
│   ├── dashboards.go           # ListDashboards, GetDashboard
│   ├── deployments.go          # ListDeployments, CreateDeployment
│   ├── entities.go             # SearchEntities
│   ├── logs.go                 # ListLogParsingRules, CreateLogParsingRule, DeleteLogParsingRule
│   ├── nrql.go                 # QueryNRQL
│   ├── synthetics.go           # ListSyntheticMonitors, GetSyntheticMonitor
│   └── users.go                # ListUsers, GetUser
├── internal/
│   ├── cmd/                    # Cobra commands (one package per resource)
│   │   ├── root/root.go        # Root command, Options struct, global flags
│   │   ├── apps/               # apps list, get, metrics
│   │   ├── alerts/             # alerts policies list, get
│   │   ├── configcmd/          # config set-api-key, set-account-id, etc.
│   │   ├── dashboards/         # dashboards list, get
│   │   ├── deployments/        # deployments list, create
│   │   ├── entities/           # entities search
│   │   ├── logs/               # logs rules list, create, delete
│   │   ├── nerdgraph/          # nerdgraph query
│   │   ├── nrql/               # nrql query
│   │   ├── synthetics/         # synthetics list, get
│   │   └── users/              # users list, get
│   ├── config/config.go        # Credential storage (Keychain/file)
│   ├── version/version.go      # Build-time version injection via ldflags
│   └── view/view.go            # Output formatting (table, JSON, plain)
├── Makefile                    # Build, test, lint targets
└── go.mod                      # Module: github.com/open-cli-collective/newrelic-cli
```

## Key Patterns

### Options Struct Pattern

Commands use an Options struct for dependency injection:

```go
// Root options (global flags)
type Options struct {
    Output  string    // table, json, plain
    NoColor bool
    Stdin   io.Reader
    Stdout  io.Writer
    Stderr  io.Writer
}

// Command-specific options embed root options
type createOptions struct {
    *root.Options
    revision    string
    description string
}
```

### Register Pattern

Each command package exports a Register function:

```go
func Register(rootCmd *cobra.Command, opts *root.Options) {
    cmd := &cobra.Command{
        Use:   "apps",
        Short: "Manage APM applications",
    }
    cmd.AddCommand(newListCmd(opts))
    cmd.AddCommand(newGetCmd(opts))
    rootCmd.AddCommand(cmd)
}
```

### View Pattern

Use the View struct for formatted output:

```go
v := opts.View()

// Table output (default)
headers := []string{"ID", "NAME", "STATUS"}
rows := [][]string{{"123", "app", "green"}}
v.Render(headers, rows, data)

// JSON output
v.JSON(data)

// Plain output (tab-separated, no headers)
v.Plain(rows)

// Messages
v.Success("Created successfully")
v.Warning("Deprecated flag")
v.Error("Failed: %v", err)
```

### Safe Type Assertions

NerdGraph returns `map[string]interface{}`. Use safe helpers:

```go
// Safe extraction from interface{}
name := safeString(data["name"])        // Returns "" if not string
count := safeInt(data["count"])         // Returns 0 if not float64
nested, ok := safeMap(data["nested"])   // Returns map and bool
items, ok := safeSlice(data["items"])   // Returns slice and bool
```

### API Client Initialization

```go
// From environment/config (recommended)
client, err := api.New()

// With explicit config
client := api.NewWithConfig(api.ClientConfig{
    APIKey:    "NRAK-xxx",
    AccountID: "12345",
    Region:    "US",
})
```

### Domain Types

The API package uses dedicated types for New Relic identifiers to provide type safety and self-documenting code:

| Type | Purpose | Key Methods |
|------|---------|-------------|
| `EntityGUID` | Entity identifiers (base64 encoded) | `Parse()`, `AppID()`, `Validate()` |
| `APIKey` | User API keys (NRAK- prefix) | `Validate()`, `HasNRAKPrefix()` |
| `AccountID` | Account identifiers (numeric) | `Int()`, `Validate()`, `IsEmpty()` |

Use constructors (`NewAPIKey`, `NewAccountID`) for validation at boundaries (user input, config loading). Type fields in structs are already validated.

```go
// At boundaries - validate on creation
key, warning, err := api.NewAPIKey(userInput)
accountID, err := api.NewAccountID(configValue)

// In structs - types provide documentation and safety
type Client struct {
    APIKey    APIKey     // Not just "string"
    AccountID AccountID  // Not just "string"
}
```

## Testing Philosophy

- Unit tests in `*_test.go` files alongside source
- Use `testify/assert` for assertions
- Table-driven tests for multiple scenarios
- Injectable clients for command testing (via Options struct)

Example test structure:

```go
func TestSomething(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"case 1", "input1", "output1"},
        {"case 2", "input2", "output2"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Something(tt.input)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

## Workflows

### Branch Naming

```
type/description
```

Examples:
- `feat/add-alerts-conditions`
- `fix/nrql-timeout`
- `refactor/extract-api-package`
- `docs/update-readme`

### Commit Messages

Use conventional commits:

```
type(scope): description

feat(alerts): add conditions list command
fix(nrql): increase timeout for long queries
docs(readme): add scripting examples
refactor(api): extract NerdGraph client
test(apps): add unit tests for list command
chore(deps): update cobra to v1.8.0
```

| Prefix | Purpose | Triggers Release? |
|--------|---------|-------------------|
| `feat:` | New features | Yes |
| `fix:` | Bug fixes | Yes |
| `docs:` | Documentation only | No |
| `test:` | Adding/updating tests | No |
| `refactor:` | Code changes that don't fix bugs or add features | No |
| `chore:` | Maintenance tasks | No |
| `ci:` | CI/CD changes | No |

### Pull Request Process

1. Create feature branch from `main`
2. Make changes with tests
3. Run `make verify`
4. Push and create PR targeting `main`
5. Add reviewer

## CI & Release Workflow

Releases are automated with a dual-gate system to avoid unnecessary releases:

**Gate 1 - Path filter:** Only triggers when Go code changes (`**.go`, `go.mod`, `go.sum`)
**Gate 2 - Commit prefix:** Only `feat:` and `fix:` commits create releases

This means:
- `feat: add command` + Go files changed → release
- `fix: handle edge case` + Go files changed → release
- `docs:`, `ci:`, `test:`, `refactor:` → no release
- Changes only to docs, packaging, workflows → no release

**After merging a release-triggering PR:** The workflow creates a tag, which triggers GoReleaser to build binaries and publish to Homebrew. Chocolatey and Winget require manual workflow dispatch.

## Common Tasks

### Adding a New Command

1. Create package in `internal/cmd/<name>/`
2. Create `<name>.go` with Register function
3. Create subcommand files (`list.go`, `get.go`, etc.)
4. Add Register call to `cmd/newrelic-cli/main.go`
5. Add API methods to `api/` if needed
6. Write tests

### Adding an API Method

1. Add type definitions to `api/types.go`
2. Add method to appropriate domain file (`api/applications.go`, etc.)
3. Use `doRequest()` for REST or `NerdGraphQuery()` for GraphQL
4. Handle errors with `APIError` or return `ErrNotFound`

### Changing Output Format

The View struct handles all output formatting. To add a new format:

1. Update `internal/view/view.go`
2. Add format constant and case in `Render()`
3. Update `ValidateFormat()`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NEWRELIC_API_KEY` | User API key (NRAK-xxx) |
| `NEWRELIC_ACCOUNT_ID` | Account ID |
| `NEWRELIC_REGION` | US or EU |

## Dependencies

Key dependencies:
- `github.com/spf13/cobra` - CLI framework
- `github.com/fatih/color` - Colored terminal output
- `github.com/stretchr/testify` - Testing assertions
