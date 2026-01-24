# Contributing to newrelic-cli

Thank you for your interest in contributing to newrelic-cli! This guide will help you get started.

## Development Setup

### Prerequisites

- Go 1.21 or later
- Make
- golangci-lint (optional, for linting)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/open-cli-collective/newrelic-cli.git
cd newrelic-cli

# Build
make build

# Run tests
make test

# Install locally
make install
```

### Verify Installation

```bash
./nrq --version
```

## Code Style

### Formatting

All Go code must be formatted with `gofmt`. Run before committing:

```bash
make fmt
```

### Linting

We use golangci-lint for static analysis:

```bash
make lint
```

### Naming Conventions

- **Packages**: lowercase, short, no underscores (`apps`, `alerts`, `configcmd`)
- **Files**: lowercase with underscores (`log_rules.go`, `client_test.go`)
- **Types**: PascalCase (`AlertPolicy`, `ClientConfig`)
- **Functions**: PascalCase for exported, camelCase for internal
- **Variables**: camelCase (`apiKey`, `accountID`)
- **Constants**: PascalCase for exported (`RegionUS`), camelCase for internal

### Code Organization

```
internal/cmd/<resource>/
├── <resource>.go      # Register function, parent command
├── list.go            # list subcommand
├── get.go             # get subcommand
└── <resource>_test.go # Tests
```

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes nor adds |
| `test` | Adding or correcting tests |
| `chore` | Maintenance tasks |

### Scopes

Use the affected area: `apps`, `alerts`, `api`, `config`, `view`, `readme`, etc.

### Examples

```bash
feat(alerts): add conditions list command
fix(nrql): handle empty result sets gracefully
docs(readme): add scripting examples section
refactor(api): extract dashboard methods to separate file
test(apps): add unit tests for metrics command
chore(deps): update cobra to v1.8.0
```

## Pull Request Process

### 1. Create a Branch

```bash
git checkout main
git pull origin main
git checkout -b type/description
```

Branch naming:
- `feat/add-alerts-conditions`
- `fix/nrql-timeout`
- `docs/update-readme`
- `refactor/extract-api`

### 2. Make Changes

- Write code following the style guidelines
- Add tests for new functionality
- Update documentation if needed

### 3. Run Checks

```bash
# Format, lint, and test
make verify
```

### 4. Commit and Push

```bash
git add .
git commit -m "type(scope): description"
git push -u origin your-branch
```

### 5. Create Pull Request

- Target the `main` branch
- Fill out the PR template
- Request review from maintainers

## Project Structure

```
newrelic-cli/
├── cmd/nrq/                   # Entry point
│   └── main.go
├── api/                        # Public Go library
│   ├── client.go              # HTTP client, New(), NewWithConfig()
│   ├── types.go               # Data types
│   ├── errors.go              # Error types
│   └── *.go                   # Domain-specific methods
├── internal/
│   ├── cmd/                   # Cobra commands
│   │   ├── root/              # Root command, global options
│   │   ├── apps/              # apps commands
│   │   ├── alerts/            # alerts commands
│   │   └── ...
│   ├── config/                # Credential storage
│   ├── version/               # Version info
│   └── view/                  # Output formatting
├── docs/                       # Additional documentation
├── Makefile                   # Build targets
├── go.mod                     # Module definition
└── go.sum                     # Dependency checksums
```

## Adding New Commands

### Step 1: Create Command Package

Create a new directory in `internal/cmd/`:

```bash
mkdir internal/cmd/newcommand
```

### Step 2: Create Register Function

`internal/cmd/newcommand/newcommand.go`:

```go
package newcommand

import (
    "github.com/spf13/cobra"
    "github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
)

func Register(rootCmd *cobra.Command, opts *root.Options) {
    cmd := &cobra.Command{
        Use:   "newcommand",
        Short: "Description of the command",
    }

    cmd.AddCommand(newListCmd(opts))
    rootCmd.AddCommand(cmd)
}
```

### Step 3: Create Subcommands

`internal/cmd/newcommand/list.go`:

```go
package newcommand

import (
    "github.com/spf13/cobra"
    "github.com/open-cli-collective/newrelic-cli/api"
    "github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
)

func newListCmd(opts *root.Options) *cobra.Command {
    return &cobra.Command{
        Use:   "list",
        Short: "List items",
        RunE: func(cmd *cobra.Command, args []string) error {
            return runList(opts)
        },
    }
}

func runList(opts *root.Options) error {
    client, err := api.New()
    if err != nil {
        return err
    }

    // Call API
    items, err := client.ListItems()
    if err != nil {
        return err
    }

    // Format output
    v := opts.View()
    headers := []string{"ID", "NAME"}
    rows := make([][]string, len(items))
    for i, item := range items {
        rows[i] = []string{item.ID, item.Name}
    }

    return v.Render(headers, rows, items)
}
```

### Step 4: Register in main.go

`cmd/nrq/main.go`:

```go
import (
    // ...
    "github.com/open-cli-collective/newrelic-cli/internal/cmd/newcommand"
)

func main() {
    root.RegisterCommands(
        // ...existing...
        newcommand.Register,
    )
    // ...
}
```

### Step 5: Add API Methods (if needed)

`api/newcommand.go`:

```go
package api

func (c *Client) ListItems() ([]Item, error) {
    // Implementation
}
```

`api/types.go`:

```go
type Item struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}
```

### Step 6: Write Tests

`internal/cmd/newcommand/newcommand_test.go`:

```go
package newcommand

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestListCommand(t *testing.T) {
    // Test implementation
}
```

## Testing

### Running Tests

```bash
# All tests
make test

# With coverage
make test-cover

# Specific package
go test ./internal/cmd/apps/...
```

### Writing Tests

Use table-driven tests with `testify/assert`:

```go
func TestFunction(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid input",
            input:    "test",
            expected: "result",
            wantErr:  false,
        },
        {
            name:    "empty input",
            input:   "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := Function(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

## Questions?

If you have questions about contributing, please open an issue or reach out to the maintainers.
