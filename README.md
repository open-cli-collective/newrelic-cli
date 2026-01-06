# newrelic-cli

A command-line interface for New Relic.

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap piekstra/tap
brew install newrelic-cli
```

### From Source

```bash
go install github.com/piekstra/newrelic-cli@latest
```

### Binary Downloads

Download pre-built binaries from the [Releases](https://github.com/piekstra/newrelic-cli/releases) page.

## Configuration

### Set API Key (Recommended)

```bash
# Store securely in macOS Keychain (or config file on Linux)
newrelic-cli config set-api-key
```

### Set Account ID

```bash
newrelic-cli config set-account-id 12345678
```

### Set Region (Optional)

```bash
# US (default) or EU
newrelic-cli config set-region EU
```

### Environment Variables (Alternative)

```bash
export NEWRELIC_API_KEY="NRAK-..."
export NEWRELIC_ACCOUNT_ID="12345678"
export NEWRELIC_REGION="US"  # or "EU"
```

### View Configuration

```bash
newrelic-cli config show
```

## Usage

### Applications

```bash
# List all APM applications
newrelic-cli apps list

# Get application details
newrelic-cli apps get <app-id>

# List metrics for an application
newrelic-cli apps metrics <app-id>
```

### NRQL Queries

```bash
# Execute an NRQL query
newrelic-cli nrql "SELECT count(*) FROM Transaction SINCE 1 day ago"

# Output as JSON
newrelic-cli nrql --json "SELECT average(duration) FROM Transaction FACET appName"
```

### Dashboards

```bash
# List all dashboards
newrelic-cli dashboards list

# Get dashboard details
newrelic-cli dashboards get <guid>
```

### Alert Policies

```bash
# List all policies
newrelic-cli alerts policies list

# Get policy details
newrelic-cli alerts policies get <policy-id>
```

### Users

```bash
# List all users
newrelic-cli users list

# Get user details
newrelic-cli users get <user-id>
```

### Entities

```bash
# Search for entities
newrelic-cli entities search "type = 'APPLICATION'"
newrelic-cli entities search "name LIKE 'production%'"
```

### Synthetic Monitors

```bash
# List all monitors
newrelic-cli synthetics list

# Get monitor details
newrelic-cli synthetics get <monitor-id>
```

### Deployments

```bash
# List deployments for an app
newrelic-cli deployments list <app-id>

# Record a deployment
newrelic-cli deployments create <app-id> --revision v1.2.3 --description "Bug fixes"
```

### Log Parsing Rules

```bash
# List all rules
newrelic-cli logs rules list

# Create a rule
newrelic-cli logs rules create \
  --description "Parse user events" \
  --grok "User %{UUID:user_id} logged in" \
  --nrql "SELECT * FROM Log WHERE message LIKE 'User % logged in'"

# Delete a rule
newrelic-cli logs rules delete <rule-id>
```

### NerdGraph (GraphQL)

```bash
# Execute a GraphQL query
newrelic-cli nerdgraph query '{ actor { user { name email } } }'

# From a file
newrelic-cli nerdgraph query --file query.graphql

# With variables
newrelic-cli nerdgraph query --file query.graphql --variables '{"id": 123}'
```

## Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |
| `--help` | Show help for a command |
| `--version` | Show version |

## Credential Storage

- **macOS**: Credentials are stored securely in the system Keychain
- **Linux**: Credentials are stored in `~/.config/newrelic-cli/credentials` with restricted permissions (0600)

## License

MIT License - see [LICENSE](LICENSE) for details.
