# newrelic-cli

A command-line interface for interacting with New Relic APIs.

## Features

- **APM Applications**: List applications, view details, and retrieve available metrics
- **Alert Policies**: List and inspect alert policy configurations
- **Dashboards**: List and view dashboard details
- **Deployments**: Track deployment markers for applications
- **Entities**: Search across all New Relic entity types
- **Log Parsing Rules**: Create, list, and delete log parsing rules
- **NerdGraph**: Execute arbitrary GraphQL queries
- **NRQL**: Run NRQL queries directly from the command line
- **Synthetic Monitors**: List and inspect synthetic monitoring configurations
- **Users**: List and view user details
- **Multiple Output Formats**: Table, JSON, and plain (scriptable) output
- **Secure Credential Storage**: macOS Keychain or encrypted config file

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap piekstra/tap
brew install newrelic-cli
```

### Go Install

```bash
go install github.com/piekstra/newrelic-cli/cmd/newrelic-cli@latest
```

### Binary Downloads

Download pre-built binaries from the [Releases](https://github.com/piekstra/newrelic-cli/releases) page.

## Quick Start

```bash
# 1. Configure your API key (stored securely)
newrelic-cli config set-api-key

# 2. Set your account ID
newrelic-cli config set-account-id 12345678

# 3. Verify configuration
newrelic-cli config show

# 4. Start using the CLI
newrelic-cli apps list
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NEWRELIC_API_KEY` | Your New Relic User API key (starts with `NRAK-`) | Yes |
| `NEWRELIC_ACCOUNT_ID` | Your New Relic account ID | Yes (for most commands) |
| `NEWRELIC_REGION` | API region: `US` (default) or `EU` | No |

### CLI Configuration Commands

```bash
# Set API key (interactive prompt)
newrelic-cli config set-api-key

# Set API key (inline)
newrelic-cli config set-api-key NRAK-xxxxxxxxxxxxxxxxxxxx

# Set account ID
newrelic-cli config set-account-id 12345678

# Set region (US or EU)
newrelic-cli config set-region EU

# View current configuration
newrelic-cli config show

# Delete stored credentials
newrelic-cli config delete-api-key
newrelic-cli config delete-account-id
```

### Credential Storage

| Platform | Storage Method | Location |
|----------|----------------|----------|
| macOS | System Keychain | Secure keychain storage |
| Linux | Config file | `~/.config/newrelic-cli/credentials` (0600 permissions) |

### Configuration Precedence

1. Environment variables (highest priority)
2. Stored credentials (CLI config)
3. Default values (lowest priority)

---

## Command Reference

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `table` | Output format: `table`, `json`, or `plain` |
| `--no-color` | | `false` | Disable colored output |
| `--help` | `-h` | | Show help for any command |
| `--version` | | | Show version information |

---

### apps

Manage APM applications.

#### apps list

List all APM applications in your account.

```bash
newrelic-cli apps list
newrelic-cli apps list -o json
newrelic-cli apps list -o plain
```

**Table Output:**
```
ID          NAME                        LANGUAGE    STATUS
12345678    production-api              ruby        green
23456789    staging-api                 ruby        gray
34567890    frontend-service            nodejs      green
```

#### apps get

Get details for a specific application.

```bash
newrelic-cli apps get <app-id>
newrelic-cli apps get 12345678
newrelic-cli apps get 12345678 -o json
```

**Table Output:**
```
ID:              12345678
Name:            production-api
Language:        ruby
Health Status:   green
Reporting:       true
Last Reported:   2024-01-15T10:30:00Z
```

#### apps metrics

List available metrics for an application.

```bash
newrelic-cli apps metrics <app-id>
newrelic-cli apps metrics 12345678
```

---

### alerts policies

Manage alert policies.

#### alerts policies list

List all alert policies.

```bash
newrelic-cli alerts policies list
newrelic-cli alerts policies list -o json
```

**Table Output:**
```
ID          NAME                            INCIDENT PREFERENCE
12345       Production Alerts               PER_POLICY
23456       Staging Alerts                  PER_CONDITION
```

#### alerts policies get

Get details for a specific alert policy.

```bash
newrelic-cli alerts policies get <policy-id>
newrelic-cli alerts policies get 12345
```

---

### dashboards

Manage dashboards.

#### dashboards list

List all dashboards.

```bash
newrelic-cli dashboards list
newrelic-cli dashboards list -o json
```

**Table Output:**
```
GUID                                    NAME                        PAGES
ABC123...                               Production Overview         3
DEF456...                               API Performance             2
```

#### dashboards get

Get details for a specific dashboard.

```bash
newrelic-cli dashboards get <guid>
newrelic-cli dashboards get "ABC123..."
```

---

### deployments

Manage deployment markers.

**Aliases:** `deployment`, `deploy`

#### deployments list

List deployments for an application.

```bash
newrelic-cli deployments list <app-id>
newrelic-cli deployments list 12345678
```

**Table Output:**
```
ID          REVISION        DESCRIPTION             USER            TIMESTAMP
9876        v1.2.3          Bug fixes               alice           2024-01-15T10:30:00Z
9875        v1.2.2          Feature release         bob             2024-01-14T15:00:00Z
```

#### deployments create

Create a deployment marker.

```bash
newrelic-cli deployments create <app-id> --revision <rev> [flags]
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--revision` | `-r` | Yes | Deployment revision/version |
| `--description` | `-d` | No | Deployment description |
| `--user` | `-u` | No | User who deployed |
| `--changelog` | `-c` | No | Changelog information |

**Examples:**
```bash
# Minimal
newrelic-cli deployments create 12345678 --revision v1.2.3

# Full
newrelic-cli deployments create 12345678 \
  --revision v1.2.3 \
  --description "Bug fixes and performance improvements" \
  --user "alice" \
  --changelog "Fixed memory leak, improved cache hit rate"
```

---

### entities

Search and manage New Relic entities.

**Aliases:** `entity`, `ent`

#### entities search

Search for entities using NRQL-style queries.

```bash
newrelic-cli entities search <query>
```

**Examples:**
```bash
# Find all applications
newrelic-cli entities search "type = 'APPLICATION'"

# Find by name pattern
newrelic-cli entities search "name LIKE 'production%'"

# Find by domain
newrelic-cli entities search "domain = 'APM'"

# Combined conditions
newrelic-cli entities search "type = 'APPLICATION' AND name LIKE 'prod%'"
```

**Table Output:**
```
GUID                                    NAME                    TYPE            DOMAIN      ACCOUNT ID
ABC123...                               production-api          APPLICATION     APM         12345678
DEF456...                               production-web          APPLICATION     APM         12345678
```

---

### logs rules

Manage log parsing rules.

#### logs rules list

List all log parsing rules.

```bash
newrelic-cli logs rules list
newrelic-cli logs rules list -o json
```

**Table Output:**
```
ID                                      DESCRIPTION                     ENABLED     UPDATED
abc-123...                              Parse user login events         true        2024-01-15T10:00:00Z
def-456...                              Extract error codes             false       2024-01-10T08:00:00Z
```

#### logs rules create

Create a log parsing rule.

```bash
newrelic-cli logs rules create [flags]
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--description` | `-d` | Yes | Rule description |
| `--grok` | `-g` | Yes | GROK pattern for parsing |
| `--nrql` | `-n` | Yes | NRQL matching condition |
| `--enabled` | `-e` | No | Enable the rule (default: true) |
| `--lucene` | `-l` | No | Lucene filter expression |

**Example:**
```bash
newrelic-cli logs rules create \
  --description "Parse user login events" \
  --grok "User %{UUID:user_id} logged in from %{IP:ip_address}" \
  --nrql "SELECT * FROM Log WHERE message LIKE 'User % logged in%'" \
  --enabled true
```

#### logs rules delete

Delete a log parsing rule.

```bash
newrelic-cli logs rules delete <rule-id>
newrelic-cli logs rules delete abc-123-def-456
```

---

### nerdgraph

Execute NerdGraph GraphQL queries.

**Aliases:** `ng`, `graphql`

#### nerdgraph query

Execute a GraphQL query against the NerdGraph API.

```bash
newrelic-cli nerdgraph query <graphql-query>
```

**Examples:**
```bash
# Get current user info
newrelic-cli nerdgraph query '{ actor { user { email name } } }'

# List accounts
newrelic-cli nerdgraph query '{ actor { accounts { id name } } }'

# Complex query
newrelic-cli nerdgraph query '{
  actor {
    account(id: 12345678) {
      name
      nrql(query: "SELECT count(*) FROM Transaction") {
        results
      }
    }
  }
}'
```

---

### nrql

Execute NRQL queries.

#### nrql query

Execute an NRQL query against your account.

```bash
newrelic-cli nrql query <nrql-query>
```

**Examples:**
```bash
# Transaction count
newrelic-cli nrql query "SELECT count(*) FROM Transaction SINCE 1 hour ago"

# Average response time by app
newrelic-cli nrql query "SELECT average(duration) FROM Transaction FACET appName SINCE 1 day ago"

# Error rate
newrelic-cli nrql query "SELECT percentage(count(*), WHERE error IS true) FROM Transaction SINCE 1 hour ago"

# Top slow transactions
newrelic-cli nrql query "SELECT average(duration), count(*) FROM Transaction FACET name SINCE 1 hour ago LIMIT 10"
```

---

### synthetics

Manage synthetic monitors.

#### synthetics list

List all synthetic monitors.

```bash
newrelic-cli synthetics list
newrelic-cli synthetics list -o json
```

**Table Output:**
```
ID                                      NAME                    TYPE            STATUS      FREQUENCY
abc-123...                              Production Health       SIMPLE          ENABLED     5
def-456...                              API Endpoint Check      API             ENABLED     1
```

#### synthetics get

Get details for a specific synthetic monitor.

```bash
newrelic-cli synthetics get <monitor-id>
newrelic-cli synthetics get abc-123-def-456
```

---

### users

Manage users.

#### users list

List all users in your account.

```bash
newrelic-cli users list
newrelic-cli users list -o json
```

**Table Output:**
```
ID          NAME                EMAIL                       ROLE
12345       Alice Smith         alice@example.com           admin
23456       Bob Jones           bob@example.com             user
```

#### users get

Get details for a specific user.

```bash
newrelic-cli users get <user-id>
newrelic-cli users get 12345
```

---

### config

Configure newrelic-cli credentials.

#### config set-api-key

Set the New Relic API key.

```bash
# Interactive (recommended)
newrelic-cli config set-api-key

# Inline (less secure - visible in shell history)
newrelic-cli config set-api-key NRAK-xxxxxxxxxxxxxxxxxxxx
```

#### config set-account-id

Set the New Relic account ID.

```bash
newrelic-cli config set-account-id 12345678
```

#### config set-region

Set the New Relic region.

```bash
newrelic-cli config set-region US   # Default
newrelic-cli config set-region EU   # European datacenter
```

#### config show

Show current configuration status.

```bash
newrelic-cli config show
```

**Output:**
```
Configuration Status:

  API Key:    NRAK-xx...xxxx (stored)
  Account ID: 12345678 (environment)
  Region:     US (default)

Storage: macOS Keychain (secure)
```

#### config delete-api-key

Delete the stored API key.

```bash
newrelic-cli config delete-api-key
```

#### config delete-account-id

Delete the stored account ID.

```bash
newrelic-cli config delete-account-id
```

---

## Output Formats

### Table (default)

Human-readable tabular format with headers and aligned columns.

```bash
newrelic-cli apps list
newrelic-cli apps list -o table
```

### JSON

Machine-readable JSON output for programmatic use.

```bash
newrelic-cli apps list -o json
```

### Plain

Tab-separated values without headers, ideal for shell scripting.

```bash
newrelic-cli apps list -o plain
```

---

## Scripting Examples

### Extract Application IDs

```bash
# Get all app IDs
newrelic-cli apps list -o plain | cut -f1

# Get app ID by name
newrelic-cli apps list -o json | jq -r '.[] | select(.name == "production-api") | .id'
```

### Create Deployments from Git

```bash
# Deploy with git info
newrelic-cli deployments create $APP_ID \
  --revision "$(git rev-parse --short HEAD)" \
  --description "$(git log -1 --pretty=%B)" \
  --user "$(git config user.name)"
```

### Monitor Health Status

```bash
# Check for unhealthy apps
newrelic-cli apps list -o json | jq -r '.[] | select(.health_status != "green") | .name'
```

### Batch Operations

```bash
# Record deployment for all production apps
newrelic-cli apps list -o json | \
  jq -r '.[] | select(.name | startswith("prod")) | .id' | \
  xargs -I {} newrelic-cli deployments create {} --revision v1.0.0
```

### NRQL in Scripts

```bash
# Get error count as a number
ERROR_COUNT=$(newrelic-cli nrql query "SELECT count(*) FROM TransactionError SINCE 1 hour ago" | jq '.results[0].count')
echo "Errors in last hour: $ERROR_COUNT"
```

---

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error (API error, invalid arguments, etc.) |

---

## Go Library Usage

The `api` package can be imported and used as a Go library:

```go
package main

import (
    "fmt"
    "log"

    "github.com/piekstra/newrelic-cli/api"
)

func main() {
    // Create client from environment variables
    client, err := api.New()
    if err != nil {
        log.Fatal(err)
    }

    // Or with explicit configuration
    client = api.NewWithConfig(api.ClientConfig{
        APIKey:    "NRAK-xxxxxxxxxxxxxxxxxxxx",
        AccountID: "12345678",
        Region:    "US",
    })

    // List applications
    apps, err := client.ListApplications()
    if err != nil {
        log.Fatal(err)
    }

    for _, app := range apps {
        fmt.Printf("%d: %s (%s)\n", app.ID, app.Name, app.HealthStatus)
    }

    // Execute NRQL query
    result, err := client.QueryNRQL("SELECT count(*) FROM Transaction SINCE 1 hour ago")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Results: %+v\n", result)

    // Execute GraphQL query
    response, err := client.NerdGraphQuery(`{ actor { user { email } } }`, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Response: %+v\n", response)
}
```

### Available API Methods

| Method | Description |
|--------|-------------|
| `ListApplications()` | List all APM applications |
| `GetApplication(id)` | Get application details |
| `ListApplicationMetrics(id)` | List available metrics |
| `ListAlertPolicies()` | List alert policies |
| `GetAlertPolicy(id)` | Get policy details |
| `ListDashboards()` | List dashboards |
| `GetDashboard(guid)` | Get dashboard details |
| `ListDeployments(appID)` | List deployments |
| `CreateDeployment(...)` | Create deployment marker |
| `SearchEntities(query)` | Search entities |
| `ListLogParsingRules()` | List log parsing rules |
| `CreateLogParsingRule(...)` | Create parsing rule |
| `DeleteLogParsingRule(id)` | Delete parsing rule |
| `QueryNRQL(query)` | Execute NRQL query |
| `NerdGraphQuery(query, vars)` | Execute GraphQL query |
| `ListSyntheticMonitors()` | List synthetic monitors |
| `GetSyntheticMonitor(id)` | Get monitor details |
| `ListUsers()` | List users |
| `GetUser(id)` | Get user details |

### Entity GUIDs

**Important**: New Relic Entity GUIDs are **NOT** standard UUIDs. They are base64-encoded, pipe-delimited strings with a specific structure:

```
base64(version|domain|type|id)
```

| Encoded GUID | Decoded |
|--------------|---------|
| `MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=` | `1\|APM\|APPLICATION\|12345678` |
| `MXxWSVp8REFTSEJPQVJEfDEyMzQ1` | `1\|VIZ\|DASHBOARD\|12345` |

The `EntityGUID` type provides methods for working with these identifiers:

```go
guid := api.EntityGUID("MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=")

// Parse components
version, domain, entityType, entityID, err := guid.Parse()

// Get specific components
domain, err := guid.Domain()      // "APM"
entityType, err := guid.EntityType() // "APPLICATION"
entityID, err := guid.EntityID()  // "12345678"

// For APM applications, extract the app ID
appID, err := guid.AppID()        // "12345678"

// Validate format
if err := guid.Validate(); err != nil {
    log.Printf("Invalid GUID: %v", err)
}

// Check if a string looks like a GUID
if api.IsValidEntityGUID(identifier) {
    // Likely a GUID, not a name or numeric ID
}
```

Methods using Entity GUIDs:
- `GetDashboard(guid)` - Takes an EntityGUID
- `SearchEntities(query)` - Returns entities with GUIDs

Methods using numeric IDs:
- `GetApplication(id)` - Takes an integer ID
- `GetAlertPolicy(id)` - Takes an integer ID
- `GetUser(id)` - Takes a string ID

### APIKey Type

The `APIKey` type provides type-safe handling of New Relic User API keys:

```go
// Create and validate an API key
key, warning, err := api.NewAPIKey("NRAK-ABCDEFGHIJ1234567890")
if err != nil {
    log.Fatal(err)
}
if warning != "" {
    log.Printf("Warning: %s", warning)  // Non-NRAK prefix warning
}

// Validate an existing key
warning, err = key.Validate()

// Check prefix
if key.HasNRAKPrefix() {
    // Standard User API key
}
```

Valid User API keys start with `NRAK-` and are typically 40+ characters. Keys without the `NRAK-` prefix will validate successfully but return a warning.

### Error Handling

The API package provides structured error types and helper functions:

**Error Types:**

```go
// APIError - HTTP API errors
var apiErr *api.APIError
if errors.As(err, &apiErr) {
    fmt.Printf("HTTP %d: %s\n", apiErr.StatusCode, apiErr.Message)
}

// GraphQLError - NerdGraph query errors
var gqlErr *api.GraphQLError
if errors.As(err, &gqlErr) {
    fmt.Printf("GraphQL error: %s\n", gqlErr.Message)
}

// ResponseError - Response parsing errors
var respErr *api.ResponseError
if errors.As(err, &respErr) {
    fmt.Printf("Parse error: %s\n", respErr.Message)
}
```

**Sentinel Errors:**

```go
api.ErrNotFound          // Resource not found (404)
api.ErrUnauthorized      // Invalid or missing API key (401)
api.ErrAPIKeyRequired    // API key not configured
api.ErrAccountIDRequired // Account ID not configured
```

**Helper Functions:**

```go
// Check for specific error conditions
if api.IsNotFound(err) {
    fmt.Println("Resource does not exist")
}

if api.IsUnauthorized(err) {
    fmt.Println("Check your API key")
}
```

**Example:**

```go
app, err := client.GetApplication(12345678)
if err != nil {
    if api.IsNotFound(err) {
        log.Println("Application not found")
        return
    }
    if api.IsUnauthorized(err) {
        log.Fatal("Invalid API key - run 'newrelic-cli config set-api-key'")
    }
    log.Fatalf("API error: %v", err)
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
