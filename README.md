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

### macOS

**Homebrew (recommended)**

```bash
brew install open-cli-collective/tap/newrelic-cli
```

> Note: This installs from our third-party tap.

---

### Windows

**Chocolatey**

```powershell
choco install nrq-cli
```

**Winget**

```powershell
winget install OpenCLICollective.newrelic-cli
```

---

### Linux

**Snap**

```bash
sudo snap install ocli-newrelic
```

> Note: After installation, the command is available as `nrq`.

**APT (Debian/Ubuntu)**

```bash
# Add the GPG key
curl -fsSL https://open-cli-collective.github.io/linux-packages/keys/gpg.asc | sudo gpg --dearmor -o /usr/share/keyrings/open-cli-collective.gpg

# Add the repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/open-cli-collective.gpg] https://open-cli-collective.github.io/linux-packages/apt stable main" | sudo tee /etc/apt/sources.list.d/open-cli-collective.list

# Install
sudo apt update
sudo apt install nrq
```

> Note: This is our third-party APT repository, not official Debian/Ubuntu repos.

**DNF/YUM (Fedora/RHEL/CentOS)**

```bash
# Add the repository
sudo tee /etc/yum.repos.d/open-cli-collective.repo << 'EOF'
[open-cli-collective]
name=Open CLI Collective
baseurl=https://open-cli-collective.github.io/linux-packages/rpm
enabled=1
gpgcheck=1
gpgkey=https://open-cli-collective.github.io/linux-packages/keys/gpg.asc
EOF

# Install
sudo dnf install nrq
```

> Note: This is our third-party RPM repository, not official Fedora/RHEL repos.

**Binary download**

Download `.deb`, `.rpm`, or `.tar.gz` from the [Releases page](https://github.com/open-cli-collective/newrelic-cli/releases) - available for x64 and ARM64.

```bash
# Direct .deb install
curl -LO https://github.com/open-cli-collective/newrelic-cli/releases/latest/download/nrq_VERSION_linux_amd64.deb
sudo dpkg -i nrq_VERSION_linux_amd64.deb

# Direct .rpm install
curl -LO https://github.com/open-cli-collective/newrelic-cli/releases/latest/download/nrq-VERSION.x86_64.rpm
sudo rpm -i nrq-VERSION.x86_64.rpm
```

---

### From Source

```bash
go install github.com/open-cli-collective/newrelic-cli/cmd/nrq@latest
```

## Quick Start

```bash
# 1. Configure your API key (stored securely)
nrq config set-api-key

# 2. Set your account ID
nrq config set-account-id 12345678

# 3. Verify configuration
nrq config show

# 4. Start using the CLI
nrq apps list
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
nrq config set-api-key

# Set API key (inline)
nrq config set-api-key NRAK-xxxxxxxxxxxxxxxxxxxx

# Set account ID
nrq config set-account-id 12345678

# Set region (US or EU)
nrq config set-region EU

# View current configuration
nrq config show

# Delete stored credentials
nrq config delete-api-key
nrq config delete-account-id
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

### Shell Completion

Generate shell completions for tab completion support:

```bash
# Bash (Linux)
nrq completion bash > /etc/bash_completion.d/newrelic-cli

# Bash (macOS with Homebrew)
nrq completion bash > $(brew --prefix)/etc/bash_completion.d/newrelic-cli

# Zsh
nrq completion zsh > "${fpath[1]}/_newrelic-cli"

# Fish
nrq completion fish > ~/.config/fish/completions/newrelic-cli.fish

# PowerShell
nrq completion powershell >> $PROFILE
```

Run `nrq completion --help` for detailed setup instructions.

---

## Command Reference

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `table` | Output format: `table`, `json`, or `plain` |
| `--no-color` | | `false` | Disable colored output |
| `--help` | `-h` | | Show help for any command |
| `--version` | | | Show version information |

### Command Aliases

Most commands have shorter aliases for convenience:

| Command | Aliases |
|---------|---------|
| `applications` | `apps`, `app` |
| `alerts` | `alert` |
| `dashboards` | `dashboard`, `dash` |
| `deployments` | `deployment`, `deploy` |
| `entities` | `entity`, `ent` |
| `logs` | `log` |
| `synthetics` | `synthetic`, `syn` |
| `nerdgraph` | `ng`, `graphql` |
| `users` | `user` |

---

### apps

Manage APM applications.

#### apps list

List all APM applications in your account.

```bash
nrq apps list
nrq apps list -o json
nrq apps list -o plain
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
nrq apps get <app-id>
nrq apps get 12345678
nrq apps get 12345678 -o json
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
nrq apps metrics <app-id>
nrq apps metrics 12345678
```

---

### alerts policies

Manage alert policies.

#### alerts policies list

List all alert policies.

```bash
nrq alerts policies list
nrq alerts policies list -o json
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
nrq alerts policies get <policy-id>
nrq alerts policies get 12345
```

---

### dashboards

Manage dashboards.

#### dashboards list

List all dashboards.

```bash
nrq dashboards list
nrq dashboards list -o json
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
nrq dashboards get <guid>
nrq dashboards get "ABC123..."
```

---

### deployments

Manage deployment markers.

**Aliases:** `deployment`, `deploy`

#### deployments list

List deployments for an application with optional time filtering.

```bash
# By app ID
nrq deployments list 12345678

# By application name
nrq deployments list --name "My Application"

# By entity GUID
nrq deployments list --guid "MjcxMjY0MHxBUE18..."

# With time filtering
nrq deployments list 12345678 --since "7 days ago" --until "yesterday"

# Limit results
nrq deployments list 12345678 --limit 10
```

| Flag | Short | Description |
|------|-------|-------------|
| `--name` | `-n` | Application name to look up |
| `--guid` | `-g` | Entity GUID to look up |
| `--since` | | Show deployments after this time |
| `--until` | | Show deployments before this time |
| `--limit` | `-l` | Limit number of results |

**Time formats:** Supports relative times (`7 days ago`, `2 hours ago`), keywords (`now`, `yesterday`), and standard formats (`2025-01-14`, RFC3339).

**Table Output:**
```
ID          REVISION        DESCRIPTION             USER            TIMESTAMP
9876        v1.2.3          Bug fixes               alice           2024-01-15T10:30:00Z
9875        v1.2.2          Feature release         bob             2024-01-14T15:00:00Z
```

#### deployments create

Create a deployment marker for an application.

```bash
# By app ID
nrq deployments create 12345678 --revision v1.2.3

# By application name
nrq deployments create --name "My Application" --revision v1.2.3

# By entity GUID
nrq deployments create --guid "MjcxMjY0MHxBUE18..." --revision v1.2.3

# Full example
nrq deployments create 12345678 \
  --revision v1.2.3 \
  --description "Bug fixes and performance improvements" \
  --user "alice" \
  --changelog "Fixed memory leak, improved cache hit rate"
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--name` | `-n` | No* | Application name to look up |
| `--guid` | `-g` | No* | Entity GUID to look up |
| `--revision` | `-r` | Yes | Deployment revision/version |
| `--description` | `-d` | No | Deployment description |
| `--user` | `-u` | No | User who deployed |
| `--changelog` | `-c` | No | Changelog information |

*One of app ID (positional), `--name`, or `--guid` is required.

#### deployments search

Search deployments across all applications using NRQL WHERE clause syntax.

```bash
# Search by user
nrq deployments search "user = 'jane.doe@example.com'"

# Search by revision pattern
nrq deployments search "revision LIKE 'v2%'"

# Search with time range
nrq deployments search "description LIKE '%hotfix%'" --since "30 days ago"

# Limit results
nrq deployments search "changelog IS NOT NULL" --limit 50
```

| Flag | Short | Description |
|------|-------|-------------|
| `--since` | | Search from this time |
| `--until` | | Search until this time |
| `--limit` | `-l` | Maximum results (default: 100) |

**Table Output:**
```
TIMESTAMP                   APP NAME            REVISION    DESCRIPTION         USER
2024-01-15T10:30:00Z        production-api      v2.1.0      Hotfix              jane.doe
2024-01-14T15:00:00Z        staging-api         v2.0.9      Bug fixes           bob
```

---

### entities

Search and manage New Relic entities.

**Aliases:** `entity`, `ent`

#### entities search

Search for entities using NRQL-style queries.

```bash
nrq entities search <query>
```

**Examples:**
```bash
# Find all applications
nrq entities search "type = 'APPLICATION'"

# Find by name pattern
nrq entities search "name LIKE 'production%'"

# Find by domain
nrq entities search "domain = 'APM'"

# Combined conditions
nrq entities search "type = 'APPLICATION' AND name LIKE 'prod%'"
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
nrq logs rules list
nrq logs rules list -o json
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
nrq logs rules create [flags]
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
nrq logs rules create \
  --description "Parse user login events" \
  --grok "User %{UUID:user_id} logged in from %{IP:ip_address}" \
  --nrql "SELECT * FROM Log WHERE message LIKE 'User % logged in%'" \
  --enabled true
```

#### logs rules update

Update an existing log parsing rule. Only specified fields are modified.

```bash
nrq logs rules update <rule-id> [flags]
```

| Flag | Short | Description |
|------|-------|-------------|
| `--description` | `-d` | Rule description |
| `--grok` | `-g` | GROK pattern |
| `--nrql` | `-n` | NRQL matching condition |
| `--lucene` | `-l` | Lucene filter expression |
| `--enabled` | `-e` | Enable the rule |
| `--disabled` | | Disable the rule |

**Examples:**
```bash
# Update description only
nrq logs rules update abc-123 --description "Updated description"

# Disable a rule
nrq logs rules update abc-123 --disabled

# Update multiple fields
nrq logs rules update abc-123 \
  --grok "%{IP:client} %{WORD:method}" \
  --enabled
```

#### logs rules delete

Delete a log parsing rule. Requires confirmation unless `--force` is specified.

```bash
# With confirmation prompt
nrq logs rules delete abc-123-def-456

# Skip confirmation
nrq logs rules delete abc-123-def-456 --force
```

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Skip confirmation prompt |

---

### nerdgraph

Execute NerdGraph GraphQL queries.

**Aliases:** `ng`, `graphql`

#### nerdgraph query

Execute a GraphQL query against the NerdGraph API.

```bash
nrq nerdgraph query <graphql-query>
```

**Examples:**
```bash
# Get current user info
nrq nerdgraph query '{ actor { user { email name } } }'

# List accounts
nrq nerdgraph query '{ actor { accounts { id name } } }'

# Complex query
nrq nerdgraph query '{
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
nrq nrql query <nrql-query>
```

**Examples:**
```bash
# Transaction count
nrq nrql query "SELECT count(*) FROM Transaction SINCE 1 hour ago"

# Average response time by app
nrq nrql query "SELECT average(duration) FROM Transaction FACET appName SINCE 1 day ago"

# Error rate
nrq nrql query "SELECT percentage(count(*), WHERE error IS true) FROM Transaction SINCE 1 hour ago"

# Top slow transactions
nrq nrql query "SELECT average(duration), count(*) FROM Transaction FACET name SINCE 1 hour ago LIMIT 10"
```

---

### synthetics

Manage synthetic monitors.

#### synthetics list

List all synthetic monitors.

```bash
nrq synthetics list
nrq synthetics list -o json
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
nrq synthetics get <monitor-id>
nrq synthetics get abc-123-def-456
```

---

### users

Manage users.

#### users list

List all users in your account.

```bash
nrq users list
nrq users list -o json
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
nrq users get <user-id>
nrq users get 12345
```

---

### config

Configure nrq credentials.

#### config set-api-key

Set the New Relic API key.

```bash
# Interactive (recommended)
nrq config set-api-key

# Inline (less secure - visible in shell history)
nrq config set-api-key NRAK-xxxxxxxxxxxxxxxxxxxx
```

#### config set-account-id

Set the New Relic account ID.

```bash
nrq config set-account-id 12345678
```

#### config set-region

Set the New Relic region.

```bash
nrq config set-region US   # Default
nrq config set-region EU   # European datacenter
```

#### config show

Show current configuration status.

```bash
nrq config show
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

Delete the stored API key. Requires confirmation unless `--force` is specified.

```bash
# With confirmation prompt
nrq config delete-api-key

# Skip confirmation
nrq config delete-api-key --force
```

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Skip confirmation prompt |

#### config delete-account-id

Delete the stored account ID. Requires confirmation unless `--force` is specified.

```bash
# With confirmation prompt
nrq config delete-account-id

# Skip confirmation
nrq config delete-account-id --force
```

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Skip confirmation prompt |

---

## Output Formats

### Table (default)

Human-readable tabular format with headers and aligned columns.

```bash
nrq apps list
nrq apps list -o table
```

### JSON

Machine-readable JSON output for programmatic use.

```bash
nrq apps list -o json
```

### Plain

Tab-separated values without headers, ideal for shell scripting.

```bash
nrq apps list -o plain
```

---

## Scripting Examples

### Extract Application IDs

```bash
# Get all app IDs
nrq apps list -o plain | cut -f1

# Get app ID by name
nrq apps list -o json | jq -r '.[] | select(.name == "production-api") | .id'
```

### Create Deployments from Git

```bash
# Deploy with git info
nrq deployments create $APP_ID \
  --revision "$(git rev-parse --short HEAD)" \
  --description "$(git log -1 --pretty=%B)" \
  --user "$(git config user.name)"
```

### Monitor Health Status

```bash
# Check for unhealthy apps
nrq apps list -o json | jq -r '.[] | select(.health_status != "green") | .name'
```

### Batch Operations

```bash
# Record deployment for all production apps
nrq apps list -o json | \
  jq -r '.[] | select(.name | startswith("prod")) | .id' | \
  xargs -I {} nrq deployments create {} --revision v1.0.0
```

### NRQL in Scripts

```bash
# Get error count as a number
ERROR_COUNT=$(nrq nrql query "SELECT count(*) FROM TransactionError SINCE 1 hour ago" | jq '.results[0].count')
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

    "github.com/open-cli-collective/newrelic-cli/api"
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
| `GetLogParsingRule(id)` | Get parsing rule by ID |
| `UpdateLogParsingRule(id, update)` | Update parsing rule |
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

### AccountID Type

The `AccountID` type provides type-safe handling of New Relic account identifiers:

```go
// Create and validate an account ID
accountID, err := api.NewAccountID("12345678")
if err != nil {
    log.Fatal(err)  // Empty, non-numeric, or non-positive
}

// Get as integer (no error check needed - already validated)
id := accountID.Int()

// Check if empty
if accountID.IsEmpty() {
    log.Fatal("Account ID required")
}

// Validate an existing AccountID
if err := accountID.Validate(); err != nil {
    log.Fatal(err)
}
```

Account IDs must be positive integers. The `Int()` method provides pre-validated integer conversion without requiring error handling.

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
        log.Fatal("Invalid API key - run 'nrq config set-api-key'")
    }
    log.Fatalf("API error: %v", err)
}
```

### Utility Functions

#### App ID Resolution

Resolve application identifiers from multiple formats (numeric ID, Entity GUID, or application name):

```go
// Accepts: numeric ID, Entity GUID, or application name
appID, err := client.ResolveAppID("my-application")
if err != nil {
    log.Fatal(err)
}

// Now use appID with deployment or metrics APIs
deployments, err := client.ListDeployments(appID)
```

#### Flexible Time Parsing

Parse time strings in various formats for filtering:

```go
// Relative times
t, _ := api.ParseFlexibleTime("7 days ago")
t, _ := api.ParseFlexibleTime("2 hours ago")
t, _ := api.ParseFlexibleTime("1 week ago")

// Keywords
t, _ := api.ParseFlexibleTime("now")
t, _ := api.ParseFlexibleTime("today")
t, _ := api.ParseFlexibleTime("yesterday")

// ISO8601/RFC3339
t, _ := api.ParseFlexibleTime("2025-01-14T10:00:00Z")

// Date-only (parses as start of day)
t, _ := api.ParseFlexibleTime("2025-01-14")
t, _ := api.ParseFlexibleTime("01/14/2025")
```

#### Deployment Filtering

Filter deployments by time range:

```go
since, _ := api.ParseFlexibleTime("7 days ago")
until, _ := api.ParseFlexibleTime("now")
filtered := api.FilterDeploymentsByTime(deployments, since, until)
```

#### GUID Validation

Check if a string looks like an Entity GUID (useful for disambiguation):

```go
if api.IsValidEntityGUID(input) {
    // Likely a base64-encoded entity GUID
    guid := api.EntityGUID(input)
    appID, _ := guid.AppID()
} else if isNumeric(input) {
    // Numeric app ID
    appID = input
} else {
    // Probably an application name
    appID, _ = client.ResolveAppID(input)
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
