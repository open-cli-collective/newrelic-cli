# newrelic-cli

A command-line interface for interacting with New Relic APIs.

## Features

- **APM Applications**: List applications, view details, and retrieve available metrics
- **Alert Policies**: List and inspect alert policy configurations
- **Dashboards**: List and view dashboard details
- **Deployments**: Record and list deployments via change tracking
- **Entities**: Search across all New Relic entity types
- **Log Parsing Rules**: Create, list, and delete log parsing rules
- **NerdGraph**: Execute arbitrary GraphQL queries
- **NRQL**: Run NRQL queries directly from the command line
- **Synthetic Monitors**: Full CRUD for synthetic monitors on the current runtimes
- **Users**: List and view user details
- **Agent-First Output**: Table and plain (scriptable) output on resource reads; JSON reserved for control-plane envelopes (`set-credential`, `config show`, `config test` with `--json`) and NerdGraph/NRQL passthrough (see cli-common docs/output-and-rendering.md §2)
- **Secure Credential Storage**: API key stored in the OS keyring (macOS Keychain / Windows Credential Manager / Linux Secret Service), or an encrypted file with the explicit file-backend opt-in — never in plaintext and never in `config.yml`

## New Relic API deprecation status

All `nrq` commands run on **NerdGraph**, New Relic's supported GraphQL API.
New Relic has deprecated or is phasing out several older APIs; here is where
`nrq` stands on each:

| New Relic API | Status | nrq |
|---|---|---|
| [REST v2](https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/) (`api.newrelic.com/v2`) | Being replaced by NerdGraph; minimal maintenance | No longer used by any command. The Go `api` package retains `*REST` methods, marked `Deprecated` |
| [Synthetics REST](https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/administration/synthetics-api/) (`synthetics/api/v3`) | Deprecated; legacy runtimes only — new legacy-runtime monitors blocked since Aug 26, 2024 | No longer used. `nrq synthetics` uses the runtime-capable [NerdGraph mutations](https://docs.newrelic.com/docs/apis/nerdgraph/examples/synthetics-api/overview/) |
| REST v2 deployment markers | Superseded by [change tracking](https://docs.newrelic.com/docs/change-tracking/change-tracking-introduction/) | `nrq deployments` records and lists deployments via change tracking |
| [REST API keys](https://docs.newrelic.com/eol/2025/01/deprecation-notice-rest-api-keys/) | End of life March 1, 2025 | Not affected — `nrq` authenticates with a User API key (`NRAK-…`) |
| [NRQL Drop Filter Rules API](https://docs.newrelic.com/eol/2025/05/drop-rule-filter/) | Shut off August 31, 2026 | Not used by `nrq` |

The deprecated `*REST` methods in the public `api` package remain available
for Go consumers during migration; each carries a `Deprecated:` doc comment
linking to the relevant New Relic notice.

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
# 1. First-time setup (API key stored in the OS keyring — never in plaintext, never in config.yml)
nrq init

# 2. Verify configuration
nrq config show

# 3. Start using the CLI
nrq apps list
```

## Configuration

### Environment Variables

| Variable | Description | Notes |
|----------|-------------|-------|
| `NEWRELIC_API_KEY` | New Relic User API key (`NRAK-`) | **Setup ingress only** — accepted by `nrq init --api-key-from-env` / `nrq set-credential --from-env`; **not** read at runtime |
| `NEWRELIC_ACCOUNT_ID` | New Relic account ID (non-secret) | Runtime override; precedence **env > config.yml** |
| `NEWRELIC_REGION` | API region: `US` (default) or `EU` (non-secret) | Runtime override; precedence **env > config.yml** |

### CLI Configuration Commands

```bash
# First-time setup (interactive no-echo API key prompt, or scripted ingress)
nrq init
op read "op://Vault/New Relic/api key" | nrq init --api-key-stdin --account-id 12345 --region US

# Fully non-interactive (central installer: op resolves refs into env vars)
nrq init --region US \
  --api-key-from-env NEWRELIC_API_KEY \
  --account-id-from-env NEWRELIC_ACCOUNT_ID \
  --non-interactive

# Verify the resolved credential / account (exits non-zero if broken)
nrq me

# Low-level scripted secret ingress (single key, stdin or env — never a flag value)
nrq set-credential --key api_key --stdin
nrq set-credential --key api_key --from-env NEWRELIC_API_KEY

# Set non-secret config (written to config.yml)
nrq config set --account-id 12345678 --region EU

# View current configuration (never prints the key value)
nrq config show

# Remove credentials (idempotent, non-interactive)
nrq config clear          # removes the keyring api_key
nrq config clear --all    # also removes config.yml
```

> `nrq config set-api-key` is **removed** — the API key is no longer stored on
> disk or accepted as a positional/flag value (§1.5). Use `nrq init` or
> `nrq set-credential`. `config set-account-id` / `config set-region` are
> deprecated thin aliases of `config set` (one cycle).

> **Installer / non-interactive `init`:** `--api-key-from-env <VAR>` ingests
> the secret into the keyring; `--account-id-from-env <VAR>` ingests the
> **non-secret** account ID into `config.yml` (same `op→env→--*-from-env`
> channel, never the keyring). `--non-interactive` makes `init` fail loudly
> instead of prompting for any missing value — including the file-backend
> passphrase. `nrq me` resolves the credential and prints the authenticated
> user/account, exiting non-zero if the key is invalid or the configured
> account is inaccessible (scripted health check / installer `verify`).

### Credential Storage

The API key lives **only** in the OS keyring via the shared
`cli-common/credstore`:

| Platform | Backend |
|----------|---------|
| macOS | Keychain |
| Windows | Credential Manager |
| Linux | Secret Service (encrypted-file fallback when no keyring is available) |

Backend selection has three user-configurable knobs that fall back to
auto-detect, in precedence order: `--backend <name>` flag >
`NEWRELIC_CLI_KEYRING_BACKEND` env var > `keyring.backend` in
`config.yml` > auto-detect. Supported names: `keychain`, `wincred`,
`secret-service`, `file`, `memory`. The `file` backend additionally
requires `NEWRELIC_CLI_KEYRING_PASSPHRASE`.

Non-secret config (`credential_ref`, `account_id`, `region`) lives in
`~/.config/newrelic-cli/config.yml` (0600). A pre-existing macOS Keychain
entry or legacy `~/.config/newrelic-cli/credentials` file is auto-migrated on
first run (one-time; the API key moves to the keyring, account_id/region into
config.yml, the legacy original is removed). Divergent legacy secret values
fail loudly rather than silently picking a winner.

### Configuration Precedence

- **API key:** OS keyring only at runtime (env is setup-ingress only).
- **account_id / region:** environment variable > `config.yml` > built-in default.

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
nrq apps list -o plain
```

**Table Output:**
```
ID          NAME                        LANGUAGE    STATUS
12345678    production-api              ruby        NOT_ALERTING
23456789    staging-api                 ruby        not reporting
34567890    frontend-service            nodejs      WARNING
```

Status values are NerdGraph alert severities (`NOT_ALERTING`, `WARNING`,
`CRITICAL`, `NOT_CONFIGURED`), or `not reporting` when the agent has stopped
reporting.

#### apps get

Get details for a specific application, identified by numeric app ID, name,
or entity GUID.

```bash
nrq apps get <app>
nrq apps get 12345678
nrq apps get "production-api"
```

**Table Output:**
```
ID:              12345678
GUID:            MjcxMjY0MHxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg
Name:            production-api
Language:        ruby
Alert Status:    NOT_ALERTING
Reporting:       true
Status Changed:  2024-01-15T10:30:00Z
```

#### apps metrics

List the metric names an application reported over the past day, identified
by numeric app ID, name, or entity GUID. Requires a configured account ID
(`nrq config set --account-id`) — names are read via NRQL
(`SELECT uniques(metricName) FROM Metric`).

```bash
nrq apps metrics <app>
nrq apps metrics 12345678
```

---

### alerts policies

Manage alert policies.

#### alerts policies list

List all alert policies. Requires a configured account ID
(`nrq config set --account-id`).

```bash
nrq alerts policies list
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

Record and list deployments via the NerdGraph change tracking API.

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
DEPLOYMENT ID       VERSION         DESCRIPTION             USER            TIMESTAMP
dep-8a7b6c5d        v1.2.3          Bug fixes               alice           2024-01-15T10:30:00Z
dep-4e3f2a1b        v1.2.2          Feature release         bob             2024-01-14T15:00:00Z
```

#### deployments create

Record a deployment for an application. The `--revision` value is recorded
as the change tracking `version`.

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
  --changelog "Fixed memory leak, improved cache hit rate" \
  --commit "0c38bc4"
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--name` | `-n` | No* | Application name to look up |
| `--guid` | `-g` | No* | Entity GUID to look up |
| `--revision` | `-r` | Yes | Deployment revision/version |
| `--description` | `-d` | No | Deployment description |
| `--user` | `-u` | No | User who deployed |
| `--changelog` | `-c` | No | Changelog information |
| `--commit` | | No | Commit SHA associated with the deployment |

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

| Flag | Description |
|------|-------------|
| `--link` | Include New Relic deep link URLs in output |
| `--since` | Time range start for deep links (e.g., `1 hour ago`, `2025-01-01`) |
| `--until` | Time range end for deep links (e.g., `now`, `2025-01-15`) |

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

# Include deep links with a time range
nrq entities search "domain = 'APM'" --link --since "1 hour ago"
```

**Table Output:**
```
GUID                                    NAME                    TYPE            DOMAIN      ACCOUNT ID
ABC123...                               production-api          APPLICATION     APM         12345678
DEF456...                               production-web          APPLICATION     APM         12345678
```

---

### logs link

Generate a New Relic deep link that opens the log viewer with a Lucene filter query pre-populated.

```bash
nrq logs link <lucene-filter>
```

| Flag | Description |
|------|-------------|
| `--since` | Time range start (e.g., `30 minutes ago`, `2025-01-01`) |
| `--until` | Time range end (e.g., `now`, `2025-01-15`) |

When `--since` is provided without `--until`, the end defaults to now.

**Examples:**
```bash
# Link to error logs for a service
nrq logs link 'entity.name:"my-service" level:"ERROR"'

# With time range
nrq logs link 'level:"ERROR"' --since "30 minutes ago"

# Multiple entities
nrq logs link '(entity.name:"svc-a" OR entity.name:"svc-b") level:"ERROR"' --since "1 hour ago"
```

---

### logs rules

Manage log parsing rules.

#### logs rules list

List all log parsing rules.

```bash
nrq logs rules list
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

```bash
nrq nrql <nrql-query>
nrq nrql query <nrql-query>
```

| Flag | Description |
|------|-------------|
| `--link` | Output a New Relic deep link URL instead of executing the query |
| `--since` | Time range start, appended as SINCE clause (e.g., `7 days ago`, `2025-01-01`) |
| `--until` | Time range end, appended as UNTIL clause (e.g., `now`, `2025-01-15`) |

**Examples:**
```bash
# Transaction count
nrq nrql "SELECT count(*) FROM Transaction SINCE 1 hour ago"

# Average response time by app
nrq nrql "SELECT average(duration) FROM Transaction FACET appName SINCE 1 day ago"

# Error rate
nrq nrql "SELECT percentage(count(*), WHERE error IS true) FROM Transaction SINCE 1 hour ago"

# Top slow transactions
nrq nrql "SELECT average(duration), count(*) FROM Transaction FACET name SINCE 1 hour ago LIMIT 10"

# Generate a deep link to open the query in New Relic
nrq nrql --link "SELECT count(*) FROM Transaction SINCE 1 hour ago"

# Using --since flag (appends to query)
nrq nrql "SELECT count(*) FROM Transaction" --since "7 days ago"
```

---

### synthetics

Manage synthetic monitors.

#### synthetics list

List all synthetic monitors.

```bash
nrq synthetics list
```

**Table Output:**
```
ID                                      NAME                    TYPE            STATUS      FREQUENCY
abc-123...                              Production Health       SIMPLE          ENABLED     5 min
def-456...                              API Endpoint Check      SCRIPT_API      ENABLED     1 min
```

#### synthetics get

Get details for a specific synthetic monitor, identified by monitor ID
(UUID), entity GUID, or name.

```bash
nrq synthetics get <monitor>
nrq synthetics get abc-123-def-456
nrq synthetics get "Production Health"
```

#### synthetics create / update / delete

Create, update, and delete monitors from a JSON definition. Monitors are
created via NerdGraph on the current synthetics runtimes; scripted monitors
(`SCRIPT_API`, `SCRIPT_BROWSER`) take `script` and optional `runtime` fields.
See `nrq synthetics create --help` for the JSON schema, valid frequencies,
and locations.

```bash
nrq synthetics create --from-file monitor.json
nrq synthetics update abc-123-def-456 --from-file monitor.json
nrq synthetics delete abc-123-def-456
```

---

### users

Manage users.

#### users list

List all users in your account.

```bash
nrq users list
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

#### Setting the API key

The API key is stored in the OS keyring and is **never** taken as a
flag/positional literal (§1.5). Use `nrq init` (the standard setup
path) or `nrq set-credential` for non-interactive ingress:

```bash
# Interactive setup (no-echo prompt)
nrq init

# Scripted ingress (op → env → --from-env, or stdin)
op read "op://Vault/New Relic/api key" | nrq set-credential --key api_key --stdin
nrq set-credential --key api_key --from-env NEWRELIC_API_KEY
```

`nrq config set-api-key` was removed; a stub remains that prints the
migration message above. See also the §1.5 note further up.

#### config set

Set non-secret fields (`account_id`, `region`) in `config.yml`:

```bash
nrq config set --account-id 12345678
nrq config set --region US      # or EU
nrq config set --account-id 12345678 --region EU   # combined
```

`nrq config set-account-id <id>` and `nrq config set-region <r>` remain
as thin deprecating aliases of `config set` (one cycle).

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

Resource reads emit text only (table by default, plain for scripts). JSON is
reserved per cli-common [`docs/output-and-rendering.md`](https://github.com/open-cli-collective/cli-common/blob/main/docs/output-and-rendering.md) §2 for:

- **Control-plane envelopes**: `set-credential --json`, `config show --json`,
  `config test --json` — `--json` is a subcommand-local flag, not part of the
  global `-o` selector.
- **Passthrough surfaces**: `nerdgraph query` and `nrql` always emit JSON
  regardless of `-o` (their data is GraphQL/NRQL result shape).

`nrq -o json …` on any resource command is rejected at the root. The
previously-deprecated root `--json` boolean alias is also removed — it
was a translation layer over `-o json` and has no closed-set value to
forward to.

### Table (default)

Human-readable tabular format with headers and aligned columns.

```bash
nrq apps list
nrq apps list -o table
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

# Get app ID by name (plain output: ID is column 1, NAME is column 2)
nrq apps list -o plain | awk -F'\t' '$2 == "production-api" {print $1}'
```

### Create Deployments from Git

```bash
# Deploy with git info
nrq deployments create $APP_ID \
  --revision "$(git rev-parse --short HEAD)" \
  --description "$(git log -1 --pretty=%B)" \
  --user "$(git config user.name)"
```

### Monitor Health Status (via NerdGraph passthrough)

```bash
# Check for unhealthy apps using the passthrough JSON surface
nrq nerdgraph query '{ actor { entitySearch(query: "domain = '\''APM'\''") { results { entities { name ... on AlertableEntityOutline { alertSeverity } } } } } }' \
  | jq -r '.actor.entitySearch.results.entities[] | select(.alertSeverity != "NOT_ALERTING") | .name'
```

### NRQL in Scripts

```bash
# Get error count as a number (nrql is a passthrough JSON surface)
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
