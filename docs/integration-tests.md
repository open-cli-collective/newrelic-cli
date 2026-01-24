# Integration Test Checklist

This document provides a manual testing checklist for verifying nrq functionality against a live New Relic account.

## Prerequisites

### Required

- [ ] Valid New Relic User API key (`NRAK-...`)
- [ ] New Relic account ID
- [ ] At least one APM application reporting data
- [ ] Account permissions for all features being tested

### Test Data Naming Convention

When creating test data (deployments, log parsing rules, etc.), use the prefix:

```
newrelic-cli-test-*
```

This makes it easy to identify and clean up test data after testing.

### Setup

```bash
# Configure credentials
nrq config set-api-key
nrq config set-account-id <your-account-id>

# Verify configuration
nrq config show
```

---

## Test Matrix

### apps

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| List apps (table) | `nrq apps list` | Table with ID, NAME, LANGUAGE, STATUS columns | [ ] |
| List apps (JSON) | `nrq apps list -o json` | Valid JSON array | [ ] |
| List apps (plain) | `nrq apps list -o plain` | Tab-separated, no headers | [ ] |
| Get app | `nrq apps get <id>` | App details displayed | [ ] |
| Get app (JSON) | `nrq apps get <id> -o json` | Valid JSON object | [ ] |
| Get invalid app | `nrq apps get 99999999` | Error message, exit code 1 | [ ] |
| List metrics | `nrq apps metrics <id>` | List of metric names | [ ] |

**Notes:**
- Record an app ID for use in later tests: `__________`

---

### alerts policies

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| List policies (table) | `nrq alerts policies list` | Table with ID, NAME, INCIDENT PREFERENCE | [ ] |
| List policies (JSON) | `nrq alerts policies list -o json` | Valid JSON array | [ ] |
| Get policy | `nrq alerts policies get <id>` | Policy details displayed | [ ] |
| Get invalid policy | `nrq alerts policies get 99999999` | Error message | [ ] |

**Notes:**
- Record a policy ID for reference: `__________`

---

### dashboards

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| List dashboards (table) | `nrq dashboards list` | Table with GUID, NAME, PAGES | [ ] |
| List dashboards (JSON) | `nrq dashboards list -o json` | Valid JSON array | [ ] |
| Get dashboard | `nrq dashboards get <guid>` | Dashboard details displayed | [ ] |
| Get dashboard (JSON) | `nrq dashboards get <guid> -o json` | Valid JSON with pages/widgets | [ ] |

**Notes:**
- Record a dashboard GUID for reference: `__________`

---

### deployments

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| List deployments | `nrq deployments list <app-id>` | Table or "No deployments found" | [ ] |
| Create deployment | `nrq deployments create <app-id> -r "newrelic-cli-test-v1.0.0" -d "Test deployment"` | Success message with ID | [ ] |
| Create deployment (JSON) | `nrq deployments create <app-id> -r "newrelic-cli-test-v1.0.1" -o json` | Valid JSON object | [ ] |
| Verify created | `nrq deployments list <app-id>` | Shows test deployments | [ ] |
| Missing revision | `nrq deployments create <app-id>` | Error about required flag | [ ] |

**Notes:**
- Test deployments will appear in New Relic UI for the application

---

### entities

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| Search by type | `nrq entities search "type = 'APPLICATION'"` | Table with APM apps | [ ] |
| Search by name | `nrq entities search "name LIKE '%'"` | Table with entities | [ ] |
| Search (JSON) | `nrq entities search "type = 'APPLICATION'" -o json` | Valid JSON array | [ ] |
| Empty results | `nrq entities search "name = 'nonexistent-entity-xyz'"` | "No entities found" | [ ] |

---

### logs rules

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| List rules | `nrq logs rules list` | Table or "No log parsing rules found" | [ ] |
| List rules (JSON) | `nrq logs rules list -o json` | Valid JSON array | [ ] |
| Create rule | See command below | Success message with ID | [ ] |
| Verify created | `nrq logs rules list` | Shows test rule | [ ] |
| Update rule description | `nrq logs rules update <rule-id> --description "newrelic-cli-test-updated"` | Success message | [ ] |
| Update rule (disable) | `nrq logs rules update <rule-id> --disabled` | Success message | [ ] |
| Update rule (JSON) | `nrq logs rules update <rule-id> --description "test" -o json` | Valid JSON object | [ ] |
| Verify update persisted | `nrq logs rules list` | Shows updated description | [ ] |
| Delete rule | `nrq logs rules delete <rule-id>` | Success message | [ ] |
| Verify deleted | `nrq logs rules list` | Test rule removed | [ ] |

**Create rule command:**
```bash
nrq logs rules create \
  --description "newrelic-cli-test-rule" \
  --grok "Test %{WORD:test_field}" \
  --nrql "SELECT * FROM Log WHERE message LIKE 'Test%'" \
  --enabled false
```

**Notes:**
- Record the rule ID for deletion: `__________`
- Creating rules disabled (`--enabled false`) to avoid affecting production logs

---

### nerdgraph

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| Simple query | `nrq nerdgraph query '{ actor { user { email } } }'` | JSON with user email | [ ] |
| Account query | `nrq nerdgraph query '{ actor { accounts { id name } } }'` | JSON with accounts | [ ] |
| Invalid query | `nrq nerdgraph query '{ invalid }'` | Error message | [ ] |

---

### nrql

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| Count query | `nrq nrql query "SELECT count(*) FROM Transaction SINCE 1 hour ago"` | JSON with count | [ ] |
| Facet query | `nrq nrql query "SELECT count(*) FROM Transaction FACET appName SINCE 1 hour ago"` | JSON with facets | [ ] |
| Invalid NRQL | `nrq nrql query "SELECT * FROM InvalidEventType"` | Error or empty results | [ ] |
| Empty results | `nrq nrql query "SELECT count(*) FROM Transaction WHERE 1=0"` | JSON with count = 0 | [ ] |

---

### synthetics

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| List monitors | `nrq synthetics list` | Table or "No synthetic monitors found" | [ ] |
| List monitors (JSON) | `nrq synthetics list -o json` | Valid JSON array | [ ] |
| Get monitor | `nrq synthetics get <id>` | Monitor details | [ ] |
| Get invalid monitor | `nrq synthetics get invalid-id` | Error message | [ ] |

**Notes:**
- Requires at least one synthetic monitor in the account

---

### users

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| List users | `nrq users list` | Table with ID, NAME, EMAIL, ROLE | [ ] |
| List users (JSON) | `nrq users list -o json` | Valid JSON array | [ ] |
| Get user | `nrq users get <id>` | User details | [ ] |
| Get invalid user | `nrq users get 99999999` | Error message | [ ] |

---

### config

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| Show config | `nrq config show` | Status with masked key, account ID, region | [ ] |
| Set region US | `nrq config set-region US` | Success message | [ ] |
| Set region EU | `nrq config set-region EU` | Success message | [ ] |
| Invalid region | `nrq config set-region XX` | Error message | [ ] |
| Set account ID | `nrq config set-account-id 12345` | Success message | [ ] |

---

## Edge Cases

### Unicode Characters

| Test | Expected | Pass |
|------|----------|------|
| App name with unicode (if exists) | Displayed correctly | [ ] |
| Entity search with unicode | No crash, proper handling | [ ] |

### Empty Results

| Test | Expected | Pass |
|------|----------|------|
| `apps list` (no apps) | "No applications found" | [ ] |
| `alerts policies list` (no policies) | "No alert policies found" | [ ] |
| `dashboards list` (no dashboards) | "No dashboards found" | [ ] |
| `entities search` (no matches) | "No entities found" | [ ] |

### Authentication Errors

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| Invalid API key | Set invalid key, run any command | "unauthorized" error | [ ] |
| Missing API key | Unset key, run any command | "API key required" error | [ ] |
| Missing account ID | Commands requiring account | "account ID required" error | [ ] |

### Output Format Consistency

For each command that supports output formats, verify:

| Format | Characteristics | Pass |
|--------|-----------------|------|
| `table` | Aligned columns, headers, colored status | [ ] |
| `json` | Valid JSON, parseable by jq | [ ] |
| `plain` | Tab-separated, no headers, no color | [ ] |

### Global Flags

| Test | Command | Expected | Pass |
|------|---------|----------|------|
| `--no-color` | `nrq apps list --no-color` | No ANSI color codes | [ ] |
| `--help` | `nrq apps --help` | Help text displayed | [ ] |
| `--version` | `nrq --version` | Version info with commit, date | [ ] |

---

## Test Execution Checklist

### Pre-Test

- [ ] Built latest version (`make build`)
- [ ] Configured valid credentials
- [ ] Verified `config show` works
- [ ] Identified test app ID, policy ID, dashboard GUID

### Post-Test Cleanup

- [ ] Delete any test log parsing rules created
- [ ] Note: Test deployments cannot be deleted via API

### Results Summary

| Category | Total | Passed | Failed |
|----------|-------|--------|--------|
| apps | 7 | | |
| alerts policies | 4 | | |
| dashboards | 4 | | |
| deployments | 5 | | |
| entities | 4 | | |
| logs rules | 10 | | |
| nerdgraph | 3 | | |
| nrql | 4 | | |
| synthetics | 4 | | |
| users | 4 | | |
| config | 5 | | |
| Edge cases | ~15 | | |
| **TOTAL** | ~69 | | |

---

## Troubleshooting

### Common Issues

**"unauthorized" error:**
- Verify API key is valid and has proper permissions
- Check if key is User API key (NRAK-) not License key

**"account ID required" error:**
- Set account ID via `config set-account-id` or `NEWRELIC_ACCOUNT_ID`

**Empty results when data exists:**
- Verify account ID matches where data exists
- Check region setting (US vs EU)

**Timeout errors:**
- Large result sets may timeout
- Try more specific queries to reduce result size
