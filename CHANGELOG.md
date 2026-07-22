# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Migrated all commands off deprecated New Relic APIs onto NerdGraph.**
  New Relic is replacing the REST v2 API with NerdGraph and has deprecated the
  Synthetics REST API (legacy runtimes only; new legacy-runtime monitors have
  been blocked since Aug 2024). Affected commands:
  - `synthetics` — full CRUD now uses the runtime-capable NerdGraph mutations;
    monitors can be identified by ID, entity GUID, or name; monitor JSON
    accepts optional `script` and `runtime` fields. Status `MUTED` is no
    longer accepted (REST-only concept). Creates now require a configured
    account ID.
  - `deployments` — `list`/`create` now use the change tracking API. Output
    reports the change tracking `deploymentId`/`version` (previously numeric
    marker ID/revision); `create` gains `--commit`.
  - `apps` — `list`/`get` now use entity search; `get`/`metrics` accept app
    ID, name, or entity GUID. Status column now shows NerdGraph alert
    severity values (NOT_ALERTING/WARNING/CRITICAL/NOT_CONFIGURED).
    `metrics` reads metric names via NRQL (`uniques(metricName) FROM Metric`,
    past day) and requires a configured account ID.
  - `alerts list` — now uses `policiesSearch` (paginated) and requires a
    configured account ID.
  The Go `api` package keeps the REST implementations as `*REST` methods,
  each marked `Deprecated:` with a link to the New Relic notice; the README
  documents the deprecation status of every New Relic API nrq touches.
- Fixed `alerts get` showing policy ID 0: NerdGraph serializes policy IDs as
  strings, which the parser now accepts.

- Chocolatey package renamed from `newrelic-cli` to `nrq-cli` ([#69](https://github.com/open-cli-collective/newrelic-cli/pull/69))
- **Binary renamed to `nrq`** - The CLI binary is now `nrq` (short for New Relic query). Install via `brew install newrelic-cli`, run with `nrq`. ([#63](https://github.com/open-cli-collective/newrelic-cli/pull/63))
- Module path migrated to `github.com/open-cli-collective/newrelic-cli` ([#56](https://github.com/open-cli-collective/newrelic-cli/pull/56))

### Added

- Linux distribution support via Snap, APT, and RPM packages ([#67](https://github.com/open-cli-collective/newrelic-cli/pull/67))
- `nrq init` command for guided API key setup ([#60](https://github.com/open-cli-collective/newrelic-cli/pull/60))
- `nrq config test` and `config clear` subcommands ([#60](https://github.com/open-cli-collective/newrelic-cli/pull/60))
- CRUD operations for dashboards: `dashboards create`, `dashboards update`, `dashboards delete` ([#61](https://github.com/open-cli-collective/newrelic-cli/pull/61))
- CRUD operations for synthetics monitors: `synthetics create`, `synthetics update`, `synthetics delete` ([#61](https://github.com/open-cli-collective/newrelic-cli/pull/61))
- NRQL query UX improvements: `--since`, `--until` time flags and `nrql` shortcut command ([#59](https://github.com/open-cli-collective/newrelic-cli/pull/59))
- `--limit` flag for all list commands ([#57](https://github.com/open-cli-collective/newrelic-cli/pull/57))
