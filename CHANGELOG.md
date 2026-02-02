# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
