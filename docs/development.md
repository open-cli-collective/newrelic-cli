# newrelic-cli Development Guide

This is the repo-local guide for New Relic-specific facts. Shared Open CLI
Collective standards and automation remain canonical in their own repositories.

## Project Overview

newrelic-cli builds the `nrq` command-line interface for New Relic. It uses Cobra
for commands and exposes a public `api/` package for Go callers.

`nrq` covers APM applications, alerts, dashboards, deployments, entities, log
parsing rules, NerdGraph, NRQL, synthetic monitors, users, API keys, and
connection checks.

## Quick Commands

```bash
make build      # build ./nrq from ./cmd/nrq
make test       # run tests with race detection
make test-cover # run tests with coverage output
make lint       # run golangci-lint
make fmt        # go fmt ./...
make verify     # fmt + lint + test
make install    # move nrq to /usr/local/bin
make clean      # remove local build artifacts
```

## Repo Structure

```text
newrelic-cli/
├── cmd/nrq/main.go
├── api/          # public New Relic API client package
├── internal/
│   ├── cmd/      # Cobra commands by resource
│   ├── config/   # non-secret config
│   ├── keychain/ # cli-common credstore adapter and legacy migration
│   ├── version/  # build-time version injection
│   └── view/     # text/table rendering helpers
├── Makefile
└── go.mod
```

## Command Patterns

- Commands use options structs for dependency injection.
- Resource command packages expose `Register` functions.
- New command packages live under `internal/cmd/<resource>/`.
- Add API methods in `api/` when a command needs new New Relic API coverage.
- Use dedicated API identifier types such as `EntityGUID`, `APIKey`, and
  `AccountID` at input/config boundaries.

## Output Contract

Resource reads emit text output only through table/plain rendering. JSON is
reserved for local control-plane envelopes such as `set-credential`,
`config show`, and `config test`, plus passthrough surfaces such as `nerdgraph`
and `nrql`.

Shared output policy:

```md
Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/output-and-rendering.md
Local convenience copy, if present: `../cli-common/docs/output-and-rendering.md`
```

## Credentials And Config

The New Relic API key is stored in the OS keyring through
`cli-common/credstore` under ref `newrelic-cli/default`, key `api_key`.
It is not stored in plaintext, not stored in `config.yml`, and not read from the
environment at runtime.

Non-secret `account_id` and `region` live in
`~/.config/newrelic-cli/config.yml` alongside `credential_ref` and optional
`keyring.backend`.

Credential ingress is through `nrq init` or `nrq set-credential`, using stdin,
`--from-env` style inputs, or interactive no-echo prompts. `nrq me` is the
scripted verification command for key/account access.

Shared credential, state, and scriptability policy:

```md
Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/working-with-secrets.md
Local convenience copy, if present: `../cli-common/docs/working-with-secrets.md`

Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/working-with-state.md
Local convenience copy, if present: `../cli-common/docs/working-with-state.md`

Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/scriptability.md
Local convenience copy, if present: `../cli-common/docs/scriptability.md`
```

## Environment Variables

- `NEWRELIC_API_KEY` - setup ingress only for `init` / `set-credential`
  `--from-env`; not read at runtime.
- `NEWRELIC_ACCOUNT_ID` - non-secret runtime override and init ingress target.
- `NEWRELIC_REGION` - non-secret runtime override.
- `NEWRELIC_CLI_KEYRING_BACKEND` - backend selector.
- `NEWRELIC_CLI_KEYRING_PASSPHRASE` - file-backend passphrase for headless use.

## Shared Repo Standards

Use these sources for shared repository policy. Do not copy their mechanics into
this guide.

```md
Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/command-surface.md
Local convenience copy, if present: `../cli-common/docs/command-surface.md`

Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/repo-layout.md
Local convenience copy, if present: `../cli-common/docs/repo-layout.md`

Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/ci.md
Local convenience copy, if present: `../cli-common/docs/ci.md`

Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/release.md
Local convenience copy, if present: `../cli-common/docs/release.md`

Source of truth: https://github.com/open-cli-collective/cli-common/blob/main/docs/distribution.md
Local convenience copy, if present: `../cli-common/docs/distribution.md`
```

## Shared Automation

Use `open-cli-collective/.github` for shared action and reusable workflow
implementations.

```md
Source of truth: https://github.com/open-cli-collective/.github
Local convenience copy, if present: `../.github`
```

## Dependencies

- `github.com/open-cli-collective/cli-common` - shared credential storage.
- `github.com/spf13/cobra` - command framework.
- `github.com/fatih/color` - terminal color support.
- `github.com/stretchr/testify` - test assertions.
