# Testing and catalog maintenance

## Offline verification

Install Go 1.26 and [golangci-lint v2.12.2](https://golangci-lint.run/docs/welcome/install/local/), matching CI. Run `make fmt` to format Go source with the standard `go fmt` command. `make fmt-check` checks formatting without changing files; `.golangci.yml` also selects `gofmt` as its formatter.

Run `make verify` after implementation changes. The Makefile target checks formatting, runs `make lint` with golangci-lint, `go test -race ./...`, `go vet ./...`, offline `--check` in stdio and HTTP configuration modes for both example configs, and builds both binaries. Offline checks do not need appliance passwords or network access. Do not use production appliances for mutation tests; tests use offline fixtures unless a dedicated write-test device is explicitly configured.

Linting uses golangci-lint's version 2 configuration with its standard correctness checks plus HTTP response cleanup, error wrapping, modern Go idioms, nil-error checks, and explained, specific `nolint` directives. CI validates the entire codebase and uses the same lint and formatting commands as local development.

Run an individual offline configuration/catalog check with:

```sh
go run ./cmd/sp-utm-mcp --config configs/sp-utm.example.toml --check
go run ./cmd/sp-utm-mcp --config configs/sp-utm.example.toml --transport http --check
go run ./cmd/mikrotik-mcp --config configs/mikrotik.example.toml --check
go run ./cmd/mikrotik-mcp --config configs/mikrotik.example.toml --transport http --check
```

`make build` builds both binaries. `make cross-build` builds both for Linux amd64, macOS arm64, and Windows amd64. During stdio serving, stdout is reserved for MCP protocol messages; diagnostics belong on stderr.

## Catalog refresh

Refresh one vendor at a time:

```sh
make research catalog VENDOR=securepoint
make research catalog VENDOR=mikrotik
```

Securepoint catalog research requires Python 3; MikroTik generation is implemented in Go. Working caches and artifacts belong under ignored `.cache/<vendor>`. Reviewed embedded source data is under `internal/<vendor>/catalog`; human-authored vendor guides are under `docs/<vendor>`. Preserve unavailable documentation entries and existing verification evidence. A catalog refresh does not establish live device compatibility.

## Automated catalog updates

The `.github/workflows/update-catalogs.yml` workflow runs every Monday at 06:23 UTC and supports **Actions → Update catalogs → Run workflow**. Its matrix refreshes Securepoint and MikroTik independently from the default branch, retrieves fresh public documentation without restoring a research cache, and runs `make verify` before proposing changes. A failed vendor job does not cancel the other vendor.

The workflow maintains one PR per vendor on `chore/catalog-securepoint` and `chore/catalog-mikrotik`. Repeated runs update the existing PR; changes are never merged automatically. Only each vendor's generated catalog and coverage files are included. Raw downloaded documentation, credentials, device evidence files, and local configuration are excluded. Vendor jobs are serialized across workflow runs to avoid concurrent updates to the same PR branch.

In **Settings → Actions → General → Workflow permissions**, enable **Allow GitHub Actions to create and approve pull requests**. The workflow grants its update jobs `contents: write` and `pull-requests: write` and uses `GITHUB_TOKEN` by default. See the [create-pull-request permissions guidance](https://github.com/peter-evans/create-pull-request#workflow-permissions).

PRs created with `GITHUB_TOKEN` do not trigger ordinary PR workflows, so the refresh job runs full verification before opening the PR. To trigger the separate Verify workflow as well, configure the optional `CATALOG_PR_TOKEN` repository secret with a token allowed to write repository contents and pull requests, following the action's [workflow-triggering guidance](https://github.com/peter-evans/create-pull-request/blob/main/docs/concepts-guidelines.md#triggering-further-workflow-runs). No appliance credentials are needed for catalog refreshes.

## Current device evidence

Securepoint live read evidence covers 27 operations on observed firmware 14.1.5. No Securepoint writes, activation/save actions, or file transfers are verified. MikroTik has no live-router verification. Catalog documentation and offline tests are not proof of live compatibility. See [Securepoint verification](securepoint/verification.md) and the vendor coverage reports for current scope.
