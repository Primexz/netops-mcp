# Testing and catalog maintenance

## Offline verification

Install Go 1.26, Python 3, and [golangci-lint v2.12.2](https://golangci-lint.run/docs/welcome/install/local/), matching CI. Run `make fmt` to format Go source with the standard `go fmt` command. `make fmt-check` checks formatting without changing files; `.golangci.yml` also selects `gofmt` as its formatter.

Run `make verify` after implementation changes. The Makefile target checks formatting, runs `make lint` with golangci-lint, `go test -race ./...`, Python research tests, `go vet ./...`, offline `--check` in stdio and HTTP configuration modes for both example configs, and builds both binaries. Offline checks do not need appliance passwords or network access. Tests use offline fixtures and local test servers; no appliance credentials are required.

Linting uses golangci-lint's version 2 configuration with its standard correctness checks plus HTTP response cleanup, error wrapping, modern Go idioms, nil-error checks, and explained, specific `nolint` directives. CI validates the entire codebase and uses the same lint and formatting commands as local development.

The Verify workflow runs six independent jobs in parallel: formatting, lint, race-enabled tests, vet and configuration checks, native builds, and cross-builds. Each job reports its own result, so failures in one check do not prevent the other checks from running. Locally, `make verify` runs formatting, lint, tests, checks, and native builds together; `make cross-build` runs the cross-builds.

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

Securepoint catalog research requires Python 3; MikroTik generation is implemented in Go. Working caches and artifacts belong under ignored `.cache/<vendor>`. Reviewed embedded source data is under `internal/<vendor>/catalog`; human-authored vendor guides are under `docs/<vendor>`. Use the vendor documentation as the source of support and preserve unavailable documentation entries.

## Automated catalog updates

The `.github/workflows/update-catalogs.yml` workflow runs every Monday at 06:23 UTC and supports **Actions → Update catalogs → Run workflow**. Its matrix refreshes Securepoint and MikroTik independently from `develop`, retrieves fresh public documentation without restoring a research cache, and runs `make verify` before proposing changes. A failed vendor job does not cancel the other vendor.

The workflow maintains one PR per vendor on `chore/catalog-securepoint` and `chore/catalog-mikrotik`, targeting `develop`. Repeated runs update the existing PR; changes are never merged automatically. Only each vendor's generated catalog and coverage files are included. Raw downloaded documentation, credentials, and local configuration are excluded. Vendor jobs are serialized across workflow runs to avoid concurrent updates to the same PR branch.

Identical upstream documentation retains the published snapshot's retrieval dates, so a refresh without source changes produces no PR. MikroTik matches sources by URL, version, and content hash; Securepoint compares complete page metadata, including revisions, hashes, links, and retrieval failures. Real source changes remain reviewable. Fresh fetch dates remain in MikroTik's ignored research cache and the workflow logs rather than creating timestamp-only commits.

In **Settings → Actions → General → Workflow permissions**, enable **Allow GitHub Actions to create and approve pull requests**. The workflow grants its update jobs `contents: write` and `pull-requests: write` and uses `GITHUB_TOKEN` by default. See the [create-pull-request permissions guidance](https://github.com/peter-evans/create-pull-request#workflow-permissions).

The refresh job runs full verification before opening the PR. For PRs created with `GITHUB_TOKEN`, GitHub starts the ordinary PR workflow in an approval-required state: a maintainer must select **Approve workflows to run** before the six required checks run. This is GitHub's [bot-workflow approval policy](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow), separate from approving a code review. Manually dispatched workflow checks do not satisfy [PR ruleset requirements](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks#checks-from-some-workflow-jobs-are-not-evaluated).

For automatic PR checks without that approval prompt, configure the optional `CATALOG_PR_TOKEN` secret with a GitHub App or personal access token that can write repository contents and pull requests, following the action's [workflow-triggering guidance](https://github.com/peter-evans/create-pull-request/blob/main/docs/concepts-guidelines.md#triggering-further-workflow-runs). No appliance credentials are needed for catalog refreshes.

## Protected branches

`develop` is the default integration branch and the target for feature, fix, and catalog changes. `master` contains production code. Promote changes from `develop` to `master`, and bring production hotfixes back into `develop`. The owner account `Primexz` can push directly to any branch, including `develop` and `master`, without a pull request or waiting for GitHub checks. Run `make verify` locally before pushing implementation changes; the Verify workflow still runs on every push.

For other contributors, both branches require a pull request, an up-to-date branch, resolved review threads, and all six Verify checks from GitHub Actions. The production and integration rulesets grant only `Primexz` an always-allowed bypass for those requirements. A separate history ruleset blocks force pushes and branch deletion on `develop` and `master` for everyone, including the owner. A second person's approval is optional for the current solo-maintainer setup.

The applied GitHub ruleset definitions are stored in `.github/rulesets/master.json`, `.github/rulesets/develop.json`, and `.github/rulesets/history.json`. Changes to these files document the intended policy; applying a ruleset update in GitHub requires repository administration access.
