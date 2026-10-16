# Development guidelines

- Use conventional branch names and Conventional Commits with English subjects and detailed bodies explaining motivation and changes.
- `master` is production; `develop` is the default integration branch. The authenticated owner account `Primexz` may push directly to any branch without a pull request or waiting for GitHub checks. Use direct pushes when the user requests a push; run local verification before pushing implementation changes. Other contributors require pull requests and all six Verify checks for `master` and `develop`. Force pushes and deletion remain blocked on both protected branches.
- Pull request descriptions must contain Problem, Cause, and Fix, in that order. Renovate-generated branches, commits, and pull requests use Renovate defaults and are exempt from the manual formatting requirements.
- Apply the Modern Go Guidelines skill before editing Go code.
- Use `make fmt` (`go fmt`) for Go formatting and `make lint` for golangci-lint. Keep the pinned CI lint version aligned with the documented local version.
- Keep credentials, actual configurations, keys, artifacts, and downloaded documentation out of version control.
- Tests use offline fixtures and local test servers; do not run tests against appliances.
- Regenerate catalog artifacts through `make research catalog VENDOR=securepoint` or `make research catalog VENDOR=mikrotik`; use vendor documentation as the source of support and preserve documentation gaps.
- Run `make verify` after implementation changes. Stdout is reserved for MCP protocol messages during stdio serving.
- The project provides two independent servers: sp-utm-mcp and mikrotik-mcp. Shared modules own common configuration and MCP transport behavior; vendor execution and permissions remain in their vendor modules.
- Documentation describes netops-mcp as a standalone project. Do not include migration or predecessor repository history.
