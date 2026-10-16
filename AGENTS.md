# Development guidelines

- Use conventional branch names and Conventional Commits with English subjects and detailed bodies explaining motivation and changes.
- `master` is production; `develop` is the default integration branch. Both require pull requests and all six Verify checks. Do not push directly to either protected branch.
- Pull request descriptions must contain Problem, Cause, and Fix, in that order.
- Apply the Modern Go Guidelines skill before editing Go code.
- Use `make fmt` (`go fmt`) for Go formatting and `make lint` for golangci-lint. Keep the pinned CI lint version aligned with the documented local version.
- Keep credentials, actual configurations, keys, artifacts, and downloaded documentation out of version control.
- Never run mutation tests against production. Tests use offline fixtures; live integration checks are read-only unless a dedicated test device is explicitly configured for write tests.
- Regenerate catalog artifacts through `make research catalog VENDOR=securepoint` or `make research catalog VENDOR=mikrotik`; preserve documentation gaps and existing verification evidence. Do not claim new live verification without device evidence.
- Run `make verify` after implementation changes. Stdout is reserved for MCP protocol messages during stdio serving.
- The project provides two independent servers: sp-utm-mcp and mikrotik-mcp. Shared modules own common configuration and MCP transport behavior; vendor execution and permissions remain in their vendor modules.
- Documentation describes netops-mcp as a standalone project. Do not include migration or predecessor repository history.
