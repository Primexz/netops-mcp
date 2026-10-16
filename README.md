# netops-mcp

netops-mcp provides two independent MCP servers for network administration:

- **sp-utm-mcp** manages Securepoint UTM 14.x appliances over verified SSH. Root/support access and restricted SFTP features are optional. Changes use expiring one-shot plans; review and explicitly execute a plan, then activate and save when the operation requires it.
- **mikrotik-mcp** manages RouterOS 7 over certificate-verified HTTPS REST. Permitted writes take effect immediately. There are no plans, automatic retries, or rollback.

Each server has its own configuration and permissions. Tool namespaces remain `utm_*` and `mikrotik_*`. Profiles are read-only by default, and credentials are loaded from environment variables rather than tool arguments.

## Setup

Requirements: Go 1.26, Python 3, and [golangci-lint](https://golangci-lint.run/docs/welcome/install/local/) v2.12.2. The Go module is `github.com/Primexz/netops-mcp`. Create local configs from the examples, edit profile addresses and settings, then validate and build:

```sh
mkdir -p .local
cp configs/sp-utm.example.toml .local/sp-utm.toml
cp configs/mikrotik.example.toml .local/mikrotik.toml
# Edit the two .local files and set the password environment variables they reference.
make verify
```

The example addresses use documentation-only IP ranges. Replace them with device addresses. Set `SP_UTM_HQ_PASSWORD` / `SP_UTM_BRANCH_PASSWORD` and `MIKROTIK_HQ_PASSWORD` / `MIKROTIK_BRANCH_PASSWORD` as needed. See [configuration](docs/configuration.md) for transport, profiles, secrets, and paths.

Both configs default to stdio. For clients that support HTTP, the two listeners have distinct ports and bearer-token environment variables. Review [HTTP configuration](docs/configuration.md#http-transport) before exposing a listener.

## MCP client configuration

Register each server separately. Replace the absolute paths below with paths on your machine:

```json
{
  "mcpServers": {
    "securepoint-utm": {
      "command": "/absolute/path/to/netops-mcp/bin/sp-utm-mcp",
      "args": ["--config", "/absolute/path/to/netops-mcp/.local/sp-utm.toml"]
    },
    "mikrotik": {
      "command": "/absolute/path/to/netops-mcp/bin/mikrotik-mcp",
      "args": ["--config", "/absolute/path/to/netops-mcp/.local/mikrotik.toml"]
    }
  }
}
```

When building locally, set the executable paths to where your build places the binaries. For stdio, keep standard output reserved for MCP messages.

## Development

`make fmt` formats Go code with `go fmt`. `make lint` runs golangci-lint with the version 2 configuration in `.golangci.yml`. `make verify` checks formatting, runs lint, race-enabled tests, vet, and offline config/catalog checks for stdio and HTTP settings, then builds both servers. `make build` builds both binaries; `make cross-build` builds them for Linux amd64, macOS arm64, and Windows amd64.

The **Update catalogs** workflow refreshes both vendors every Monday at 06:23 UTC, opening or updating a separate PR for each catalog. It can also be run manually from GitHub Actions. See [automation setup](docs/testing.md#automated-catalog-updates) for the required repository permission. Catalog maintenance can also run locally:

```sh
make research catalog VENDOR=securepoint
make research catalog VENDOR=mikrotik
```

The Securepoint refresh requires Python 3; the MikroTik generator is Go. See [testing and maintenance](docs/testing.md), [architecture](docs/architecture.md), and vendor guides under [docs/securepoint](docs/securepoint/) and [docs/mikrotik](docs/mikrotik/).

## License

Licensed under the [MIT License](LICENSE).
