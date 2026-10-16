# Architecture

The repository is one Go 1.26 module with two independently configured MCP servers, both versioned `0.1.0`. `cmd/sp-utm-mcp` starts the Securepoint server, `cmd/mikrotik-mcp` starts the MikroTik server, and `cmd/mikrotik-cataloggen` generates MikroTik catalog data. Their vendor-specific engines and permissions stay separate. Shared modules are `internal/serverconfig` for configuration, `internal/mcphttp` for HTTP behavior, `internal/mcpschema` for strict MCP schemas, and `internal/buildinfo` for version information.

Both servers register finite, schema-validated operations from embedded catalog data. Tool arguments select documented operations and values; they do not accept arbitrary shell commands or REST paths. Profiles constrain access by vendor, read-only mode, and optional feature groups. See the [Securepoint](securepoint/architecture.md) and [MikroTik](mikrotik/architecture.md) architecture notes for execution details.

Each binary supports stdio and stateless Streamable HTTP at `/mcp`. HTTP behavior and response limits are described in [configuration](configuration.md#http-transport). A token represents that server's shared administration principal. HTTP does not provide OAuth or multi-user isolation; use separate secrets for the two servers.

## Source and local data

- Vendor documentation and guides live under `docs/<vendor>`; maintenance utilities live under `tools/<vendor>` where applicable.
- Catalog JSON is embedded from `internal/<vendor>/catalog`.
- Catalog research caches and generated working artifacts belong under ignored `.cache/<vendor>` paths.
- Local active configs belong in ignored `.local/`; committed examples are in `configs/`.

Keep credentials, actual device configuration, keys, downloaded documentation, and generated research artifacts out of version control. Relative file paths in configuration resolve from the selected config file; `~/` expansion applies to supported home-relative paths.
