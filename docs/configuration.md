# Configuration

Start with `configs/sp-utm.example.toml` and `configs/mikrotik.example.toml`. Copy them to `.local/sp-utm.toml` and `.local/mikrotik.toml`, then edit the local copies. Each binary reads only its own configuration. These are also the default config paths for `sp-utm-mcp` and `mikrotik-mcp`; pass `--config PATH` to choose another file. Relative paths are resolved against that config file. Keep `.local/`, credentials, keys, and real appliance configurations out of version control.

The Securepoint example refers to `known_hosts/sp-utm`, relative to `.local/sp-utm.toml`. Before using SSH, create that file and install the UTM's verified SSH host key in it. Verify the host key fingerprint through a trusted channel before adding it. The example credentials are environment variable names; set their values outside the config file.

## Profiles

Both formats define top-level `groups`, `[server]`, `[server.http]`, and `[profiles.NAME]` groups. Profile fields include `host`, `port`, `username`, `password_env`, `read_only`, `timeout_seconds`, `max_output_bytes`, and optional `groups`. Profiles default to read-only; credentials are never tool arguments. Use environment variables such as `SP_UTM_HQ_PASSWORD`, `SP_UTM_BRANCH_PASSWORD`, `MIKROTIK_HQ_PASSWORD`, and `MIKROTIK_BRANCH_PASSWORD` for passwords.

Securepoint profiles can also configure `known_hosts`, `key_file`, `key_passphrase_env`, `ssh_agent`, `root_cli`, `json_output`, and separately permissioned diagnostics, sensitive exports, file transfer, lifecycle operations, and unverified catalog operations. SSH host keys are verified. Root/support CLI and SFTP are optional. SFTP uploads are staged in the restricted remote directory `/tmp/sp-utm-mcp`.

MikroTik profiles can set `ca_file` to add a PEM trust certificate; otherwise the system trust store is used. The connection is HTTPS and certificate validation remains enabled.

## HTTP transport

Set `[server].transport = "http"` or use `--transport http`; stdio is the default. The common `[server.http]` fields are `listen`, `token`, `token_env`, `allowed_hosts`, `allowed_origins`, `tls_cert_file`, `tls_key_file`, and `max_request_bytes`.

Defaults are `127.0.0.1:8080` with token environment variable `SP_UTM_MCP_HTTP_TOKEN` for Securepoint, and `127.0.0.1:8081` with `MIKROTIK_MCP_HTTP_TOKEN` for MikroTik. The default request limit is 16 MiB. A nonempty inline `token` takes precedence over `token_env`; otherwise the server reads the named environment variable when starting HTTP. Tokens must contain 32–4096 ASCII bearer-token characters. Offline checks do not require token values.

Non-loopback listeners require both TLS certificate and key paths (TLS 1.2 minimum). Wildcard listeners also require an explicit `allowed_hosts` list. `allowed_origins` contains exact `http` or `https` origins without paths. A same-origin browser request is accepted without adding that origin to the list; cross-origin requests need an exact allowlist entry. Non-browser MCP clients may omit `Origin`.

The shared listener serves stateless JSON Streamable HTTP at `POST /mcp`. `GET /healthz` returns `{"status":"ok"}` after bearer authentication. Every non-preflight request must use exactly one valid bearer `Authorization` header; missing or invalid credentials return **401**. Invalid or duplicate `Origin` headers and hosts outside `allowed_hosts` return **403**. A valid browser preflight to `/mcp` allows only POST and the documented MCP/content/auth headers; it returns **204** without bearer authentication. A preflight asking for another method returns **405**. Other paths require authentication and are then handled by the HTTP router. The server caps MCP request bodies at the configured limit and complete `/mcp` JSON responses at 64 MiB. It configures a 16 KiB maximum header parsing size, a 5-second header-read timeout, a 30-second request-read timeout, and a 60-second idle timeout. The header parsing setting is not a precise total wire-header size guarantee. The endpoint sets `Cache-Control: no-store`; shutdown allows up to 10 seconds for active requests before forced close.

Both servers advertise static tool catalogs, and Securepoint also exposes a static resource catalog; catalogs are fixed at startup. HTTP is stateless JSON only, with no list-change notifications or SSE notification subscriptions.

A token grants access as the server's shared administration principal: there is no OAuth or multi-user isolation. Use separate secrets for the two servers. A response-size failure returns **500** and warns that a requested change may already have applied; clients must check device state before considering any retry.

## CLI

Both binaries support `--version`, `--catalog`, `--check`, `--discover PROFILE`, `--config PATH`, and `--transport stdio|http`. `--check` validates local configuration and catalog information without connecting to an appliance. `--discover` performs read-only device discovery and therefore requires a reachable device and valid profile credentials.
