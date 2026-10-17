# Safe mode

A MikroTik profile can require RouterOS safe mode for all writes. Configuration changes still apply immediately through the profile's selected HTTPS or HTTP REST connection. A persistent SSH shell owns safe mode until an explicit confirmation commits the window. Expiry, an explicit rollback, a failed write, or server shutdown requests rollback. Existing profiles retain immediate-write behavior unless protection is enabled.

## Configuration

Set `read_only = false` on the profile, then add:

```toml
[profiles.headquarters.safe_mode]
required = true
ssh_port = 22
known_hosts = "known_hosts/mikrotik"
timeout_seconds = 300
```

The deadline accepts 30–600 seconds and defaults to 300. The SSH port defaults to 22. The host-key file is mandatory for protected profiles. Relative paths resolve beside the config file, and `~/` expands normally. Verify the router fingerprint independently before installing its key; unknown or changed keys are refused.

SSH uses the profile's host, username, and password environment variable. The account needs SSH login permission alongside its existing REST permissions. Selecting HTTP REST does not change SSH host-key verification or the safe-mode SSH port. SSH keys and separate SSH credentials are not supported. Host-key file contents and password values are checked when opening a window, not by offline `--check`.

## Workflow

1. List profiles and inspect `safe_mode_required` and `safe_mode_timeout_seconds`.
2. Call `mikrotik_safe_mode_begin` with `profile`. Review its `safe_mode_id` and `expires_at`.
3. Include that ID as top-level `safe_mode_id` on every mutation. Existing profile/group/read-only restrictions remain enforced. The ID is never sent as a RouterOS configuration parameter.
4. Verify the affected network behavior. A successful write response alone is insufficient evidence that connectivity and forwarding still work.
5. Call `mikrotik_safe_mode_confirm` with `profile` and `safe_mode_id` before the deadline to keep the changes. Confirmation checks SSH ownership and makes a fresh authenticated REST read.
6. Alternatively call `mikrotik_safe_mode_rollback`, or let the deadline expire. Use `mikrotik_safe_mode_status` with `profile` to inspect local state.

Only one window can be active per profile. IDs cannot be reused after confirmation, rollback, or expiry, or used for another profile. The window survives ordinary MCP request completion, including stateless HTTP requests. HTTP clients share the server's existing administration principal; a window ID prevents accidental mixing of operations, not access by another principal.

State is `inactive` before opening, `active` while changes await confirmation, `committed` only after acknowledged confirmation, `rollback_requested` when rollback has been requested or scheduled, and `uncertain` if ownership/control cannot be verified. Results include `history_actions`; a failed transmitted write also exposes `release_after` when deliberate rollback must wait. These states describe the server's knowledge. Never treat `rollback_requested` as verified restoration or automatically retry a failed mutation.

## Recovery and limits

RouterOS documents that safe mode covers configuration changes from other login sessions. This is the basis for owning safe mode over SSH while making changes over REST. The server uses only fixed control/status commands and refuses unsupported replies or ownership takeover. Offline SSH fixtures paired with HTTP and HTTPS REST servers verify the implementation; they do not certify behavior on every firmware release. [RouterOS console documentation](https://manual.mikrotik.com/docs/management-tools/console/#safe-mode)

Safe mode is router-wide: other administrators' changes, including other profiles or MCP processes addressing the same router, can join the same commit/rollback window. Avoid concurrent administration during a protected window. The server never takes over another owner's safe mode.

RouterOS's history holds approximately 100 actions; overflowing it can exit safe mode without reverting changes. The server checks before and after writes and every five seconds, stops new writes at 80 floating-undo actions, and requests rollback. External changes or one operation creating many history entries can still exceed the limit between checks. Reboot-dependent operations are outside safe-mode protection. [Configuration management limits](https://manual.mikrotik.com/docs/getting-started/configuration-management/#safe-mode)

The server uses Ctrl+D to request rollback, never `/quit`. If SSH is lost, native recovery can be delayed by RouterOS's connection timeout. A lost commit acknowledgement is reported as uncertain even when the router may have kept the changes. Loss of management connectivity is not proof of successful rollback.

REST commands can continue running after their client cancels or times out, up to RouterOS's documented 60-second request limit. After a write error, the server rejects further writes/confirmation and keeps the SSH owner for another 65 seconds before deliberately requesting rollback. Shutdown also waits for outstanding writes and this drain. Unexpected SSH loss during the drain makes recovery uncertain. [REST request lifecycle](https://manual.mikrotik.com/docs/developer-guides/rest-api/#send-parallel-requests-from-separate-users)

After restarting the MCP process, old IDs are invalid. A new window can be opened only if RouterOS no longer reports an existing owner. Check router state before resuming changes after any uncertain outcome.
