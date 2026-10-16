# Documentation coverage

Research snapshot: 2026-10-16T19:50:32.891142+00:00. Retrieved 1257 pages: 573 archive, 410 current, 274 translation.

The catalog contains 552 typed operations across 46 groups. 17 entries are unavailable because the vendor documentation does not establish usable 14.x syntax.

Retrieval, extraction, and live verification are separate statuses. All source text was fetched and scanned; core CLI grammar, parameter relationships, activation commands, and known malformed examples were reviewed during implementation. This does not establish complete GUI parity or live interoperability for every catalog entry.

The complete page inventory is in [wiki-manifest.json](wiki-manifest.json). [feature-matrix.json](feature-matrix.json) maps current guides and command references to catalog entries or records them as retrieved guides needing further reconciliation. Original wiki text and rendered HTML remain in the ignored local cache.

| Command group | Typed operations |
| --- | ---: |
| `alertingcenter` | 15 |
| `appmgmt` | 9 |
| `captiveportal` | 5 |
| `cert` | 23 |
| `clientlessvpn` | 9 |
| `cluster` | 5 |
| `ctproxy` | 1 |
| `debug` | 9 |
| `dhcp` | 21 |
| `diagnostics` | 1 |
| `dns` | 12 |
| `extc` | 25 |
| `geolocation` | 2 |
| `httpproxy` | 4 |
| `interface` | 31 |
| `ipsec` | 13 |
| `mail` | 53 |
| `manager` | 3 |
| `model` | 1 |
| `node` | 12 |
| `nwkview` | 1 |
| `oauth` | 9 |
| `object` | 3 |
| `openvpn` | 19 |
| `pkey` | 5 |
| `qos` | 4 |
| `route` | 7 |
| `rproxy` | 12 |
| `rsa` | 5 |
| `rule` | 22 |
| `server` | 4 |
| `service` | 11 |
| `spdmsimd` | 3 |
| `spf2bd` | 6 |
| `ssh` | 6 |
| `syslog` | 8 |
| `system` | 102 |
| `tcpdump` | 6 |
| `usc_vhost` | 3 |
| `user` | 23 |
| `userbulk` | 1 |
| `view` | 2 |
| `webfilter` | 12 |
| `wgmodel` | 7 |
| `wireguard` | 12 |
| `wlan` | 5 |

## Execution gaps

- `cert import`: The wiki marks this interactive syntax as obsolete since firmware 11.4; validate on 14.x first. ([source](https://wiki.securepoint.de/index.php?title=CLI%2FCert&oldid=86422)).
- `debug show`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `debug validate`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `mail dkimsign domain delete`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `mail dkimsign domain new`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `mail dkimsign domain set`: The wiki supplies neither parameters nor an example. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FCLI%2FMail&oldid=98434)).
- `mail dkimsign header delete`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `mail dkimsign selector delete`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `mail dkimsign selector new`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `mail dkimsign selector set`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `oauth account delete`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `oauth account new`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `oauth account set`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `oauth user delete`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `rule transparent add`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `rule transparent delete`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).
- `rule transparent set`: Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FEXTRAS%2FCLI&oldid=98768)).

Interactive editors, undocumented internal setup commands, and arbitrary Linux shell commands are excluded. Template content is managed with `extc template set`; documented EXTC variables provide the appliance application configuration interface. Portal-owned configuration, hardware installation, hypervisor setup, and client-side VPN installation are outside the local appliance management interface.

## Verification boundary

Read-only MCP verification on firmware 14.1.5 passed 27 command checks. The appliance advertises 564 commands in JSON session mode. Only exact read operations tested on that firmware are marked live-verified. No configuration write, firmware action, restore, file upload, or secret export was attempted.

Mutations require both `read_only=false` and `allow_unverified=true`; this is an explicit operator opt-in to documentation-derived behavior. All mutations remain live-unverified.

Before declaring full UTM management verified, resolve the unavailable schemas and the unmapped guide entries against a 14.x test appliance, exercise each operation family, and capture sanitized transcripts. There is no automatic claim of full support based on a matching help entry alone.
