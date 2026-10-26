# Documentation coverage

Research snapshot: 2026-10-26T13:18:55.822807+00:00. Retrieved 1257 pages: 573 archive, 410 current, 274 translation.

The catalog contains 474 typed operations across 37 groups. 3 entries are unavailable because the vendor documentation does not establish usable 14.x syntax.

The vendor wiki is the source of support for catalog operations. All source text was fetched and scanned; core CLI grammar, parameter relationships, activation commands, and known malformed examples were reviewed during implementation. Entries with incomplete or obsolete syntax remain unavailable.

The complete page inventory is in [wiki-manifest.json](wiki-manifest.json). [feature-matrix.json](feature-matrix.json) maps current guides and command references to catalog entries or records them as retrieved guides needing further reconciliation. Original wiki text and rendered HTML remain in the ignored local cache.

| Command group | Typed operations |
| --- | ---: |
| `alertingcenter` | 12 |
| `appmgmt` | 9 |
| `captiveportal` | 5 |
| `cert` | 23 |
| `clientlessvpn` | 9 |
| `cluster` | 3 |
| `debug` | 6 |
| `dhcp` | 17 |
| `diagnostics` | 1 |
| `dns` | 7 |
| `extc` | 25 |
| `geolocation` | 2 |
| `interface` | 31 |
| `ipsec` | 12 |
| `mail` | 36 |
| `manager` | 3 |
| `node` | 12 |
| `object` | 3 |
| `openvpn` | 19 |
| `pkey` | 5 |
| `qos` | 4 |
| `route` | 7 |
| `rproxy` | 12 |
| `rsa` | 5 |
| `rule` | 18 |
| `server` | 4 |
| `service` | 11 |
| `spf2bd` | 6 |
| `ssh` | 6 |
| `syslog` | 8 |
| `system` | 96 |
| `usc_vhost` | 3 |
| `user` | 23 |
| `view` | 2 |
| `webfilter` | 12 |
| `wireguard` | 12 |
| `wlan` | 5 |

## Execution gaps

- `cert import`: The wiki marks this interactive syntax as obsolete since firmware 11.4 and supplies no current 14.x syntax. ([source](https://wiki.securepoint.de/index.php?title=CLI%2FCert&oldid=86422)).
- `mail dkimsign domain set`: The wiki supplies neither parameters nor an example. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FCLI%2FMail&oldid=98434)).
- `mail fetch map set`: The wiki leaves mapping parameters unspecified. ([source](https://wiki.securepoint.de/index.php?title=UTM%2FCLI%2FMail&oldid=98434)).

Interactive editors, undocumented internal setup commands, and arbitrary Linux shell commands are excluded. Template content is managed with `extc template set`; documented EXTC variables provide the appliance application configuration interface. Portal-owned configuration, hardware installation, hypervisor setup, and client-side VPN installation are outside the local appliance management interface.

## Catalog policy

Catalog operations and parameter schemas are based on the vendor wiki. Configuration changes require `read_only=false`, plan execution, and any applicable lifecycle or sensitive-data permissions. Documentation gaps remain explicit in the catalog and coverage report.
