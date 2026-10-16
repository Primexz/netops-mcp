# Verification

## Device evidence

Read-only checks through the MCP executable passed for 27 operations on Securepoint firmware 14.1.5. This evidence applies to those exact read operations on the observed firmware. It does not establish other firmware compatibility or write behavior. Help and catalog entries beyond those reads are not live verification.

No Securepoint writes, activation, save, restore, firmware actions, packet capture, file transfer, or sensitive export have been verified on a device. Write interoperability and failure/recovery behavior require a dedicated test UTM; never run mutation tests against production.

## Scope

The server discovers firmware and advertised commands at runtime. When help provides a complete command inventory, operations absent from it are rejected. Abbreviated or incomplete help cannot prove that an operation is unavailable, so the appliance response remains authoritative in that case. An advertised command is not necessarily live-verified. Catalog documentation gaps and unavailable operations remain identified in [coverage](coverage.md).

Offline checks use fixtures and validate local configuration and catalog behavior without contacting an appliance. See [testing guidance](../testing.md) for the repository verification workflow.
