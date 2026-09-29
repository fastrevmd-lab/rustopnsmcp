<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustopnsmcp</h1>

<p align="center"><strong>Enterprise MCP server for OPNsense — curated tools, scoped access, audited change control</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

---

`rustopnsmcp` is the OPNsense member of the mechub MCP server family. It does
for OPNsense what [`rustjunosmcp`](https://github.com/fastrevmd-lab/rustjunosmcp)
does for Junos, [`rustpanosmcp`](https://github.com/fastrevmd-lab/rustpanosmcp)
for PAN-OS and [`rustunifimcp`](https://github.com/fastrevmd-lab/rustunifimcp)
for UniFi: a curated, scoped, audited MCP surface over one vendor's management
API.

It is built **mecmcp-native**: authentication, transport, audit, policy,
inventory, redaction and change control all come from
[`mecmcp`](https://github.com/fastrevmd-lab/mecmcp), the shared Rust foundation.
What lives here is the OPNsense resource model, the tool surface and the
workflows.

## Status

**In development.** Nothing is released yet.

- **Phase 1 — reads:** system status, interfaces, firewall rules and aliases,
  NAT, routes, DHCP leases, gateways, firmware/version. OPNsense REST API with an
  API key and secret from the environment or an owner-only file; TLS always
  verified.
- **Phase 2a — governed writes, aliases:** create/update/delete firewall
  aliases through mecmcp's change sets (plan, digest, human approval, apply
  with a drift check). OPNsense has no candidate configuration, so writes
  persist to `config.xml` immediately and only take effect once `apply`
  calls `reconfigure`; a partial apply is a reachable outcome.
- **Phase 2b — governed writes, firewall rules:** the same lifecycle,
  extended to firewall filter rules. Not yet started.

Design and scope: [mecmcp#425](https://github.com/fastrevmd-lab/mecmcp/issues/425).

## License

Licensed under [MIT](LICENSE).
