> [!WARNING]
> 🚧 **Under construction — not operational.** `rustopnsmcp` is in early development and is not ready for use. Tools, configuration and APIs will change without notice. Do not deploy it against a real OPNsense firewall.

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
for OPNsense what [`rustjunosmcp`](https://github.com/mechubsec/rustjunosmcp)
does for Junos, [`rustpanosmcp`](https://github.com/mechubsec/rustpanosmcp)
for PAN-OS and [`rustunifimcp`](https://github.com/mechubsec/rustunifimcp)
for UniFi: a curated, scoped, audited MCP surface over one vendor's management
API.

It is built **mecmcp-native**: authentication, transport, audit, policy,
inventory, redaction and change control all come from
[`mecmcp`](https://github.com/mechubsec/mecmcp), the shared Rust foundation.
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
  extended to firewall filter rules, through the same seven change-set
  tools — a change set stages mutations against exactly one resource kind
  (alias or rule) at a time. As with aliases, OPNsense has no candidate
  configuration for filter rules: writes persist to `config.xml`
  immediately and only take effect once `apply` calls the filter
  controller's `apply` endpoint.

None of this has been exercised against a live OPNsense instance yet — every
test here runs against synthetic fixtures. The under-construction banner
above stays until a live-device verification pass has run.

Design and scope: [mecmcp#425](https://github.com/mechubsec/mecmcp/issues/425).

## License

Licensed under [MIT](LICENSE).
