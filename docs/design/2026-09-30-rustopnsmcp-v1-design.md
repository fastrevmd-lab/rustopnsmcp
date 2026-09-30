# rustopnsmcp v1.0 — design

- **Status:** approved by the board, 2026-09-30.
- **Supersedes:** the scope section of mecmcp#425 for v1.0.
- **Implementation plan:** `2026-09-30-rustopnsmcp-v1-plan.md` (same folder).

## 1. Intent

rustopnsmcp becomes a **full-featured** OPNsense MCP server with **feature parity with rustjunosmcp and rustpanosmcp**. To an operator and to an LLM client it must look and behave **exactly like the other mechub MCP servers**:

- the same operating modes, configuration layout, CLI, tool naming and change-set flow;
- mecmcp's shared crates and standards used wherever they apply.

The house rule is unchanged: deterministic code decides, the model explains, a human approves.

**v1.0 is done when all three hold:**

1. **Live-verified** against a real OPNsense lab firewall ("opnsense-lab", 26.7.x). Every tool is exercised, and every governed write is applied and rolled back. Synthetic fixtures alone are not enough.
2. **Released and deployed through the standard pipeline.** The release engineer cuts v1.0.0, and the deploy engineer runs it on a `test-twoperson-opnsense` / `test-labmode-opnsense` pair, then on a production `prod-opnsmcp` instance in lab mode after board approval.
3. **Security review passed**, with no open High or Critical findings. The review covers auth scopes, redaction of OPNsense secrets (API keys, PSKs, private keys, certificates, user hashes) and change-set safety.

**Out of scope for v1.0:**

- plugins, except read-only os-frr routing diagnostics;
- anything specific to Business Edition;
- multi-tenant or central management;
- any device access other than the OPNsense REST API.

## 2. Where the code stands (2026-09-30)

**Present:**

- 9 read tools: system status, firmware status, interfaces, gateways, firewall rules, aliases, NAT (outbound and 1:1), routes, DHCP leases.
- Governed writes for aliases (Phase 2a) and filter rules (Phase 2b), through mecmcp-changeset.
- Already on mecmcp: the shared CLI, auth, transport, SIGHUP reload, sysusers/tmpfiles and a hardened unit.
- Nothing has been exercised against a live OPNsense yet.

**Gaps against the reference servers:**

- **Mixed mecmcp refs.** mecmcp-redact is pinned to a revision that lacks the untrusted-content marking from mecmcp#432; everything else is on v0.24.1.
- **Audit.** Only apply is audited; there is no per-call audit record.
- **Lab-mode waiver.** It is applied at approve, not at creation, which contradicts `docs/PACKAGING.md` §2.
- **Digests.** `expected_digest` is optional on approve and absent on apply.
- **Missing flags.** No `--allow-direct-commit` / `DirectCommitPolicy`, and no `--inventory-readonly`.
- **Flags parsed but ignored:** SSDF evidence, `--approval-digest-key-file`, OTel.
- **Tool naming.** It follows the UniFi style, not the Junos pattern, and there are no fleet-meta tools.
- **Packaging.** No LXC installer or tarball script, no logrotate, no release workflows, no dependabot, and almost no operator docs.
- **Unit file.** It uses placeholders instead of loopback defaults plus a site `override.conf`, and names the state file `changesets.json` instead of `changeset-state.json`.
- **Coverage.** Firewall basics only.

## 3. Conventions contract (what "looks exactly like the others" means)

Every PR is checked against this section.

### 3.1 Tools (as the LLM sees them)

**Fleet meta:**

- `get_device_list`
- `gather_device_facts` (redacted)
- `opnsmcp_status` (server version, endpoint, uptime)
- `add_device` and `reload_devices`, which are refused under `--inventory-readonly`

**Reads:**

- `list_opnsense_<noun>` for collections, e.g. `list_opnsense_firewall_rules`, `list_opnsense_aliases`, `list_opnsense_nat_rules`, `list_opnsense_routes`, `list_opnsense_dhcp_leases`, `list_opnsense_gateways`, `list_opnsense_interfaces`.
- `get_opnsense_<noun>` for single objects or status, e.g. `get_opnsense_firmware_status`, `get_opnsense_system_status`, `get_opnsense_config_backup`.

**Change sets:**

- `get_opnsense_config_fingerprint`
- `create_opnsense_change_set(device, expected_fingerprint, actions[])`
  - Creation and staging happen in one call; there is no separate stage tool.
  - Returns `change_set_id` and `plan_digest`.
  - Under `--lab-mode` the approval is waived automatically at creation. The record shows `approver: null` and `approval_waiver: "lab-mode"`.
- `approve_opnsense_change_set(change_set_id, expected_digest)`
  - `expected_digest` is required.
  - The approver must be a second principal.
- `apply_opnsense_change_set(change_set_id, expected_digest, expected_fingerprint, confirm_timeout_mins?)`
- `confirm_opnsense_change_set(operation_id)`
- `cancel_opnsense_change_set`, `get_opnsense_change_set_status`, `list_opnsense_change_sets`
  - Status and list are read-scope tools, as in rustjunosmcp.

**Direct-commit class.** Each is refused unless `--allow-direct-commit` is set, with audit reason `direct_commit_disabled`:

- `upgrade_opnsense_firmware`: plan unless `confirm=true`; takes a device lease.
- `revert_opnsense_config_backup`
- `update_opnsense_ids_rules`

**Parameters and output:**

- `device` is the canonical parameter.
- `#[serde(deny_unknown_fields)]` everywhere.
- List tools take `limit` and `offset`; large outputs take `max_bytes`.
- Every tool description states its redaction contract.
- Output is JSON, passed through mecmcp-redact, and marked as untrusted device content.
- Errors use the mecmcp error shape.

**Renames.** The current `opnsense_*` names are replaced outright. Nothing has been released, so no aliases are kept.

### 3.2 CLI, files, unit

**CLI:**

- The shared `mecmcp_runtime::cli::Cli`, plus the same server flags as rustjunosmcp:
  - `--lab-mode` (CLI-only, never read from product config)
  - `--allow-direct-commit`
  - `--commit-confirm-default-mins` (default 10)
  - `--approval-timeout-secs` (default **3600**)
  - `--state-file`
  - `--inventory-readonly`
  - `--web-enabled-approver`
- Subcommands: `token …` and `state resolve`.

**Files (mecmcp `docs/FILESYSTEM-LAYOUT.md`):**

- `/etc/rustopnsmcp/`: `devices.json`, `audit-hmac.key`, `credentials.env`, CA certificates.
- `/var/lib/rustopnsmcp/`: `tokens.json`, `changeset-state.json`, `audit.jsonl`.

**devices.json** keeps the current per-device shape:

- endpoint
- API key and secret, from an env var or an owner-only file
- `ca_pem_path`

It adds a mecmcp-policy block, as rustpanosmcp does.

**Unit:**

- Ships loopback-only, with the baseline audit flags: `--audit-format json --audit-journald --audit-redact devices=hmac --audit-hmac-key-file …`.
- Bind address, allowed host and TLS go in a site `override.conf`, documented in `HOW-TO-SETUP-LXC.md`.

### 3.3 Behaviour

- Every call produces a per-call `AuditScope` record.
- All mecmcp crates are pinned to **one** ref, the mecmcp release that contains P0.
- `/readyz` includes an OPNsense API auth readiness check (rustpanosmcp precedent).
- Interrupted or partial applies are reconciled at startup.
- SIGHUP reloads inventory, tokens and audit.
- Rate limits use the mecmcp defaults.

### 3.4 OPNsense semantics (explicit, not hidden)

- **There is no candidate configuration.** Model and API writes persist to config.xml immediately and take effect only when apply calls the controller's `reconfigure`/`apply`. A partial apply is a reachable, reported outcome. Tool descriptions say this.
- **Firewall filter rules** support commit-confirmed with auto-revert, through the filter savepoint/apply/cancelRollback/revert endpoints. For every other resource kind, `confirm_timeout_mins` is **refused**, not ignored.
- Endpoint paths are verified live on the target version. Where a path differs between supported versions, the tool detects the version from firmware info.

## 4. Phases and gates

Each phase lands as PRs through the normal review loop. A phase starts only when the previous gate has passed.

| Phase | Scope | Gate |
|---|---|---|
| **P0 Upstream (mecmcp)** | Add `known::OPNSENSE` to mecmcp-secret naming, and rustopnsmcp to FILESYSTEM-LAYOUT.md. Resolve mecmcp's two internal contradictions: short vs full directory base names, and devices.json 0600 service-owned (code) vs 0640 root:svc (doc). | Merged, and included in a mecmcp release. |
| **P1 Platform parity** | One mecmcp pin. Per-call audit. §3.1 renames and change-set reshape. Lab-mode auto-waiver. Required digests. `--allow-direct-commit`. Wire or remove the ignored flags (evidence, digest key, OTel). Fleet-meta tools. Approval timeout set to 3600. | A parity-check script diffs CLI flags, file paths and tool-name patterns against rustjunosmcp and finds no unexplained differences. Security review of the change-set changes. |
| **P2 Packaging and ops parity** | `packaging/lxc/install.sh`, `scripts/package-lxc.sh`, logrotate, loopback unit plus `override.conf`, `changeset-state.json`. Release workflows (image, signed tarball, SBOM) through the mecmcp reusable workflows at a reachable pin. `security.yml`, dependabot. Docs: HOW-TO-SETUP-LXC, HOW-TO-SETUP-DOCKER, OPERATIONS, AUDIT, METRICS, THREAT-MODEL, packaging/FILESYSTEM, CHANGELOG, CONTRIBUTING, AGENTS. | mecmcp packaging conformance passes. A dry-run install on Debian 13 succeeds. |
| **P3 Live verification** | Exercise every existing tool against opnsense-lab. Apply and roll back each alias and rule change set. Correct endpoint paths. Record sanitized fixtures from the live device. | All tools pass live on 26.7.x. The under-construction banner is removed here. |
| **P4 Read breadth** | Diagnostics: states, ARP/NDP, pf statistics, firewall log, activity. VPN report: IPsec, OpenVPN, WireGuard sessions. CARP/HA status. DHCP: Kea, Dnsmasq, DHCPv6 leases. Unbound overrides and stats. config.xml backup list and diff. Trust/cert expiry report. Read-only users and groups. Pagination. | Each read is live-tested, and its redaction is reviewed. |
| **P5 Write breadth** | Change sets for NAT (port-forward, outbound, 1:1, NPT), static routes, VLANs and VIPs, and DHCP static mappings. Filter-rule commit-confirmed through savepoint/auto-revert, with `--commit-confirm-default-mins`. | Each write is applied, verified and rolled back live. The auto-revert is proven by letting a confirm window lapse. |
| **P6 Direct-commit ops** | Firmware check/update/reboot (plan, then `confirm=true`, with a device lease through mecmcp-device). config.xml backup revert. Suricata rule update. All behind `--allow-direct-commit`. | Each is refused without the flag and works with it, on opnsense-lab. |
| **P7 Release** | Full security review. v1.0.0 release PR, signed tag, artifacts verified. Deploy to the test pair, then production in lab mode after board approval. | Deployed and healthy. |

## 5. Execution and reporting

- **Owner:** Arthur (CEO agent), through one epic, "rustopnsmcp v1.0", with child issues P0–P7. Each child is blocked by its predecessor.
- **Start condition:** after the current backlog. P0 is blocked until the current release train (rustnetconf → rustez → mecmcp) is tagged and the open PR backlog is cleared. Arthur holds the epic until then.
- **Routing (engineering lead):**
  - Design-heavy work (P1, P5, P6) goes to the Rust engineer.
  - Mechanical work (P2 docs and packaging, P3 fixtures) goes to the second engineer, limited to small single-repo tasks.
  - The security reviewer gates P1, P5, P6 and P7.
  - The release engineer and the deploy engineer run P7.
- **Lab device:** "opnsense-lab", a dedicated OPNsense VM with seeded aliases, rules, NAT and DHCP and a `baseline-seeded` snapshot for resets. Its credentials and CA are held owner-only on the development host and are **never committed**. The pre-push secret gate enforces this.
- **Reporting:** one summary per phase gate on the epic: what merged, gate evidence, what's next.
- **Board involvement:**
  - approving this spec and the plan;
  - the mecmcp release tag containing P0;
  - the v1.0.0 tag;
  - the production deploy approval;
  - any scope change (for example, plugin support).
