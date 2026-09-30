//! OPNsense REST API paths used by phase 1's read tools.
//!
//! OPNsense's core API follows a `/api/<module>/<controller>/<command>`
//! convention (<https://docs.opnsense.org/development/api.html>). The paths
//! below follow that documented convention and the module/controller names
//! OPNsense's own core plugins use, but **none has been exercised against a
//! live OPNsense instance** — this phase has no lab device to verify against,
//! and every test here runs against a synthetic fixture instead. Treat these
//! as the best-effort starting point for phase 2's live-device verification
//! pass, not as a confirmed contract.
//!
//! Search-style endpoints (`search_*`) are OPNsense's paginated list
//! convention: a `POST` with a JSON body (`current`, `rowCount`, `searchPhrase`)
//! and a response shaped `{"rows": [...], "rowCount": N, "total": N, ...}`.

/// System status. Module `core`, controller `system`.
pub const SYSTEM_STATUS: &str = "/api/core/system/status";

/// Firmware and installed-version status. Module `core`, controller `firmware`.
pub const FIRMWARE_STATUS: &str = "/api/core/firmware/status";

/// Interface overview. Module `interfaces`, controller `overview`.
pub const INTERFACES_OVERVIEW: &str = "/api/interfaces/overview/interfacesInfo";

/// Firewall filter rules, paginated search. Module `firewall`, controller `filter`.
///
/// `search_rule` iterates only the MVC ("automation") rule set. Legacy GUI
/// rules are merged in starting with OPNsense 25.1; on 24.7 and earlier this
/// endpoint returns a partial or empty list with nothing in the response to
/// signal the gap.
pub const FIREWALL_RULES_SEARCH: &str = "/api/firewall/filter/search_rule";

/// Firewall aliases, paginated search. Module `firewall`, controller `alias`.
pub const ALIASES_SEARCH: &str = "/api/firewall/alias/search_item";

/// Create a firewall alias. Module `firewall`, controller `alias`.
///
/// Persists to `config.xml` immediately but does not take effect in the live
/// `pf` tables until [`ALIASES_RECONFIGURE`] runs — OPNsense's write API has
/// no discardable candidate, only a write-then-load two-step. A `POST` here
/// can still return HTTP 200 with `{"result": "failed", "validations": {...}}`
/// in the body; a caller must check `result`, not just the status code.
pub const ALIASES_ADD_ITEM: &str = "/api/firewall/alias/addItem";

/// Fetch one firewall alias by UUID. Module `firewall`, controller `alias`.
///
/// # Panics
///
/// Never: `uuid` must already have passed [`crate::client::validate_uuid`]
/// before this is called, since it is interpolated into the path.
#[must_use]
pub fn aliases_get_item(uuid: &str) -> String {
    format!("/api/firewall/alias/getItem/{uuid}")
}

/// Update a firewall alias by UUID. Module `firewall`, controller `alias`.
///
/// Same immediate-persist-but-not-loaded semantics as [`ALIASES_ADD_ITEM`].
#[must_use]
pub fn aliases_set_item(uuid: &str) -> String {
    format!("/api/firewall/alias/setItem/{uuid}")
}

/// Delete a firewall alias by UUID. Module `firewall`, controller `alias`.
#[must_use]
pub fn aliases_del_item(uuid: &str) -> String {
    format!("/api/firewall/alias/delItem/{uuid}")
}

/// Load staged alias definitions from `config.xml` into the live `pf` alias
/// tables. Module `firewall`, controller `alias`.
///
/// This is the closest thing OPNsense's alias API has to a commit: nothing
/// written by [`ALIASES_ADD_ITEM`], [`aliases_set_item`], or
/// [`aliases_del_item`] is live until this runs.
pub const ALIASES_RECONFIGURE: &str = "/api/firewall/alias/reconfigure";

/// Create a firewall filter rule. Module `firewall`, controller `filter`.
///
/// Same immediate-persist-but-not-loaded semantics as [`ALIASES_ADD_ITEM`]:
/// this writes to `config.xml` but has no effect on the live `pf` ruleset
/// until [`FILTER_APPLY`] runs. Targets the MVC ("automation") rule set —
/// see the [`FIREWALL_RULES_SEARCH`] caveat about legacy GUI rules.
pub const FILTER_ADD_RULE: &str = "/api/firewall/filter/addRule";

/// Fetch one firewall filter rule by UUID. Module `firewall`, controller `filter`.
///
/// # Panics
///
/// Never: `uuid` must already have passed [`crate::client::validate_uuid`]
/// before this is called, since it is interpolated into the path.
#[must_use]
pub fn filter_get_rule(uuid: &str) -> String {
    format!("/api/firewall/filter/getRule/{uuid}")
}

/// Update a firewall filter rule by UUID. Module `firewall`, controller `filter`.
///
/// Same immediate-persist-but-not-loaded semantics as [`FILTER_ADD_RULE`].
#[must_use]
pub fn filter_set_rule(uuid: &str) -> String {
    format!("/api/firewall/filter/setRule/{uuid}")
}

/// Delete a firewall filter rule by UUID. Module `firewall`, controller `filter`.
#[must_use]
pub fn filter_del_rule(uuid: &str) -> String {
    format!("/api/firewall/filter/delRule/{uuid}")
}

/// Load staged filter rule changes from `config.xml` into the live `pf`
/// ruleset. Module `firewall`, controller `filter`.
///
/// This is the closest thing OPNsense's filter API has to a commit: nothing
/// written by [`FILTER_ADD_RULE`], [`filter_set_rule`], or [`filter_del_rule`]
/// is live until this runs.
pub const FILTER_APPLY: &str = "/api/firewall/filter/apply";

/// Outbound NAT rules, paginated search. Module `firewall`, controller `source_nat`.
pub const NAT_OUTBOUND_SEARCH: &str = "/api/firewall/source_nat/search_rule";

/// 1:1 NAT rules, paginated search. Module `firewall`, controller `one_to_one`.
///
/// Outbound and 1:1 NAT only. Port forwards (destination NAT) have no
/// covering endpoint here — `DNatController` exists only on core master, not
/// on any released branch this phase targets.
pub const NAT_ONE_TO_ONE_SEARCH: &str = "/api/firewall/one_to_one/search_rule";

/// Static routes, paginated search. Module `routes`, controller `routes`.
pub const ROUTES_SEARCH: &str = "/api/routes/routes/search_route";

/// Gateway status. Module `routes`, controller `gateway`.
pub const GATEWAYS_STATUS: &str = "/api/routes/gateway/status";

/// DHCPv4 leases, paginated search. Module `dhcpv4`, controller `leases`.
///
/// ISC DHCPv4 only. Kea and Dnsmasq leases are not covered; new 25.x installs
/// default to Dnsmasq, and ISC DHCPv4 is gone from core master.
pub const DHCP_LEASES_SEARCH: &str = "/api/dhcpv4/leases/search_lease";

/// Default page size for `search_*` endpoints when a tool call omits one.
pub const DEFAULT_ROW_COUNT: u32 = 200;
