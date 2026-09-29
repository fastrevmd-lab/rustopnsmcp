//! The MCP tool surface.
//!
//! Phase 1 is read-only: nine tools, one per resource this phase covers.
//! Governed writes (aliases, then firewall rules, through mecmcp's
//! change-set lifecycle) are phase 2.

pub mod read;

/// Every tool this server registers.
///
/// Kept in one place so `filter_tools_for_scope` and the registry guard read
/// the same list.
pub const TOOL_NAMES: &[&str] = &[
    "opnsense_system_status",
    "opnsense_firmware_status",
    "opnsense_list_interfaces",
    "opnsense_list_firewall_rules",
    "opnsense_list_aliases",
    "opnsense_list_nat_rules",
    "opnsense_list_routes",
    "opnsense_list_gateways",
    "opnsense_list_dhcp_leases",
];

/// The mutating tools, passed to `mecmcp_server::authorize_call`.
///
/// Empty in phase 1: every registered tool is a read. Left as a named,
/// asserted-empty constant rather than omitted, so `WRITE_TOOLS.is_empty()`
/// is a decision this phase made on purpose — visible in `tests/read_tools.rs`
/// — rather than a fact nobody checked. Phase 2 populates it as change-set
/// tools land, at which point it must never go back to empty by accident: see
/// `mecmcp-server`'s `an_empty_write_tool_registry_lets_a_wildcard_reach_a_write_tool`.
pub const WRITE_TOOLS: &[&str] = &[];
