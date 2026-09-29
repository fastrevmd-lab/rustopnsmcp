//! The MCP tool surface.
//!
//! Phase 1 covered nine read tools, one per resource. Phase 2a adds seven
//! change-set lifecycle tools that govern writes to firewall aliases;
//! firewall rules follow in a later phase.

pub mod changeset;
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
    "opnsense_create_change_set",
    "opnsense_stage_change",
    "opnsense_diff_change_set",
    "opnsense_validate_change_set",
    "opnsense_approve_change_set",
    "opnsense_apply_change_set",
    "opnsense_get_change_set",
];

/// The mutating tools, passed to `mecmcp_server::authorize_call`.
///
/// All seven change-set tools: none of them is a wildcard for "read" scope,
/// including the read-shaped `opnsense_diff_change_set`,
/// `opnsense_validate_change_set`, and `opnsense_get_change_set` — they
/// expose a plan's contents and preview, which a read-only caller has no
/// business seeing before an owner or approver does.
pub const WRITE_TOOLS: &[&str] = &[
    "opnsense_create_change_set",
    "opnsense_stage_change",
    "opnsense_diff_change_set",
    "opnsense_validate_change_set",
    "opnsense_approve_change_set",
    "opnsense_apply_change_set",
    "opnsense_get_change_set",
];
