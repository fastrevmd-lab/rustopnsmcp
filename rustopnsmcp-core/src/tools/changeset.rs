//! Change-set lifecycle tools for OPNsense firewall aliases and filter
//! rules.
//!
//! OPNsense's alias and filter controllers have no candidate configuration,
//! no dry-run validation, and no checkpoint to roll back to. The seven tools
//! below implement the change-control lifecycle — plan, digest, human
//! approve, apply with drift check — over that immediate-write REST API as a
//! best-effort approximation, with explicit honesty about what cannot be
//! guaranteed. Each change set stages mutations against exactly one resource
//! kind; see [`crate::changeset::ResourceKind`].

use crate::changeset::ResourceKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Tool descriptions for all seven change-set tools.
pub const DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "opnsense_create_change_set",
        "Creates a new change set for firewall alias or filter rule writes. Returns the \
         change set ID. Nothing is staged yet; stage into it with opnsense_stage_change.",
    ),
    (
        "opnsense_stage_change",
        "Stages one or more alias or filter rule creates, updates, or deletes into an \
         existing change set. All mutations in one change set must target the same resource \
         kind. Each change is recorded as a planned mutation against live configuration. \
         OPNsense writes each resource to config.xml immediately but does not load it into \
         the live pf tables/ruleset until apply, so staging is a planning step: it snapshots \
         the current resource state as a pre-image and defers the actual writes until apply.",
    ),
    (
        "opnsense_diff_change_set",
        "Returns a diff showing what applying the change set would do, based on the staged \
         changes and the pre-image captured at staging time. OPNsense has no candidate to \
         diff against running configuration, so this is a projection of the planned \
         mutations, not a device-generated diff.",
    ),
    (
        "opnsense_validate_change_set",
        "Validates the change set as far as possible without applying it. OPNsense has no \
         server-side dry-run validation for aliases or filter rules, so this performs \
         client-side checks only: pre-image coverage and writable-field constraints. It \
         cannot detect validation failures the device would report on the write itself.",
    ),
    (
        "opnsense_approve_change_set",
        "Approves a change set for apply. Requires approval by a different principal than \
         the one who created the set (two-person control); in lab mode the owner may waive \
         that, and the waiver is recorded as a waiver rather than as an approval. The \
         approval binds to the digest of the plan and of the preview the approver read, so \
         a change set that moves on afterwards cannot spend it. Pass expected_digest to bind \
         the approval to the plan you actually read.",
    ),
    (
        "opnsense_apply_change_set",
        "Applies the staged writes as a sequence of independent REST calls, then loads them \
         into the live pf tables/ruleset with a single reconfigure/apply call. OPNsense has \
         no candidate configuration and applies each resource one request at a time, so a \
         partial failure is a reachable outcome and is recorded as partial. Rollback replays \
         a stored pre-image and is best-effort; it can itself fail.",
    ),
    (
        "opnsense_get_change_set",
        "Returns the current status and contents of a change set: draft, planned, approved, \
         applying, applied, failed, or expired. Includes the fingerprint, staged changes, \
         any apply outcome, and the preview the approver read.",
    ),
];

/// Arguments for `opnsense_create_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// A human-readable description of this change set.
    pub description: String,
}

/// Arguments for `opnsense_stage_change`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StageChangeArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to stage into.
    pub change_set_id: String,
    /// The mutations to stage, all against the same resource kind.
    pub mutations: Vec<MutationSpec>,
}

/// A mutation specification for staging, addressed to one firewall alias or
/// filter rule.
///
/// All mutations in a `mutations` list must share the same `resource`; a
/// change set stages exactly one resource kind at a time (see
/// `crate::changeset::validate::check_single_resource_kind`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutationSpec {
    /// Create a new resource.
    Create {
        /// Which resource controller this mutation targets.
        resource: ResourceKind,
        /// The resource body: for an alias, at minimum `name` and `type`;
        /// for a rule, at minimum `action` and `interface`.
        body: serde_json::Value,
    },
    /// Update an existing resource.
    Update {
        /// Which resource controller this mutation targets.
        resource: ResourceKind,
        /// The resource UUID.
        uuid: String,
        /// The fields to change.
        body: serde_json::Value,
    },
    /// Delete an existing resource.
    Delete {
        /// Which resource controller this mutation targets.
        resource: ResourceKind,
        /// The resource UUID.
        uuid: String,
    },
}

/// Arguments for `opnsense_diff_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to diff.
    pub change_set_id: String,
}

/// Arguments for `opnsense_validate_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidateChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to validate.
    pub change_set_id: String,
}

/// Arguments for `opnsense_approve_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to approve.
    pub change_set_id: String,
    /// The plan digest the approver read, as `opnsense_get_change_set`
    /// reports it.
    ///
    /// Optional, and supplying it is what makes the approval attest to a
    /// specific plan: the approval is refused if the change set has moved on
    /// since it was read. Omitting it approves whatever the record holds
    /// when the call lands.
    #[serde(default)]
    pub expected_digest: Option<String>,
}

/// Arguments for `opnsense_apply_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to apply.
    pub change_set_id: String,
}

/// Arguments for `opnsense_get_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetChangeSetArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// The change set ID to retrieve.
    pub change_set_id: String,
}
