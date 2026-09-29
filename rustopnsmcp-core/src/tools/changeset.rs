//! Change-set lifecycle tools for OPNsense firewall aliases.
//!
//! OPNsense's alias controller has no candidate configuration, no dry-run
//! validation, and no checkpoint to roll back to. The seven tools below
//! implement the change-control lifecycle — plan, digest, human approve,
//! apply with drift check — over that immediate-write REST API as a
//! best-effort approximation, with explicit honesty about what cannot be
//! guaranteed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Tool descriptions for all seven change-set tools.
pub const DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "opnsense_create_change_set",
        "Creates a new change set for firewall alias writes. Returns the change set ID. \
         Nothing is staged yet; stage into it with opnsense_stage_change.",
    ),
    (
        "opnsense_stage_change",
        "Stages one or more alias creates, updates, or deletes into an existing change set. \
         Each change is recorded as a planned mutation against live configuration. OPNsense \
         writes each alias to config.xml immediately but does not load it into the live pf \
         tables until apply, so staging is a planning step: it snapshots the current alias \
         state as a pre-image and defers the actual writes until apply.",
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
         server-side dry-run validation for aliases, so this performs client-side checks \
         only: pre-image coverage and writable-field constraints. It cannot detect \
         validation failures the device would report on the write itself.",
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
        "Applies the staged alias writes as a sequence of independent REST calls, then loads \
         them into the live pf tables with a single reconfigure call. OPNsense has no \
         candidate configuration and applies each alias one request at a time, so a partial \
         failure is a reachable outcome and is recorded as partial. Rollback replays a \
         stored pre-image and is best-effort; it can itself fail.",
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
    /// The alias mutations to stage.
    pub mutations: Vec<MutationSpec>,
}

/// A mutation specification for staging, addressed to one firewall alias.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutationSpec {
    /// Create a new alias.
    Create {
        /// The alias body: at minimum `name` and `type`.
        body: serde_json::Value,
    },
    /// Update an existing alias.
    Update {
        /// The alias UUID.
        uuid: String,
        /// The fields to change.
        body: serde_json::Value,
    },
    /// Delete an existing alias.
    Delete {
        /// The alias UUID.
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
