//! Mapping an OPNsense alias change set onto `mecmcp-changeset`'s record.
//!
//! The shared crate owns the lifecycle — the transition policy, the
//! claim-before-apply, the preview-bound approval — and stores a change set
//! as an owner, a device, an expected fingerprint, and an ordered list of
//! opaque `actions`. What does not map onto a field of its own is the staged
//! mutations and the pre-image they were planned against, so both go into
//! `actions`, one [`StagedAction`] per mutation.

use crate::changeset::{Preimage, StagedMutation};
use crate::error::OpnsenseError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One entry of a change set's `actions`.
///
/// A mutation and the alias it was planned against, kept together so neither
/// can be swapped for the other's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedAction {
    /// The planned mutation.
    pub mutation: StagedMutation,
    /// The alias body as it stood when the mutation was staged.
    ///
    /// Absent for a create, which has no prior state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<Value>,
}

/// Pair each mutation with its pre-image entry, in staging order.
#[must_use]
pub fn actions_for(mutations: &[StagedMutation], preimage: &Preimage) -> Vec<StagedAction> {
    mutations
        .iter()
        .map(|mutation| StagedAction {
            mutation: mutation.clone(),
            preimage: mutation.resource_uuid().and_then(|uuid| preimage.get(uuid)),
        })
        .collect()
}

/// Read the actions back off a stored record.
///
/// # Errors
///
/// Returns [`OpnsenseError::Malformed`] if an action is not a
/// [`StagedAction`]. The state file is the server's own, so this is
/// corruption or a version mismatch rather than caller input, and it must not
/// be read as an empty plan — an empty plan would apply cleanly and change
/// nothing while reporting success.
pub fn actions_of(actions: &[Value]) -> Result<Vec<StagedAction>, OpnsenseError> {
    actions
        .iter()
        .enumerate()
        .map(|(position, action)| {
            serde_json::from_value(action.clone()).map_err(|error| {
                OpnsenseError::Malformed(format!(
                    "change set action {position} is not a staged action: {error}"
                ))
            })
        })
        .collect()
}

/// The mutations a stored record plans, in staging order.
///
/// # Errors
///
/// As [`actions_of`].
pub fn mutations_of(actions: &[Value]) -> Result<Vec<StagedMutation>, OpnsenseError> {
    Ok(actions_of(actions)?
        .into_iter()
        .map(|action| action.mutation)
        .collect())
}

/// The pre-image a stored record was planned against.
///
/// # Errors
///
/// As [`actions_of`].
pub fn preimage_of(actions: &[Value]) -> Result<Preimage, OpnsenseError> {
    Ok(Preimage::from_resources(
        actions_of(actions)?
            .into_iter()
            .filter_map(|action| action.preimage)
            .collect(),
    ))
}

/// The fingerprint of the alias state a plan was built against.
///
/// OPNsense's alias controller has no candidate database, so there is no
/// candidate to fingerprint. What the shared crate needs from
/// `expected_candidate_fingerprint` is a value that changes when the state
/// the plan assumed changes, and for a live-write vendor that is the
/// pre-image. Fingerprinting it gives the lifecycle the staleness check the
/// vendor does not provide.
///
/// An empty plan fingerprints the empty pre-image rather than failing: a
/// change set exists before anything is staged into it.
///
/// # Errors
///
/// Returns [`OpnsenseError::Malformed`] if the actions cannot be serialized.
pub fn fingerprint_of(actions: &[StagedAction]) -> Result<String, OpnsenseError> {
    let entries: Vec<&Value> = actions
        .iter()
        .filter_map(|action| action.preimage.as_ref())
        .collect();

    let encoded = serde_json::to_vec(&entries).map_err(|error| {
        OpnsenseError::Malformed(format!("could not fingerprint the pre-image: {error}"))
    })?;

    Ok(format!(
        "sha256:{}",
        mecmcp_changeset::digest::digest_hex(&encoded)
    ))
}

#[cfg(test)]
mod tests {
    use super::{actions_for, fingerprint_of, mutations_of, preimage_of};
    use crate::changeset::{Preimage, ResourceKind, StagedMutation};
    use serde_json::json;

    fn live_alias() -> Preimage {
        Preimage::from_resources(vec![json!({
            "uuid": "dddddddddddddddddddddddd",
            "name": "live_alias",
            "content": "10.0.0.0/24"
        })])
    }

    fn plan() -> Vec<StagedMutation> {
        vec![
            StagedMutation::update(
                ResourceKind::Alias,
                "dddddddddddddddddddddddd",
                json!({ "content": "10.0.0.0/23" }),
            ),
            StagedMutation::create(ResourceKind::Alias, json!({ "name": "new_alias" })),
        ]
    }

    /// The record is the only place the plan lives, so what goes in has to
    /// come back out -- mutations, order, and the pre-image each was planned
    /// against.
    #[test]
    fn a_plan_round_trips_through_the_actions() {
        let actions = actions_for(&plan(), &live_alias());
        let stored: Vec<serde_json::Value> = actions
            .iter()
            .map(|action| serde_json::to_value(action).expect("serialize"))
            .collect();

        assert_eq!(mutations_of(&stored).expect("read back"), plan());

        let recovered = preimage_of(&stored).expect("read back");
        assert!(
            recovered.get("dddddddddddddddddddddddd").is_some(),
            "the update's pre-image entry was lost"
        );
    }

    /// A create has no prior state. Recording one anyway would make rollback
    /// restore an alias that never existed instead of deleting it.
    #[test]
    fn a_create_carries_no_preimage() {
        let actions = actions_for(&plan(), &live_alias());
        assert!(actions[1].preimage.is_none(), "{:?}", actions[1]);
        assert!(actions[0].preimage.is_some(), "{:?}", actions[0]);
    }

    /// The state file is the server's own. An unreadable action is corruption
    /// or a version mismatch, and reading it as an empty plan would apply
    /// nothing and report success.
    #[test]
    fn an_unreadable_action_is_an_error_not_an_empty_plan() {
        let stored = vec![json!({ "not": "a staged action" })];
        let error = mutations_of(&stored).expect_err("this is not a staged action");
        assert!(error.to_string().contains("action 0"), "{error}");
    }

    /// The fingerprint stands in for a candidate OPNsense's alias API does not
    /// have. It has to move when the state the plan assumed moves, or the
    /// staleness check the lifecycle performs at apply is vacuous.
    #[test]
    fn the_fingerprint_follows_the_preimage() {
        let before = fingerprint_of(&actions_for(&plan(), &live_alias())).expect("fingerprint");

        let drifted = Preimage::from_resources(vec![json!({
            "uuid": "dddddddddddddddddddddddd",
            "name": "live_alias",
            "content": "10.0.0.0/16"
        })]);
        let after = fingerprint_of(&actions_for(&plan(), &drifted)).expect("fingerprint");

        assert_ne!(before, after, "the fingerprint ignored the drift");
    }

    /// And it must satisfy the shared crate's format check, or every insert is
    /// refused.
    #[test]
    fn the_fingerprint_is_in_the_format_the_lifecycle_requires() {
        let fingerprint = fingerprint_of(&actions_for(&plan(), &live_alias())).expect("f");
        mecmcp_changeset::digest::validate_fingerprint(&fingerprint)
            .expect("the lifecycle must accept the fingerprint we mint");
    }

    /// A change set exists before anything is staged into it, so the empty
    /// plan has to fingerprint rather than fail.
    #[test]
    fn an_empty_plan_still_fingerprints() {
        let fingerprint = fingerprint_of(&[]).expect("an empty plan fingerprints");
        mecmcp_changeset::digest::validate_fingerprint(&fingerprint).expect("valid format");
    }
}
