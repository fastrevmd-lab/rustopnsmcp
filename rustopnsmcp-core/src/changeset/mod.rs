//! Governed writes for OPNsense firewall aliases and filter rules, mapped
//! onto `mecmcp-changeset`'s change-set lifecycle.
//!
//! OPNsense's alias and filter controllers have no candidate configuration,
//! no dry-run validation separate from the write itself, and no checkpoint to
//! roll back to: `addItem`/`setItem`/`delItem` (aliases) and
//! `addRule`/`setRule`/`delRule` (filter rules) persist to `config.xml`
//! immediately, and `reconfigure`/`apply` is the only thing standing between
//! that and the live `pf` tables/ruleset. [`OpnsenseTransaction`] declares
//! this plainly via [`Atomicity`], so shared code that renders approval
//! prompts can say so rather than offering commit-confirmed semantics the
//! vendor cannot deliver — the same shape `rustunifimcp` and `rustpanosmcp`
//! already gate through.
//!
//! Scope: phase 2a governs aliases, phase 2b (this phase) adds filter rules.
//! A change set stages exactly one resource [`ResourceKind`] at a time —
//! [`validate::check_single_resource_kind`] refuses a mix — because
//! `reconfigure` and `apply` are separate device-side commits and this
//! server's apply lifecycle runs only one commit per batch.

pub mod apply;
pub mod diff;
pub mod preimage;
pub mod record;
pub mod rollback;
pub mod validate;

pub use apply::{ControllerOps, Outcome, Reconciled, State, apply_sequentially};
pub use diff::{Change, Diff, diff_against_preimage};
pub use preimage::{Preimage, ResourceKind, StagedMutation};
pub use record::{
    StagedAction, actions_for, actions_of, fingerprint_of, mutations_of, preimage_of,
};
pub use rollback::rollback_to_preimage;
pub use validate::{
    canonicalize_mutations, check_single_resource_kind, check_writable_fields, flatten_for_write,
    validate_locally,
};

// The shared crate exports `Atomicity` and `DeviceTransaction::atomicity()`,
// so this crate re-exports the shared type rather than defining an
// incompatible twin. A local copy would not be accepted by shared approval
// renderers.
pub use mecmcp_changeset::Atomicity;

/// OPNsense alias-controller transaction.
///
/// Not a [`mecmcp_changeset::DeviceTransaction`] implementation: that trait's
/// contract (fingerprint the candidate, stage all-or-nothing, diff/validate
/// against a candidate, commit atomically) is written for vendors with a
/// discardable candidate database. OPNsense's alias API has none — writes
/// persist immediately and only `reconfigure` loads them — so this server
/// follows the same pattern `rustunifimcp` uses for its own live-write API:
/// [`ControllerOps`] plus [`apply_sequentially`] drive the lifecycle, and the
/// coordinator's storage, transition policy, and preview-bound approval are
/// used directly rather than through the trait.
pub struct OpnsenseTransaction;

impl OpnsenseTransaction {
    /// What OPNsense's alias controller can guarantee about applying a
    /// change set.
    ///
    /// None of the three. This method exists so a future refactor cannot
    /// quietly make the server claim otherwise.
    #[must_use]
    pub const fn atomicity() -> Atomicity {
        Atomicity::live_writes()
    }
}

#[cfg(test)]
mod tests {
    use super::OpnsenseTransaction;

    /// OPNsense's alias controller promises none of the three. This test
    /// exists so that a future refactor cannot quietly make the server claim
    /// otherwise.
    #[test]
    fn opnsense_declares_no_atomicity_guarantees() {
        let atomicity = OpnsenseTransaction::atomicity();
        assert!(!atomicity.atomic_apply);
        assert!(!atomicity.dry_run_validation);
        assert!(!atomicity.guaranteed_rollback);
    }

    /// The design forbids the word outright, because an operator approving an
    /// OPNsense alias change set is not getting commit-confirmed semantics
    /// and the model relaying the request must be able to say so.
    #[test]
    fn no_change_set_tool_description_claims_atomicity() {
        for (name, description) in crate::tools::changeset::DESCRIPTIONS {
            let lowered = description.to_lowercase();
            assert!(
                !lowered.contains("atomic"),
                "{name} description contains 'atomic': {description}"
            );
            assert!(
                !lowered.contains("all-or-nothing"),
                "{name} description implies atomicity: {description}"
            );
        }
    }

    /// And the descriptions must say the true thing, not merely avoid the
    /// false one.
    #[test]
    fn the_apply_description_states_that_partial_failure_is_reachable() {
        let apply = crate::tools::changeset::DESCRIPTIONS
            .iter()
            .find(|(name, _)| *name == "opnsense_apply_change_set")
            .expect("apply is registered");
        let lowered = apply.1.to_lowercase();
        assert!(
            lowered.contains("partial"),
            "apply must state that partial failure is a reachable outcome: {}",
            apply.1
        );
    }
}
