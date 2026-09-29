//! Sequential apply and verification.
//!
//! OPNsense's alias controller has no atomic commit across multiple items:
//! each `addItem`/`setItem`/`delItem` is its own request, and only a final
//! `reconfigure` loads the result into the live `pf` tables. Partial failure
//! is a reachable state and must be tracked accurately.

use super::preimage::{Preimage, StagedMutation};
use super::rollback::rollback_to_preimage;

/// The outcome of applying a change set.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    /// The final state after apply.
    pub state: State,
    /// Mutations that succeeded.
    pub succeeded: Vec<StagedMutation>,
    /// All mutations that did not succeed (attempted + never attempted).
    pub failed: Vec<StagedMutation>,
    /// Mutations that were attempted but failed.
    pub attempted_and_failed: Vec<StagedMutation>,
    /// Mutations that were never attempted due to prior failure.
    pub never_attempted: Vec<StagedMutation>,
    /// Rollback operations that failed.
    pub rollback_failures: Vec<String>,
    /// Why `reconfigure` could not confirm the apply, when it could not.
    pub verification_failure: Option<String>,
}

/// The state of a change set after apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum State {
    /// Every write landed and `reconfigure` confirmed it.
    Applied,
    /// Every write landed but `reconfigure` could not be confirmed.
    AppliedUnverified,
    /// Some mutations succeeded, some failed.
    Partial,
    /// Partial apply with failed rollback.
    PartialRollbackFailed,
    /// Apply was refused because the pre-image no longer matches.
    RefusedStale,
}

/// Operations a device must support for apply and rollback.
///
/// Implemented by [`crate::client::OpnsenseClient`] and by test mocks.
pub trait ControllerOps {
    /// Apply a single mutation.
    ///
    /// Returns `Ok(Some(uuid))` for a successful create, where `uuid` is the
    /// device-assigned alias UUID. Returns `Ok(None)` for a successful update
    /// or delete.
    fn apply_mutation(
        &self,
        mutation: &StagedMutation,
    ) -> impl std::future::Future<Output = Result<Option<String>, crate::error::OpnsenseError>> + Send;

    /// Roll back a single mutation.
    ///
    /// For a create, `prior_value` is `None` and `created_uuid` holds the
    /// UUID to delete. For an update, `prior_value` holds the body to
    /// restore. For a delete, `prior_value` holds the deleted alias to
    /// re-create.
    fn rollback_mutation(
        &self,
        mutation: &StagedMutation,
        prior_value: Option<&serde_json::Value>,
        created_uuid: Option<&str>,
    ) -> impl std::future::Future<Output = Result<(), crate::error::OpnsenseError>> + Send;

    /// Whether the aliases this change set touches still look as they did
    /// when the pre-image was captured.
    ///
    /// `Err` means the check could not be completed. Callers must treat that
    /// as stale and refuse — an approval is a statement about a specific
    /// device state, and a check that did not run cannot renew it.
    fn preimage_matches(
        &self,
        preimage: &Preimage,
        mutations: &[StagedMutation],
    ) -> impl std::future::Future<Output = Result<bool, crate::error::OpnsenseError>> + Send;

    /// Fetch one alias for verification.
    ///
    /// Returns `None` if the alias does not exist (expected after a delete).
    fn fetch_alias(
        &self,
        uuid: &str,
    ) -> impl std::future::Future<
        Output = Result<Option<serde_json::Value>, crate::error::OpnsenseError>,
    > + Send;

    /// Load the staged writes into the live `pf` alias tables.
    ///
    /// This is `reconfigure`: nothing written by `apply_mutation` is live
    /// until this runs, and it runs once for the whole batch rather than once
    /// per mutation.
    fn reconfigure(
        &self,
    ) -> impl std::future::Future<Output = Result<(), crate::error::OpnsenseError>> + Send;
}

/// Apply staged mutations sequentially, then load them with `reconfigure`.
///
/// This function does not return an error directly. All failures are
/// captured in the returned [`Outcome`].
pub async fn apply_sequentially<C>(
    controller: &C,
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Outcome
where
    C: ControllerOps,
{
    // Refuse if the device moved under the approval, and refuse equally when
    // the check itself could not be completed.
    if !matches!(
        controller.preimage_matches(preimage, mutations).await,
        Ok(true)
    ) {
        return Outcome {
            state: State::RefusedStale,
            succeeded: Vec::new(),
            failed: mutations.to_vec(),
            attempted_and_failed: Vec::new(),
            never_attempted: mutations.to_vec(),
            rollback_failures: Vec::new(),
            verification_failure: None,
        };
    }

    let mut succeeded = Vec::new();
    let mut attempted_and_failed = Vec::new();
    let mut never_attempted = Vec::new();
    let mut created_uuids: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();

    for (index, mutation) in mutations.iter().enumerate() {
        match controller.apply_mutation(mutation).await {
            Ok(created_uuid) => {
                succeeded.push(mutation.clone());
                if let Some(uuid) = created_uuid {
                    created_uuids.insert(index, uuid);
                }
            }
            Err(_) => {
                attempted_and_failed.push(mutation.clone());
                never_attempted.extend(mutations[index + 1..].iter().cloned());
                break;
            }
        }
    }

    if !attempted_and_failed.is_empty() || !never_attempted.is_empty() {
        let rollback_result =
            rollback_to_preimage(controller, preimage, &succeeded, &created_uuids).await;

        let mut failed = attempted_and_failed.clone();
        failed.extend(never_attempted.clone());

        return match rollback_result {
            Ok(()) => Outcome {
                state: State::Partial,
                succeeded,
                failed,
                attempted_and_failed,
                never_attempted,
                rollback_failures: Vec::new(),
                verification_failure: None,
            },
            Err(rollback_failures) => Outcome {
                state: State::PartialRollbackFailed,
                succeeded,
                failed,
                attempted_and_failed,
                never_attempted,
                rollback_failures,
                verification_failure: None,
            },
        };
    }

    // Every write landed; load them into the live pf tables and confirm.
    let (state, verification_failure) = match controller.reconfigure().await {
        Ok(()) => match verify_applied(controller, mutations, &created_uuids).await {
            Ok(()) => (State::Applied, None),
            Err(error) => (State::AppliedUnverified, Some(error.to_string())),
        },
        Err(error) => (
            State::AppliedUnverified,
            Some(format!("reconfigure failed: {error}")),
        ),
    };

    Outcome {
        state,
        succeeded,
        failed: Vec::new(),
        attempted_and_failed: Vec::new(),
        never_attempted: Vec::new(),
        rollback_failures: Vec::new(),
        verification_failure,
    }
}

/// Re-fetch each touched alias and compare against the desired state.
///
/// # Errors
///
/// Returns an error describing which aliases failed verification, or if
/// verification itself could not run.
async fn verify_applied<C>(
    controller: &C,
    mutations: &[StagedMutation],
    created_uuids: &std::collections::HashMap<usize, String>,
) -> Result<(), crate::error::OpnsenseError>
where
    C: ControllerOps,
{
    use crate::error::OpnsenseError;

    let mut failed_verifications = Vec::new();

    for (index, mutation) in mutations.iter().enumerate() {
        match mutation {
            StagedMutation::Create { .. } => {
                let Some(uuid) = created_uuids.get(&index) else {
                    continue;
                };
                match controller.fetch_alias(uuid).await {
                    Ok(Some(_)) => {}
                    Ok(None) => failed_verifications
                        .push(format!("create {uuid}: alias does not exist after apply")),
                    Err(e) => {
                        return Err(OpnsenseError::Malformed(format!(
                            "could not verify create {uuid}: {e}"
                        )));
                    }
                }
            }
            StagedMutation::Update { uuid, body } => match controller.fetch_alias(uuid).await {
                Ok(Some(fetched)) => {
                    if let Some(expected_name) = body.get("name")
                        && fetched.get("name") != Some(expected_name)
                    {
                        failed_verifications
                            .push(format!("update {uuid}: field mismatch after apply"));
                    }
                }
                Ok(None) => {
                    failed_verifications.push(format!("update {uuid}: alias missing after apply"));
                }
                Err(e) => {
                    return Err(OpnsenseError::Malformed(format!(
                        "could not verify update {uuid}: {e}"
                    )));
                }
            },
            StagedMutation::Delete { uuid } => match controller.fetch_alias(uuid).await {
                Ok(None) => {}
                Ok(Some(_)) => {
                    failed_verifications.push(format!("delete {uuid}: alias still exists"));
                }
                Err(e) => {
                    return Err(OpnsenseError::Malformed(format!(
                        "could not verify delete {uuid}: {e}"
                    )));
                }
            },
        }
    }

    if failed_verifications.is_empty() {
        Ok(())
    } else {
        Err(OpnsenseError::Malformed(format!(
            "verification failed for {} mutation(s): {}",
            failed_verifications.len(),
            failed_verifications.join("; ")
        )))
    }
}
