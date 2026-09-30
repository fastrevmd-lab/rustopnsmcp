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
    /// Every write landed in `config.xml` but `reconfigure` itself failed, so
    /// nothing reached the live `pf` tables. The writes were rolled back, so
    /// `config.xml` is back to the pre-image and this change set was not
    /// applied.
    NotLoaded,
}

/// Whether an indeterminate mutation actually reached the device.
///
/// Returned by [`ControllerOps::reconcile_indeterminate`], called only after
/// [`ControllerOps::apply_mutation`] fails with an error
/// [`crate::error::OpnsenseError::is_indeterminate`] reports as ambiguous — a
/// transport failure that leaves it unknown whether the device received and
/// acted on the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    /// It did land. For a create, the device-assigned UUID.
    Applied(Option<String>),
    /// It did not land, as far as this check could tell.
    NotApplied,
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

    /// Whether the resources this change set touches still look as they did
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

    /// Fetch one resource for verification.
    ///
    /// Returns `None` if the resource does not exist (expected after a
    /// delete).
    fn fetch_resource(
        &self,
        kind: super::preimage::ResourceKind,
        uuid: &str,
    ) -> impl std::future::Future<
        Output = Result<Option<serde_json::Value>, crate::error::OpnsenseError>,
    > + Send;

    /// Load the staged writes into the live `pf` tables/ruleset.
    ///
    /// This is `reconfigure` (aliases) or `apply` (filter rules): nothing
    /// written by `apply_mutation` is live until this runs, and it runs once
    /// for the whole batch rather than once per mutation. A change set stages
    /// exactly one resource kind (see
    /// [`super::validate::check_single_resource_kind`]), so one call per
    /// batch is always the right amount of commits.
    fn reconfigure(
        &self,
        kind: super::preimage::ResourceKind,
    ) -> impl std::future::Future<Output = Result<(), crate::error::OpnsenseError>> + Send;

    /// Determine whether a mutation that failed with an indeterminate error
    /// actually reached the device.
    ///
    /// Called only when [`Self::apply_mutation`] returned an error
    /// [`crate::error::OpnsenseError::is_indeterminate`] reports as
    /// ambiguous. A timeout or a dropped response does not mean the write
    /// never happened — the device may have already persisted it to
    /// `config.xml` — so apply cannot simply treat it as "not attempted"
    /// without checking.
    fn reconcile_indeterminate(
        &self,
        mutation: &StagedMutation,
    ) -> impl std::future::Future<Output = Result<Reconciled, crate::error::OpnsenseError>> + Send;
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
    // Indeterminate updates/deletes whose reconciliation came back
    // `NotApplied` or errored outright. Restoring the pre-image for an
    // update or delete is idempotent either way — a `setItem` back to the
    // pre-image value is a no-op if the update never landed, and a re-create
    // of a deleted alias is exactly what the pre-image already documents —
    // so these are rolled back unconditionally rather than trusted to a
    // reconciliation check that can itself be wrong (see
    // `client::flatten_for_write`'s field-order sensitivity) or fail.
    let mut needs_rollback: Vec<StagedMutation> = Vec::new();
    // A create whose reconciliation errored: unlike an update/delete, there
    // is no uuid to roll back without knowing whether the device assigned
    // one, so this cannot be folded into `needs_rollback`. It must not be
    // reported as a plain `partial` either, since that would imply the
    // ordinary "roll back what is known" story applies to it.
    let mut indeterminate_creates: Vec<StagedMutation> = Vec::new();
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
            Err(error) if error.is_indeterminate() => {
                // This process lost track of the answer, not the device
                // refusing the write — the request may already have landed.
                // Check before assuming it did not, or a retried apply could
                // leave an orphaned write neither reported nor undone.
                match controller.reconcile_indeterminate(mutation).await {
                    Ok(Reconciled::Applied(created_uuid)) => {
                        succeeded.push(mutation.clone());
                        if let Some(uuid) = created_uuid {
                            created_uuids.insert(index, uuid);
                        }
                    }
                    Ok(Reconciled::NotApplied) => {
                        attempted_and_failed.push(mutation.clone());
                        never_attempted.extend(mutations[index + 1..].iter().cloned());
                        // A create confirmed not to have landed has nothing
                        // to roll back. An update/delete is rolled back
                        // anyway: restoring the pre-image is idempotent, and
                        // this confirmation itself can be wrong (see
                        // `client::flatten_for_write`'s field-order
                        // sensitivity).
                        if !matches!(mutation, StagedMutation::Create { .. }) {
                            needs_rollback.push(mutation.clone());
                        }
                        break;
                    }
                    Err(_) => {
                        attempted_and_failed.push(mutation.clone());
                        never_attempted.extend(mutations[index + 1..].iter().cloned());
                        // The reconciliation check itself failed: whether
                        // this landed is unknown, not merely "probably not".
                        // A create cannot be rolled back without a uuid, so
                        // it must be surfaced distinctly rather than folded
                        // into a plain partial. An update/delete is rolled
                        // back anyway, since that is safe either way.
                        if matches!(mutation, StagedMutation::Create { .. }) {
                            indeterminate_creates.push(mutation.clone());
                        } else {
                            needs_rollback.push(mutation.clone());
                        }
                        break;
                    }
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
        // `needs_rollback` holds at most the one mutation apply just broke
        // on, appended after every confirmed success, so this concatenation
        // is still the prefix of `mutations` that `created_uuids`' indices
        // assume.
        let mut to_roll_back = succeeded.clone();
        to_roll_back.extend(needs_rollback.iter().cloned());

        let rollback_result =
            rollback_to_preimage(controller, preimage, &to_roll_back, &created_uuids).await;

        let mut failed = attempted_and_failed.clone();
        failed.extend(never_attempted.clone());

        let mut rollback_failures = rollback_result.err().unwrap_or_default();
        rollback_failures.extend(indeterminate_creates.iter().map(|mutation| {
            format!(
                "{}: reconciliation after a timeout failed, so it is unknown whether this \
                 create landed; without a uuid there is nothing to roll back",
                mutation.preview()
            )
        }));

        let state = if rollback_failures.is_empty() {
            State::Partial
        } else {
            State::PartialRollbackFailed
        };

        return Outcome {
            state,
            succeeded,
            failed,
            attempted_and_failed,
            never_attempted,
            rollback_failures,
            verification_failure: None,
        };
    }

    // Every write landed; load them into the live pf tables/ruleset and
    // confirm. `mutations` is never empty here: the coordinator refuses to
    // persist a change set with no actions, so a change set that reached
    // apply always staged at least one mutation, and every mutation in it
    // shares one kind (`check_single_resource_kind`).
    let Some(kind) = mutations.first().map(StagedMutation::kind) else {
        return Outcome {
            state: State::Applied,
            succeeded,
            failed: Vec::new(),
            attempted_and_failed: Vec::new(),
            never_attempted: Vec::new(),
            rollback_failures: Vec::new(),
            verification_failure: None,
        };
    };
    match controller.reconfigure(kind).await {
        Ok(()) => {
            let (state, verification_failure) =
                match verify_applied(controller, mutations, &created_uuids).await {
                    Ok(()) => (State::Applied, None),
                    Err(error) => (State::AppliedUnverified, Some(error.to_string())),
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
        Err(error) => {
            // reconfigure itself failed: every write landed in config.xml but
            // none reached the live pf tables, so this is not "applied" by
            // any definition — it must not be recorded as one. Roll every
            // write back so config.xml matches what is actually live.
            let verification_failure = Some(format!("reconfigure failed: {error}"));
            match rollback_to_preimage(controller, preimage, &succeeded, &created_uuids).await {
                Ok(()) => Outcome {
                    state: State::NotLoaded,
                    succeeded: Vec::new(),
                    failed: succeeded,
                    attempted_and_failed: Vec::new(),
                    never_attempted: Vec::new(),
                    rollback_failures: Vec::new(),
                    verification_failure,
                },
                Err(rollback_failures) => Outcome {
                    state: State::PartialRollbackFailed,
                    succeeded,
                    failed: Vec::new(),
                    attempted_and_failed: Vec::new(),
                    never_attempted: Vec::new(),
                    rollback_failures,
                    verification_failure,
                },
            }
        }
    }
}

/// Re-fetch each touched resource and compare against the desired state.
///
/// # Errors
///
/// Returns an error describing which resources failed verification, or if
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
        let kind = mutation.kind();
        match mutation {
            StagedMutation::Create { .. } => {
                let Some(uuid) = created_uuids.get(&index) else {
                    continue;
                };
                match controller.fetch_resource(kind, uuid).await {
                    Ok(Some(_)) => {}
                    Ok(None) => failed_verifications.push(format!(
                        "create {uuid}: {} does not exist after apply",
                        kind.noun()
                    )),
                    Err(e) => {
                        return Err(OpnsenseError::Malformed(format!(
                            "could not verify create {uuid}: {e}"
                        )));
                    }
                }
            }
            StagedMutation::Update { uuid, body, .. } => {
                match controller.fetch_resource(kind, uuid).await {
                    Ok(Some(fetched)) => {
                        // `fetched` is `getItem`/`getRule` shape; flatten it
                        // before comparing against the staged (flat) body, or
                        // every option/list field would mismatch regardless
                        // of whether it actually landed.
                        let flattened = super::validate::flatten_for_write(kind, &fetched);
                        let mut mismatched: Vec<&str> = Vec::new();
                        if let Some(fields) = body.as_object() {
                            for (key, value) in fields {
                                if flattened.get(key) != Some(value) {
                                    mismatched.push(key.as_str());
                                }
                            }
                        }
                        if !mismatched.is_empty() {
                            failed_verifications.push(format!(
                                "update {uuid}: field mismatch after apply ({})",
                                mismatched.join(", ")
                            ));
                        }
                    }
                    Ok(None) => {
                        failed_verifications.push(format!(
                            "update {uuid}: {} missing after apply",
                            kind.noun()
                        ));
                    }
                    Err(e) => {
                        return Err(OpnsenseError::Malformed(format!(
                            "could not verify update {uuid}: {e}"
                        )));
                    }
                }
            }
            StagedMutation::Delete { uuid, .. } => {
                match controller.fetch_resource(kind, uuid).await {
                    Ok(None) => {}
                    Ok(Some(_)) => {
                        failed_verifications
                            .push(format!("delete {uuid}: {} still exists", kind.noun()));
                    }
                    Err(e) => {
                        return Err(OpnsenseError::Malformed(format!(
                            "could not verify delete {uuid}: {e}"
                        )));
                    }
                }
            }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::preimage::ResourceKind;
    use super::*;
    use crate::error::OpnsenseError;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn timeout_error() -> OpnsenseError {
        OpnsenseError::Http(mecmcp_http::HttpError::Timeout {
            url: mecmcp_http::SafeUrl::from_unparsed("https://opnsense.example/api/test"),
            timeout: std::time::Duration::from_secs(30),
        })
    }

    /// A scripted controller for exercising `apply_sequentially` without a
    /// device. Each queue is consumed in call order; a method called more
    /// times than it was scripted for is a test bug, so those panic rather
    /// than silently returning a default.
    struct MockController {
        apply_results: Mutex<VecDeque<Result<Option<String>, OpnsenseError>>>,
        reconcile_results: Mutex<VecDeque<Result<Reconciled, OpnsenseError>>>,
        fetch_alias_results: Mutex<VecDeque<Result<Option<serde_json::Value>, OpnsenseError>>>,
        reconfigure_result: Mutex<Option<Result<(), OpnsenseError>>>,
        rollback_fails: bool,
        rollback_log: Mutex<Vec<String>>,
    }

    impl MockController {
        fn new() -> Self {
            Self {
                apply_results: Mutex::new(VecDeque::new()),
                reconcile_results: Mutex::new(VecDeque::new()),
                fetch_alias_results: Mutex::new(VecDeque::new()),
                reconfigure_result: Mutex::new(Some(Ok(()))),
                rollback_fails: false,
                rollback_log: Mutex::new(Vec::new()),
            }
        }
    }

    impl ControllerOps for MockController {
        async fn apply_mutation(
            &self,
            _mutation: &StagedMutation,
        ) -> Result<Option<String>, OpnsenseError> {
            self.apply_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("apply_mutation called more times than scripted")
        }

        async fn rollback_mutation(
            &self,
            mutation: &StagedMutation,
            _prior_value: Option<&serde_json::Value>,
            _created_uuid: Option<&str>,
        ) -> Result<(), OpnsenseError> {
            self.rollback_log.lock().unwrap().push(mutation.preview());
            if self.rollback_fails {
                Err(OpnsenseError::WriteRefused("rollback refused".to_owned()))
            } else {
                Ok(())
            }
        }

        async fn preimage_matches(
            &self,
            _preimage: &Preimage,
            _mutations: &[StagedMutation],
        ) -> Result<bool, OpnsenseError> {
            Ok(true)
        }

        async fn fetch_resource(
            &self,
            _kind: super::super::preimage::ResourceKind,
            _uuid: &str,
        ) -> Result<Option<serde_json::Value>, OpnsenseError> {
            self.fetch_alias_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(Some(serde_json::json!({}))))
        }

        async fn reconfigure(
            &self,
            _kind: super::super::preimage::ResourceKind,
        ) -> Result<(), OpnsenseError> {
            self.reconfigure_result
                .lock()
                .unwrap()
                .take()
                .expect("reconfigure called more times than scripted")
        }

        async fn reconcile_indeterminate(
            &self,
            _mutation: &StagedMutation,
        ) -> Result<Reconciled, OpnsenseError> {
            self.reconcile_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("reconcile_indeterminate called more times than scripted")
        }
    }

    fn two_creates() -> Vec<StagedMutation> {
        vec![
            StagedMutation::create(
                ResourceKind::Alias,
                serde_json::json!({"name": "a", "type": "host"}),
            ),
            StagedMutation::create(
                ResourceKind::Alias,
                serde_json::json!({"name": "b", "type": "host"}),
            ),
        ]
    }

    /// A `reconfigure` failure means every write landed in `config.xml` but
    /// never reached the live `pf` tables. Before this fix, that state was
    /// recorded as `Applied`/`AppliedUnverified` and never rolled back —
    /// unapproved writes stayed in `config.xml` and the next GUI apply would
    /// load them. This is the regression test for that: the outcome must be
    /// `NotLoaded`, not a success state, and every write must be undone.
    #[tokio::test]
    async fn a_reconfigure_failure_rolls_back_and_is_not_recorded_as_applied() {
        let controller = MockController::new();
        controller
            .apply_results
            .lock()
            .unwrap()
            .extend([Ok(Some("uuid-a".to_owned())), Ok(Some("uuid-b".to_owned()))]);
        *controller.reconfigure_result.lock().unwrap() =
            Some(Err(OpnsenseError::WriteRefused("boom".to_owned())));

        let preimage = Preimage::from_resources(Vec::new());
        let mutations = two_creates();
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::NotLoaded);
        assert!(outcome.succeeded.is_empty());
        assert_eq!(outcome.failed.len(), 2);
        assert_eq!(controller.rollback_log.lock().unwrap().len(), 2);
        // Rolled back in reverse order.
        assert_eq!(
            controller.rollback_log.lock().unwrap()[0],
            mutations[1].preview()
        );
    }

    /// If the rollback after a `reconfigure` failure itself fails, that must
    /// surface as `PartialRollbackFailed` with the rollback failures
    /// reported, not be swallowed into a success state.
    #[tokio::test]
    async fn a_reconfigure_failure_with_a_failed_rollback_reports_partial_rollback_failed() {
        let mut controller = MockController::new();
        controller.rollback_fails = true;
        controller
            .apply_results
            .lock()
            .unwrap()
            .extend([Ok(Some("uuid-a".to_owned())), Ok(Some("uuid-b".to_owned()))]);
        *controller.reconfigure_result.lock().unwrap() =
            Some(Err(OpnsenseError::WriteRefused("boom".to_owned())));

        let preimage = Preimage::from_resources(Vec::new());
        let mutations = two_creates();
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::PartialRollbackFailed);
        assert_eq!(outcome.rollback_failures.len(), 2);
    }

    /// A timeout on the first create does not mean it never happened: if
    /// reconciliation confirms it landed, apply must continue rather than
    /// treat a successful write as a failure and roll back unnecessarily.
    #[tokio::test]
    async fn an_indeterminate_write_that_landed_lets_apply_continue() {
        let controller = MockController::new();
        controller
            .apply_results
            .lock()
            .unwrap()
            .extend([Err(timeout_error()), Ok(Some("uuid-b".to_owned()))]);
        controller
            .reconcile_results
            .lock()
            .unwrap()
            .push_back(Ok(Reconciled::Applied(Some("uuid-a".to_owned()))));
        // verify_applied fetches both created aliases afterwards.
        controller.fetch_alias_results.lock().unwrap().extend([
            Ok(Some(serde_json::json!({"name": "a"}))),
            Ok(Some(serde_json::json!({"name": "b"}))),
        ]);

        let preimage = Preimage::from_resources(Vec::new());
        let mutations = two_creates();
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::Applied);
        assert_eq!(outcome.succeeded.len(), 2);
        assert!(outcome.failed.is_empty());
    }

    /// A timeout on the first create that reconciliation confirms did *not*
    /// land must behave exactly like a definite failure: stop, and roll back
    /// nothing (there was nothing to roll back for that mutation) while
    /// refusing to attempt the rest.
    #[tokio::test]
    async fn an_indeterminate_write_that_did_not_land_behaves_like_a_definite_failure() {
        let controller = MockController::new();
        controller
            .apply_results
            .lock()
            .unwrap()
            .extend([Ok(Some("uuid-a".to_owned())), Err(timeout_error())]);
        controller
            .reconcile_results
            .lock()
            .unwrap()
            .push_back(Ok(Reconciled::NotApplied));

        let preimage = Preimage::from_resources(Vec::new());
        let mutations = two_creates();
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::Partial);
        assert_eq!(outcome.succeeded.len(), 1);
        assert_eq!(outcome.attempted_and_failed.len(), 1);
        // Only the first (successful) mutation is rolled back.
        assert_eq!(controller.rollback_log.lock().unwrap().len(), 1);
        assert_eq!(
            controller.rollback_log.lock().unwrap()[0],
            mutations[0].preview()
        );
    }

    /// An indeterminate update that reconciliation confirms did *not* land
    /// must still be rolled back: restoring the pre-image with `setItem` is
    /// a no-op if the update genuinely never landed, and the confirmation
    /// itself can be wrong (a staged `content` in different order or with a
    /// different separator reads as `NotApplied` even when it landed). Before
    /// this fix, only mutations that came before the failing one were rolled
    /// back, so a wrongly reconciled update stayed live.
    #[tokio::test]
    async fn an_indeterminate_update_reads_as_not_applied_is_rolled_back_anyway() {
        let controller = MockController::new();
        controller
            .apply_results
            .lock()
            .unwrap()
            .push_back(Err(timeout_error()));
        controller
            .reconcile_results
            .lock()
            .unwrap()
            .push_back(Ok(Reconciled::NotApplied));

        let preimage = Preimage::from_resources(vec![serde_json::json!({
            "uuid": "u1",
            "name": "before",
        })]);
        let mutations = vec![StagedMutation::update(
            ResourceKind::Alias,
            "u1",
            serde_json::json!({"name": "after"}),
        )];
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::Partial);
        assert_eq!(controller.rollback_log.lock().unwrap().len(), 1);
        assert_eq!(
            controller.rollback_log.lock().unwrap()[0],
            mutations[0].preview()
        );
    }

    /// The same, but reconciliation itself errors rather than confirming
    /// either way — the fail-closed choice is still to roll the update back.
    #[tokio::test]
    async fn an_indeterminate_delete_whose_reconciliation_errors_is_rolled_back_anyway() {
        let controller = MockController::new();
        controller
            .apply_results
            .lock()
            .unwrap()
            .push_back(Err(timeout_error()));
        controller
            .reconcile_results
            .lock()
            .unwrap()
            .push_back(Err(timeout_error()));

        let preimage = Preimage::from_resources(vec![serde_json::json!({
            "uuid": "u1",
            "name": "gone",
        })]);
        let mutations = vec![StagedMutation::delete(ResourceKind::Alias, "u1")];
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::Partial);
        assert_eq!(controller.rollback_log.lock().unwrap().len(), 1);
        assert_eq!(
            controller.rollback_log.lock().unwrap()[0],
            mutations[0].preview()
        );
    }

    /// A create whose reconciliation itself errors is unknown, not
    /// "probably didn't land" — and there is no uuid to roll back even if it
    /// did. Before this fix this was reported as a plain `Partial`,
    /// indistinguishable from a definite, fully-accounted-for failure.
    #[tokio::test]
    async fn a_create_whose_reconciliation_errors_is_not_reported_as_plain_partial() {
        let controller = MockController::new();
        controller
            .apply_results
            .lock()
            .unwrap()
            .push_back(Err(timeout_error()));
        controller
            .reconcile_results
            .lock()
            .unwrap()
            .push_back(Err(timeout_error()));

        let preimage = Preimage::from_resources(Vec::new());
        let mutations = vec![StagedMutation::create(
            ResourceKind::Alias,
            serde_json::json!({"name": "a", "type": "host"}),
        )];
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::PartialRollbackFailed);
        assert_eq!(outcome.rollback_failures.len(), 1);
        assert!(
            outcome.rollback_failures[0].contains("create alias 'a'"),
            "{:?}",
            outcome.rollback_failures
        );
        // No uuid was ever known, so nothing was attempted against the
        // device for this mutation's rollback.
        assert!(controller.rollback_log.lock().unwrap().is_empty());
    }

    /// `verify_applied` must compare every staged field, not only `name` —
    /// otherwise a write that landed with the right name but a stale
    /// `content` is reported as fully `Applied`.
    #[tokio::test]
    async fn verify_applied_catches_a_mismatch_outside_the_name_field() {
        let controller = MockController::new();
        controller.apply_results.lock().unwrap().push_back(Ok(None));
        controller
            .fetch_alias_results
            .lock()
            .unwrap()
            .push_back(Ok(Some(
                serde_json::json!({"name": "web_servers", "content": "10.0.0.9"}),
            )));

        let preimage = Preimage::from_resources(vec![serde_json::json!({
            "uuid": "u1",
            "name": "web_servers",
            "content": "10.0.0.1",
        })]);
        let mutations = vec![StagedMutation::update(
            ResourceKind::Alias,
            "u1",
            serde_json::json!({"name": "web_servers", "content": "10.0.0.1"}),
        )];
        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::AppliedUnverified);
        let failure = outcome.verification_failure.expect("must report a failure");
        assert!(failure.contains("content"), "{failure}");
    }

    /// A staged `content` given unsorted or comma-separated, once
    /// `canonicalize_mutations` runs on it at staging time (as
    /// `opnsense_stage_change` does), must verify as `Applied` — not
    /// `AppliedUnverified` — against a device that echoes it back sorted and
    /// newline-joined. Before canonicalization existed, this staged value
    /// would have read as a `content` mismatch purely from formatting, even
    /// though it landed correctly.
    #[tokio::test]
    async fn a_canonicalized_unsorted_content_update_verifies_as_applied() {
        let controller = MockController::new();
        controller.apply_results.lock().unwrap().push_back(Ok(None));
        controller
            .fetch_alias_results
            .lock()
            .unwrap()
            .push_back(Ok(Some(
                serde_json::json!({"name": "web_servers", "content": "10.0.0.1\n10.0.0.2"}),
            )));

        let preimage = Preimage::from_resources(vec![serde_json::json!({
            "uuid": "u1",
            "name": "web_servers",
            "content": "10.0.0.9",
        })]);
        let mut mutations = vec![StagedMutation::update(
            ResourceKind::Alias,
            "u1",
            serde_json::json!({"name": "web_servers", "content": "10.0.0.2,10.0.0.1"}),
        )];
        super::super::validate::canonicalize_mutations(&mut mutations);

        let outcome = apply_sequentially(&controller, &preimage, &mutations).await;

        assert_eq!(outcome.state, State::Applied);
        assert!(outcome.verification_failure.is_none());
    }
}
