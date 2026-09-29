//! Best-effort rollback to pre-image state.
//!
//! OPNsense's alias controller has no checkpoint to roll back to, so rollback
//! replays the pre-image as a sequence of `addItem`/`setItem`/`delItem`
//! calls. The rollback itself can fail partway through, and nothing here
//! runs `reconfigure` — a partial apply that got this far never reached the
//! live tables, so there is nothing loaded to unload.

use super::apply::ControllerOps;
use super::preimage::{Preimage, StagedMutation};

/// Attempt to roll back to the pre-image state.
///
/// # Errors
///
/// Returns a `Vec` of failure descriptions if any rollback operations fail.
/// An empty `Vec` indicates success; a non-empty one indicates partial
/// rollback.
pub async fn rollback_to_preimage<C>(
    controller: &C,
    preimage: &Preimage,
    succeeded: &[StagedMutation],
    created_uuids: &std::collections::HashMap<usize, String>,
) -> Result<(), Vec<String>>
where
    C: ControllerOps,
{
    let mut failures = Vec::new();

    // Roll back in reverse order — last mutation first.
    for (forward_index, mutation) in succeeded.iter().enumerate().rev() {
        let prior_value = match mutation {
            StagedMutation::Create { .. } => None,
            StagedMutation::Update { uuid, .. } | StagedMutation::Delete { uuid } => {
                preimage.get(uuid)
            }
        };

        let created_uuid = created_uuids.get(&forward_index).map(String::as_str);

        if let Err(e) = controller
            .rollback_mutation(mutation, prior_value.as_ref(), created_uuid)
            .await
        {
            failures.push(format!(
                "rollback failed for {} (mutation {forward_index}): {e}",
                mutation.preview(),
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}
