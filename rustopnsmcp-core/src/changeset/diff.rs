//! Client-side diff computation.
//!
//! OPNsense's alias controller has no candidate to diff against running, so
//! diffs are computed client-side by comparing the pre-image against the
//! desired state from staged mutations.

use crate::error::OpnsenseError;

use super::preimage::{Preimage, StagedMutation};

/// A computed diff between pre-image and staged mutations.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Diff {
    /// Whether the diff was actually computed.
    ///
    /// An empty diff is distinguishable from one that was never computed.
    pub computed: bool,
    /// The changes that would be applied.
    pub changes: Vec<Change>,
}

/// A single change in a diff.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Change {
    /// The mutation that will be applied.
    pub mutation: StagedMutation,
    /// A preview of what this change does.
    pub preview: String,
    /// The alias body before the change (`None` for a create).
    pub before: Option<serde_json::Value>,
    /// The alias body after the change (`None` for a delete).
    pub after: Option<serde_json::Value>,
}

/// Compute a diff between the pre-image and staged mutations.
///
/// # Errors
///
/// Never returns one today; the `Result` is kept so a future check (e.g.
/// content-format parsing) can fail without changing every caller's shape.
pub fn diff_against_preimage(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<Diff, OpnsenseError> {
    let changes = mutations
        .iter()
        .map(|mutation| {
            let (before, after) = match mutation {
                StagedMutation::Create { body } => (None, Some(body.clone())),
                StagedMutation::Update { uuid, body } => (preimage.get(uuid), Some(body.clone())),
                StagedMutation::Delete { uuid } => (preimage.get(uuid), None),
            };

            Change {
                preview: mutation.preview(),
                mutation: mutation.clone(),
                before,
                after,
            }
        })
        .collect();

    Ok(Diff {
        computed: true,
        changes,
    })
}

#[cfg(test)]
mod tests {
    use super::{Preimage, StagedMutation, diff_against_preimage};
    use serde_json::json;

    /// An empty diff is not the same as a diff that was never computed.
    #[test]
    fn a_no_op_change_set_is_distinguishable_from_an_uncomputed_one() {
        let preimage = Preimage::from_resources(Vec::new());
        let diff = diff_against_preimage(&preimage, &[]).expect("diffs");
        assert!(diff.computed);
        assert!(diff.changes.is_empty());
    }

    /// The diff must show before and after values from the pre-image and
    /// mutations.
    #[test]
    fn diff_shows_before_and_after_values_for_update() {
        let preimage = Preimage::from_resources(vec![json!({
            "uuid": "u1",
            "name": "before_value"
        })]);

        let mutations = vec![StagedMutation::update("u1", json!({"name": "after_value"}))];

        let diff = diff_against_preimage(&preimage, &mutations).expect("diff");

        assert_eq!(diff.changes.len(), 1);
        let change = &diff.changes[0];

        assert_eq!(
            change.before.as_ref().and_then(|v| v.get("name")),
            Some(&json!("before_value"))
        );
        assert_eq!(
            change.after.as_ref().and_then(|v| v.get("name")),
            Some(&json!("after_value"))
        );
    }

    #[test]
    fn a_delete_has_a_before_but_no_after() {
        let preimage = Preimage::from_resources(vec![json!({"uuid": "u1", "name": "gone"})]);
        let mutations = vec![StagedMutation::delete("u1")];

        let diff = diff_against_preimage(&preimage, &mutations).expect("diff");
        assert!(diff.changes[0].before.is_some());
        assert!(diff.changes[0].after.is_none());
    }

    #[test]
    fn a_create_has_no_before_but_has_an_after() {
        let preimage = Preimage::from_resources(Vec::new());
        let mutations = vec![StagedMutation::create(json!({"name": "brand_new"}))];

        let diff = diff_against_preimage(&preimage, &mutations).expect("diff");
        assert!(diff.changes[0].before.is_none());
        assert!(diff.changes[0].after.is_some());
    }
}
