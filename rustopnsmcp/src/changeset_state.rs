//! The change-set store: `mecmcp-changeset`'s coordinator, and getting onto
//! it.
//!
//! The coordinator owns the transition policy, the claim-before-apply, and
//! the preview-bound approval — three protections this server gets for free
//! by using it directly rather than re-deriving them. This module only
//! builds it and sizes it for OPNsense aliases.

use std::path::{Path, PathBuf};
use std::time::Duration;

use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};

/// Ceilings for the change-set store.
///
/// Deliberately small. A single-operator firewall does not have a hundred
/// alias change sets in flight, and an unbounded store is a way for a state
/// file to grow until it stops being loadable.
#[must_use]
pub fn limits() -> OperationLimits {
    OperationLimits {
        max_operations: 100,
        max_change_sets: 100,
        // OPNsense applies each alias as its own REST call with no atomic
        // commit across them, so a long change set is a long partial-failure
        // window. Ten is generous for an alias edit.
        max_actions_per_set: 10,
        max_change_set_bytes: 1024 * 1024,
        max_state_bytes: 10 * 1024 * 1024,
        // Single-device change sets only: a change set names one device and
        // its alias UUIDs mean nothing on another.
        max_targets_per_set: 1,
        max_preview_bytes: 256 * 1024,
    }
}

/// A change-set identifier the shared lifecycle will accept.
///
/// 64 hex characters, which is what `mecmcp_changeset` validates IDs against.
#[must_use]
pub fn new_change_set_id() -> String {
    mecmcp_changeset::digest::digest_hex(uuid::Uuid::new_v4().as_bytes())
}

/// The coordinator requires an absolute path; `--state-file` may be relative.
fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|error| {
        format!(
            "--state-file {} cannot be made absolute: {error}",
            path.display()
        )
    })
}

/// Build the change-set coordinator.
///
/// # Errors
///
/// Returns a message naming what to do if the path cannot be made absolute
/// or if the coordinator refuses the state.
pub fn build_coordinator(
    state_file: Option<&Path>,
    approval_ttl: Duration,
    lab_mode: bool,
) -> Result<std::sync::Arc<ChangesetCoordinator>, String> {
    let absolute = match state_file {
        Some(path) => Some(absolute_path(path)?),
        None => None,
    };

    let coordinator =
        ChangesetCoordinator::load(absolute.as_deref(), limits(), approval_ttl, lab_mode).map_err(
            |error| format!("change-set state ({}): {}", error.field(), error.message()),
        )?;

    Ok(std::sync::Arc::new(coordinator))
}

#[cfg(test)]
mod tests {
    use super::{build_coordinator, limits, new_change_set_id};
    use std::time::Duration;

    /// The id has to satisfy the shared lifecycle's validator.
    #[test]
    fn a_minted_id_is_one_the_lifecycle_accepts() {
        let id = new_change_set_id();
        mecmcp_changeset::OperationId::new(id.clone())
            .unwrap_or_else(|error| panic!("the lifecycle refused {id}: {error}"));
    }

    #[test]
    fn ids_are_not_reused() {
        assert_ne!(new_change_set_id(), new_change_set_id());
    }

    /// A change set targets one device, so more than one target is not a
    /// shape this server can mean.
    #[test]
    fn a_change_set_may_name_only_one_device() {
        assert_eq!(limits().max_targets_per_set, 1);
    }

    /// A relative `--state-file` is accepted here and made absolute, because
    /// the coordinator refuses a relative path outright.
    #[test]
    fn no_state_file_means_an_in_memory_store() {
        build_coordinator(None, Duration::from_secs(300), false)
            .expect("no state file is a valid configuration");
    }

    /// A relative path is made absolute before it reaches the coordinator,
    /// which refuses a relative one outright. Checked directly against
    /// `absolute_path` rather than by mutating the test process's shared
    /// current directory, which would race every other test in this binary.
    #[test]
    fn a_relative_state_file_is_made_absolute() {
        let resolved = super::absolute_path(std::path::Path::new("changesets.json"))
            .expect("a relative path resolves");
        assert!(resolved.is_absolute());
    }
}
