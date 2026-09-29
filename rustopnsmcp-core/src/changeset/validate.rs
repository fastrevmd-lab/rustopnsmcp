//! Client-side validation for staged alias mutations.
//!
//! OPNsense's alias controller does no dry-run validation separate from the
//! write itself (`addItem`/`setItem` validate synchronously and report
//! failure in the response body, not through a distinct RPC), so this module
//! is what `opnsense_validate_change_set` can actually check without touching
//! the device: pre-image coverage and body shape.

use crate::error::OpnsenseError;

use super::preimage::{Preimage, StagedMutation};

/// Body fields a staged alias create or update may set.
///
/// `uuid` is deliberately absent: it is the controller-assigned address a
/// mutation's `uuid` field already carries, not a body field a caller can set
/// or change.
const WRITABLE_FIELDS: &[&str] = &[
    "name",
    "type",
    "content",
    "description",
    "enabled",
    "proto",
    "updatefreq",
    "counters",
    "interface",
    "categories",
];

/// Refuse a staged mutation whose body sets a field outside the writable
/// set, or a create missing `name` or `type`.
///
/// Runs on the mutation list alone — no pre-image or device round trip
/// needed — so it can run at staging time, before a bad mutation ever enters
/// a change set a human might approve.
///
/// # Errors
///
/// Returns [`OpnsenseError::WriteRefused`] naming the mutation and the field
/// or omission that was refused.
pub fn check_writable_fields(mutations: &[StagedMutation]) -> Result<(), OpnsenseError> {
    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } => continue,
        };

        let Some(object) = body.as_object() else {
            return Err(OpnsenseError::WriteRefused(format!(
                "staged {} has a non-object body ({body}); the body must be a JSON object \
                 naming only writable fields",
                mutation.preview()
            )));
        };

        for field in object.keys() {
            if !WRITABLE_FIELDS.contains(&field.as_str()) {
                return Err(OpnsenseError::WriteRefused(format!(
                    "staged {} sets field '{field}', which this server refuses to write; \
                     writable fields are: {}",
                    mutation.preview(),
                    WRITABLE_FIELDS.join(", ")
                )));
            }
        }

        if matches!(mutation, StagedMutation::Create { .. }) {
            for required in ["name", "type"] {
                let present = object
                    .get(required)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty());
                if !present {
                    return Err(OpnsenseError::WriteRefused(format!(
                        "staged {} is missing required field '{required}'",
                        mutation.preview()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Refuse a plan naming a mutation the pre-image does not cover.
///
/// A mutation outside the pre-image is either a plan built against the wrong
/// snapshot or a UUID nobody ever fetched, and either way apply cannot be
/// trusted to know what it is overwriting.
///
/// # Errors
///
/// Returns [`OpnsenseError::Malformed`] naming the uncovered mutation.
pub fn validate_locally(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<(), OpnsenseError> {
    for mutation in mutations {
        if !preimage.covers(mutation) {
            return Err(OpnsenseError::Malformed(format!(
                "mutation {} references an alias not in the pre-image",
                mutation.preview()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_writable_fields, validate_locally};
    use crate::changeset::{Preimage, StagedMutation};
    use serde_json::json;

    #[test]
    fn a_create_with_name_and_type_is_accepted() {
        let mutations = vec![StagedMutation::create(json!({
            "name": "web_servers",
            "type": "host",
            "content": "10.0.0.1"
        }))];
        assert!(check_writable_fields(&mutations).is_ok());
    }

    #[test]
    fn a_create_missing_type_is_refused() {
        let mutations = vec![StagedMutation::create(json!({"name": "web_servers"}))];
        let error = check_writable_fields(&mutations).expect_err("missing type");
        assert!(error.to_string().contains("type"), "{error}");
    }

    #[test]
    fn a_disallowed_field_is_refused() {
        let mutations = vec![StagedMutation::create(json!({
            "name": "x",
            "type": "host",
            "uuid": "should-not-be-settable"
        }))];
        let error = check_writable_fields(&mutations).expect_err("uuid is not writable");
        assert!(error.to_string().contains("uuid"), "{error}");
    }

    #[test]
    fn an_update_may_omit_name_and_type() {
        let mutations = vec![StagedMutation::update("u1", json!({"content": "10.0.0.2"}))];
        assert!(check_writable_fields(&mutations).is_ok());
    }

    #[test]
    fn a_delete_needs_no_body_check() {
        let mutations = vec![StagedMutation::delete("u1")];
        assert!(check_writable_fields(&mutations).is_ok());
    }

    #[test]
    fn a_mutation_outside_the_preimage_is_refused() {
        let preimage = Preimage::from_resources(vec![json!({"uuid": "a"})]);
        let mutations = vec![StagedMutation::update("b", json!({}))];
        assert!(validate_locally(&preimage, &mutations).is_err());
    }
}
