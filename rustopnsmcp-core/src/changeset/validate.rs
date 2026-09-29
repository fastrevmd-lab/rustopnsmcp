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
pub(crate) const WRITABLE_FIELDS: &[&str] = &[
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

/// Alias types this phase refuses to stage.
///
/// A `url`/`urltable` alias makes OPNsense itself fetch a remote list on
/// `reconfigure` and periodically thereafter — an outbound request the
/// device makes because a model chose this type, not because a human
/// approved a specific URL. Refusing the type at staging time keeps that
/// decision out of the model's hands entirely, consistent with every other
/// resource kind this phase does not govern.
const REFUSED_ALIAS_TYPES: &[&str] = &["url", "urltable"];

/// Refuse a staged mutation whose body sets a field outside the writable
/// set, sets a refused alias type, or a create missing `name` or `type`.
///
/// Runs on the mutation list alone — no pre-image or device round trip
/// needed — so it can run at staging time, before a bad mutation ever enters
/// a change set a human might approve.
///
/// # Errors
///
/// Returns [`OpnsenseError::WriteRefused`] naming the mutation and the field,
/// type, or omission that was refused.
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

        if let Some(alias_type) = object.get("type").and_then(serde_json::Value::as_str)
            && REFUSED_ALIAS_TYPES.contains(&alias_type)
        {
            return Err(OpnsenseError::WriteRefused(format!(
                "staged {} sets type '{alias_type}', which this server refuses to write: it \
                 makes the device itself fetch a remote URL on reconfigure, an outbound \
                 request this phase does not let a model trigger",
                mutation.preview()
            )));
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

/// Staged fields whose value is really a set, written as one string: OPNsense
/// accepts (and its own `getItem` response settles into) a sorted,
/// deduplicated list joined by a fixed separator.
const MULTI_VALUE_FIELDS: &[(&str, &str)] =
    &[("content", "\n"), ("proto", ","), ("categories", ",")];

/// Canonicalize one multi-value field's raw string to the sorted,
/// deduplicated, fixed-separator form [`flatten_for_write`] recovers from a
/// landed write.
///
/// Accepts either separator on input (callers may stage `content` as
/// newline- or comma-joined) so the canonical form does not depend on which
/// one a caller happened to use.
fn canonicalize_multi_value(raw: &str, separator: &str) -> String {
    let mut parts: Vec<&str> = raw
        .split(['\n', ','])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    parts.sort_unstable();
    parts.dedup();
    parts.join(separator)
}

/// Canonicalize multi-value fields (`content`, `proto`, `categories`) in
/// every staged create/update body.
///
/// Must run before a mutation is staged (persisted into a change set a human
/// can approve): the plan, its digest, the preview, and later
/// reconciliation (`client::reconcile_indeterminate`) and verification
/// (`apply::verify_applied`) all compare the staged body against
/// [`flatten_for_write`]'s output, which is always sorted and
/// fixed-separator. Without this, a staged value that landed correctly but
/// was written in a different order or with a different separator reads as a
/// mismatch purely from formatting — misreporting a landed update as
/// `NotApplied` during indeterminate reconciliation, or as
/// `AppliedUnverified` during post-apply verification.
pub fn canonicalize_mutations(mutations: &mut [StagedMutation]) {
    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } => continue,
        };
        let Some(object) = body.as_object_mut() else {
            continue;
        };
        for (field, separator) in MULTI_VALUE_FIELDS {
            if let Some(canonical) = object
                .get(*field)
                .and_then(serde_json::Value::as_str)
                .map(|raw| canonicalize_multi_value(raw, separator))
            {
                object.insert((*field).to_owned(), serde_json::Value::String(canonical));
            }
        }
    }
}

/// Flatten a `getItem`-shaped alias body into the flat shape
/// `addItem`/`setItem` accept.
///
/// OPNsense's MVC controllers echo option and list fields back from
/// `getItem` as a map of `{value: label, selected: 0|1}` per choice (for
/// example `type`, `proto`, `interface`, `categories`, `content`), not as the
/// flat string or comma-list `setItem` requires. Replaying a `getItem` body
/// verbatim into `setItem`/`addItem` — which is exactly what rollback does —
/// either gets refused as malformed or, worse, silently drops the field.
///
/// Only the writable field set survives into the result: a pre-image can carry
/// read-only fields (`uuid`, computed counters, and so on) that must never be
/// replayed into a write.
///
/// # Errors
///
/// Never returns an error. A field whose shape this function does not
/// recognise (neither a flat scalar nor a `{value, selected}` map) is passed
/// through unchanged rather than dropped, since refusing silently would be
/// worse than an odd value `setItem` can reject on its own.
#[must_use]
pub fn flatten_for_write(get_item: &serde_json::Value) -> serde_json::Value {
    let mut flat = serde_json::Map::new();

    let Some(object) = get_item.as_object() else {
        return get_item.clone();
    };

    for field in WRITABLE_FIELDS {
        let Some(value) = object.get(*field) else {
            continue;
        };
        flat.insert((*field).to_owned(), flatten_field(field, value));
    }

    serde_json::Value::Object(flat)
}

/// Flatten one field's value from `getItem` shape to `setItem` shape.
fn flatten_field(field: &str, value: &serde_json::Value) -> serde_json::Value {
    let Some(options) = value.as_object() else {
        return value.clone();
    };

    // A flat scalar never round-trips as a JSON object; a `{value, selected}`
    // choice map always does. Anything else here is not this shape, so it is
    // passed through unchanged rather than mangled.
    let is_choice_map = options
        .values()
        .all(|choice| choice.is_object() && choice.get("selected").is_some());
    if !is_choice_map {
        return value.clone();
    }

    let separator = if field == "content" { "\n" } else { "," };

    let mut selected: Vec<&str> = options
        .iter()
        .filter(|(_, choice)| {
            matches!(
                choice.get("selected"),
                Some(serde_json::Value::Number(n)) if n.as_i64() == Some(1)
            ) || matches!(choice.get("selected"), Some(serde_json::Value::String(s)) if s == "1")
        })
        .map(|(key, _)| key.as_str())
        .collect();
    selected.sort_unstable();

    serde_json::Value::String(selected.join(separator))
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
    use super::{check_writable_fields, flatten_for_write, validate_locally};
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

    /// A `url`/`urltable` alias makes the device itself fetch a remote URL on
    /// `reconfigure`. This phase must refuse both a create and an update that
    /// set that type, not only rely on a human catching it in review.
    #[test]
    fn a_url_type_create_is_refused() {
        let mutations = vec![StagedMutation::create(json!({
            "name": "blocklist",
            "type": "urltable",
            "content": "https://example.org/list.txt"
        }))];
        let error = check_writable_fields(&mutations).expect_err("urltable must be refused");
        assert!(error.to_string().contains("urltable"), "{error}");
    }

    #[test]
    fn a_url_type_update_is_refused() {
        let mutations = vec![StagedMutation::update("u1", json!({"type": "url"}))];
        let error = check_writable_fields(&mutations).expect_err("url must be refused");
        assert!(error.to_string().contains("'url'"), "{error}");
    }

    #[test]
    fn a_mutation_outside_the_preimage_is_refused() {
        let preimage = Preimage::from_resources(vec![json!({"uuid": "a"})]);
        let mutations = vec![StagedMutation::update("b", json!({}))];
        assert!(validate_locally(&preimage, &mutations).is_err());
    }

    /// A realistic `getItem` response for a host alias: option fields come
    /// back as `{value, selected}` maps, not flat strings. Replaying this
    /// verbatim into `setItem` (what rollback used to do) would either be
    /// refused as malformed or silently drop the field; flattening must
    /// recover the flat shape `setItem` actually accepts.
    #[test]
    fn flatten_for_write_recovers_setitem_shape_from_getitem_shape() {
        let get_item = json!({
            "uuid": "11111111-1111-4111-8111-111111111111",
            "name": "web_servers",
            "type": {
                "host": {"value": "Host(s)", "selected": 1},
                "network": {"value": "Network(s)", "selected": 0},
                "urltable": {"value": "URL Table", "selected": 0},
            },
            "content": {
                "10.0.0.1": {"value": "10.0.0.1", "selected": 1},
                "10.0.0.2": {"value": "10.0.0.2", "selected": 1},
            },
            "proto": {
                "IPv4": {"value": "IPv4", "selected": 1},
                "IPv6": {"value": "IPv6", "selected": 0},
            },
            "description": "web servers",
            "enabled": "1",
        });

        let flat = flatten_for_write(&get_item);

        assert_eq!(flat.get("name"), Some(&json!("web_servers")));
        assert_eq!(flat.get("type"), Some(&json!("host")));
        assert_eq!(flat.get("content"), Some(&json!("10.0.0.1\n10.0.0.2")));
        assert_eq!(flat.get("proto"), Some(&json!("IPv4")));
        assert_eq!(flat.get("description"), Some(&json!("web servers")));
        assert_eq!(flat.get("enabled"), Some(&json!("1")));
        // `uuid` is not writable and must not survive flattening.
        assert!(flat.get("uuid").is_none());
    }

    /// A field this function does not recognise as either shape is passed
    /// through unchanged rather than dropped or mangled.
    #[test]
    fn flatten_for_write_passes_through_unrecognised_shapes() {
        let get_item = json!({"name": "x", "counters": 42});
        let flat = flatten_for_write(&get_item);
        assert_eq!(flat.get("counters"), Some(&json!(42)));
    }

    /// A non-object input (defensive: `getItem` should always return an
    /// object) must not panic.
    #[test]
    fn flatten_for_write_on_a_non_object_returns_it_unchanged() {
        let value = json!("not an object");
        assert_eq!(flatten_for_write(&value), value);
    }

    /// A staged `content` in a different order, or comma-separated rather
    /// than newline-separated, must be rewritten to exactly the sorted,
    /// newline-joined form `flatten_for_write` recovers from a landed write
    /// — otherwise a value that lands correctly reads as `NotApplied` during
    /// indeterminate reconciliation, or `AppliedUnverified` during
    /// post-apply verification, purely because of formatting.
    #[test]
    fn canonicalize_mutations_normalizes_unsorted_and_comma_separated_content() {
        use super::canonicalize_mutations;

        let mut unsorted = vec![StagedMutation::update(
            "u1",
            json!({"content": "10.0.0.2\n10.0.0.1"}),
        )];
        canonicalize_mutations(&mut unsorted);
        assert_eq!(
            unsorted[0].clone(),
            StagedMutation::update("u1", json!({"content": "10.0.0.1\n10.0.0.2"}))
        );

        let mut comma_separated = vec![StagedMutation::create(json!({
            "name": "web_servers",
            "type": "host",
            "content": "10.0.0.2,10.0.0.1",
        }))];
        canonicalize_mutations(&mut comma_separated);
        let StagedMutation::Create { body } = &comma_separated[0] else {
            unreachable!("staged as a create");
        };
        assert_eq!(body.get("content"), Some(&json!("10.0.0.1\n10.0.0.2")));
    }

    /// `proto` and `categories` are comma-joined, not newline-joined, and
    /// must canonicalize to that separator regardless of what order or
    /// separator the caller staged them with. Duplicates are also collapsed,
    /// since the device's own `getItem` response never repeats a selection.
    #[test]
    fn canonicalize_mutations_normalizes_proto_and_categories() {
        use super::canonicalize_mutations;

        let mut mutations = vec![StagedMutation::update(
            "u1",
            json!({"proto": "IPv6,IPv4,IPv4", "categories": "b\na"}),
        )];
        canonicalize_mutations(&mut mutations);
        let StagedMutation::Update { body, .. } = &mutations[0] else {
            unreachable!("staged as an update");
        };
        assert_eq!(body.get("proto"), Some(&json!("IPv4,IPv6")));
        assert_eq!(body.get("categories"), Some(&json!("a,b")));
    }

    /// A delete has no body to canonicalize and must not panic.
    #[test]
    fn canonicalize_mutations_skips_deletes() {
        use super::canonicalize_mutations;

        let mut mutations = vec![StagedMutation::delete("u1")];
        canonicalize_mutations(&mut mutations);
        assert_eq!(mutations, vec![StagedMutation::delete("u1")]);
    }
}
