//! The one shape phase 1 actually relies on: OPNsense's paginated `search_*`
//! response envelope.
//!
//! Everything inside `rows` is vendor- and version-dependent free-form JSON —
//! typing it field-by-field would mean guessing at a shape this phase has no
//! live device to confirm, and a wrong guess silently drops fields a caller
//! needed. So only the envelope is parsed; the rows are passed through
//! untouched (after redaction — see `tools::read`).
//!
//! `deny_unknown_fields` is deliberately absent here: this struct describes a
//! response from an authority this crate does not control, and OPNsense
//! adding a field to it in a later release must not become a parse failure
//! here.

use serde::{Deserialize, Serialize};

/// One page of an OPNsense `search_*` response.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    /// The page of matching items. Each element's shape depends on the
    /// resource and the OPNsense version; consult the tool's `description`
    /// for what a caller should expect to find in it.
    pub rows: Vec<serde_json::Value>,
    /// Items on this page, if the device reported it.
    #[serde(default)]
    pub row_count: Option<u32>,
    /// Total items across all pages, if the device reported it.
    #[serde(default)]
    pub total: Option<u32>,
    /// The page number this response answers, if the device echoed it back.
    #[serde(default)]
    pub current: Option<u32>,
}

impl SearchResponse {
    /// Parse a `search_*` response, requiring at least a `rows` array.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::OpnsenseError::Malformed`] if `rows` is
    /// missing or is not a JSON array.
    pub fn parse(raw: &serde_json::Value) -> Result<Self, crate::error::OpnsenseError> {
        serde_json::from_value(raw.clone())
            .map_err(|error| crate::error::OpnsenseError::Malformed(error.to_string()))
    }
}

/// Require a response to be a JSON object, without asserting anything about
/// its fields.
///
/// Used for the non-paginated status endpoints (system status, firmware
/// status, interfaces overview, gateway status), whose exact shape varies by
/// OPNsense version and plugin set. Confirming "this device answered with a
/// JSON object" is the invariant this phase can state with confidence;
/// anything narrower would be a guess this phase has no live device to check.
///
/// # Errors
///
/// Returns [`crate::error::OpnsenseError::Malformed`] if `raw` is not a JSON
/// object.
pub fn require_object(raw: &serde_json::Value) -> Result<(), crate::error::OpnsenseError> {
    if raw.is_object() {
        Ok(())
    } else {
        Err(crate::error::OpnsenseError::Malformed(
            "expected a JSON object response".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::SearchResponse;

    #[test]
    fn a_response_with_no_rows_field_is_rejected() {
        let raw = serde_json::json!({"total": 0});
        assert!(SearchResponse::parse(&raw).is_err());
    }

    #[test]
    fn a_response_with_a_rows_array_parses() {
        let raw = serde_json::json!({
            "rows": [{"uuid": "abc", "description": "example"}],
            "rowCount": 1,
            "total": 1,
            "current": 1,
        });
        let parsed = SearchResponse::parse(&raw).expect("parses");
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.total, Some(1));
    }

    /// An unrecognised extra field from a newer OPNsense release must not
    /// break parsing — the envelope is consumed from an authority this crate
    /// does not control.
    #[test]
    fn unknown_extra_fields_are_tolerated() {
        let raw = serde_json::json!({
            "rows": [],
            "rowCount": 0,
            "total": 0,
            "current": 1,
            "some_future_field": "unrecognised",
        });
        assert!(SearchResponse::parse(&raw).is_ok());
    }

    #[test]
    fn require_object_rejects_an_array() {
        let raw = serde_json::json!([1, 2, 3]);
        assert!(super::require_object(&raw).is_err());
    }

    #[test]
    fn require_object_accepts_an_object() {
        let raw = serde_json::json!({"product_version": "24.7"});
        assert!(super::require_object(&raw).is_ok());
    }
}
