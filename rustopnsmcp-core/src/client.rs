//! One HTTP client per OPNsense device, over `mecmcp-http`.
//!
//! Each device gets its own client with isolated rate limits, so a slow or
//! wedged device cannot exhaust a pool shared with healthy ones.
//!
//! OPNsense authenticates with HTTP Basic auth: the API key as the username,
//! the API secret as the password. The combined `key:secret` value is built
//! from two `OutboundSecret`s and immediately re-wrapped in one, so it never
//! sits in a `Debug`- or `Serialize`-reachable field. TLS is always verified;
//! a device behind a private CA supplies `ca_pem_path` rather than any
//! insecure-skip-verify knob, which `mecmcp-http` does not offer at any
//! layer.

use crate::endpoints;
use crate::error::OpnsenseError;
use crate::inventory::Device;
use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_secret::OutboundSecret;
use std::time::Duration;

/// Requests in flight to one device.
const MAX_CONCURRENT: usize = 8;
/// Callers permitted to wait behind those.
const MAX_QUEUED: usize = 32;
/// Whole-request deadline, covering permit acquisition and send.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body accepted, enforced as it streams.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A client bound to one OPNsense device.
#[derive(Clone)]
pub struct OpnsenseClient {
    endpoint: String,
    http: std::sync::Arc<HttpClient>,
    basic_auth: OutboundSecret,
}

impl OpnsenseClient {
    /// Build a client for one device, loading its API key and secret.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError`] when:
    /// - Either credential cannot be loaded from env or file
    /// - The CA PEM is unreadable
    /// - The endpoint is not HTTPS
    /// - The HTTP client fails to initialize
    pub fn new(device: Device) -> Result<Self, OpnsenseError> {
        device.validate()?;

        let api_key = device.load_api_key()?;
        let api_secret = device.load_api_secret()?;
        let basic_auth = build_basic_auth(&api_key, &api_secret);

        let mut extra_root_certificates = Vec::new();
        if let Some(path) = &device.ca_pem_path {
            let pem = std::fs::read_to_string(path).map_err(|error| {
                OpnsenseError::Config(format!("ca_pem_path {}: {error}", path.display()))
            })?;
            extra_root_certificates.push(pem);
        }

        let config = HttpClientConfig {
            request_timeout: REQUEST_TIMEOUT,
            max_concurrent_requests: MAX_CONCURRENT,
            max_queued_requests: MAX_QUEUED,
            max_response_bytes: MAX_RESPONSE_BYTES,
            user_agent: concat!("rustopnsmcp/", env!("CARGO_PKG_VERSION")).to_owned(),
            extra_root_certificates,
            ..HttpClientConfig::default()
        };

        let http = HttpClient::new(config)?;
        Ok(Self {
            endpoint: device.endpoint,
            http: std::sync::Arc::new(http),
            basic_auth,
        })
    }

    /// Issue a GET against an absolute API path.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::Upstream`] for non-2xx statuses,
    /// [`OpnsenseError::Http`] for network or protocol errors, and
    /// [`OpnsenseError::Malformed`] for a response that is not valid JSON.
    pub async fn get(&self, path: &str) -> Result<serde_json::Value, OpnsenseError> {
        let url = format!("{}{path}", self.endpoint.trim_end_matches('/'));
        let request = HttpRequest::new(Method::Get, &url)?
            .header("Accept", "application/json")?
            .secret_header("Authorization", &self.basic_auth)?;

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return Err(Self::upstream_error(response.status(), response.body()));
        }

        serde_json::from_slice(response.body())
            .map_err(|error| OpnsenseError::Malformed(error.to_string()))
    }

    /// Issue a POST with a JSON body against an absolute API path.
    ///
    /// OPNsense's `search_*` endpoints take their filter, sort, and paging
    /// parameters as a POST body rather than as a query string.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, OpnsenseError> {
        let url = format!("{}{path}", self.endpoint.trim_end_matches('/'));

        let body_bytes = serde_json::to_vec(body).map_err(|error| {
            OpnsenseError::Malformed(format!("failed to serialize body: {error}"))
        })?;

        let request = HttpRequest::new(Method::Post, &url)?
            .header("Accept", "application/json")?
            .header("Content-Type", "application/json")?
            .secret_header("Authorization", &self.basic_auth)?
            .body(body_bytes);

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return Err(Self::upstream_error(response.status(), response.body()));
        }

        serde_json::from_slice(response.body())
            .map_err(|error| OpnsenseError::Malformed(error.to_string()))
    }

    fn upstream_error(status: u16, body: &[u8]) -> OpnsenseError {
        let sanitized = crate::error::sanitize_detail(&String::from_utf8_lossy(body));
        let detail = mecmcp_redact::redact_text(&sanitized);
        OpnsenseError::Upstream { status, detail }
    }

    /// Fetch one firewall alias by UUID.
    ///
    /// OPNsense's `getItem` wraps the item's fields under a top-level
    /// `"alias"` key and does not echo the UUID back into the body, so this
    /// unwraps that envelope and inserts `uuid` itself, which is what
    /// [`crate::changeset::Preimage`] keys entries by.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::WriteRefused`] for a malformed UUID,
    /// [`OpnsenseError::Upstream`] with `status: 404` if the alias does not
    /// exist, and [`OpnsenseError::Malformed`] if the response has no
    /// `"alias"` object.
    pub async fn get_alias_item(&self, uuid: &str) -> Result<serde_json::Value, OpnsenseError> {
        validate_uuid(uuid)?;
        let raw = self.get(&endpoints::aliases_get_item(uuid)).await?;
        interpret_get_item_response(raw, uuid)
    }

    /// Search for an alias by exact name.
    ///
    /// Used to reconcile a `create` whose response was lost to a transport
    /// failure: the device may have persisted it even though this process
    /// never saw a confirming response, and this is the only way to check
    /// without a UUID to fetch by.
    ///
    /// # Errors
    ///
    /// As [`Self::post`].
    async fn find_alias_uuid_by_name(&self, name: &str) -> Result<Option<String>, OpnsenseError> {
        let body = serde_json::json!({
            "current": 1,
            "rowCount": 50,
            "searchPhrase": name,
        });
        let raw = self.post(endpoints::ALIASES_SEARCH, &body).await?;
        let Some(rows) = raw.get("rows").and_then(serde_json::Value::as_array) else {
            return Ok(None);
        };
        Ok(rows
            .iter()
            .find(|row| row.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .and_then(|row| row.get("uuid").and_then(serde_json::Value::as_str))
            .map(str::to_owned))
    }

    /// Create a firewall alias.
    ///
    /// Persists to `config.xml` immediately; the write is not live until
    /// [`Self::reconfigure_aliases`] runs. `body` is wrapped under `"alias"`
    /// per OPNsense's write convention.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::WriteRefused`] if the device reports
    /// `result != "saved"` (a validation failure, reported with HTTP 200), or
    /// if the response has no `uuid`.
    pub async fn add_alias(&self, body: &serde_json::Value) -> Result<String, OpnsenseError> {
        let payload = serde_json::json!({ "alias": body });
        let raw = self.post(endpoints::ALIASES_ADD_ITEM, &payload).await?;
        Self::require_saved(&raw)?;
        raw.get("uuid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| OpnsenseError::Malformed("addItem response has no uuid".to_owned()))
    }

    /// Update a firewall alias by UUID.
    ///
    /// Same immediate-persist-but-not-loaded semantics as [`Self::add_alias`].
    ///
    /// # Errors
    ///
    /// As [`Self::add_alias`], plus [`OpnsenseError::WriteRefused`] for a
    /// malformed UUID.
    pub async fn set_alias(
        &self,
        uuid: &str,
        body: &serde_json::Value,
    ) -> Result<(), OpnsenseError> {
        validate_uuid(uuid)?;
        let payload = serde_json::json!({ "alias": body });
        let raw = self
            .post(&endpoints::aliases_set_item(uuid), &payload)
            .await?;
        Self::require_saved(&raw)
    }

    /// Delete a firewall alias by UUID.
    ///
    /// Idempotent: OPNsense reports `result: "not found"` for a UUID that no
    /// longer exists, which is treated as success so a retried delete is
    /// safe to repeat.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::WriteRefused`] for a malformed UUID or a
    /// device response naming neither `"deleted"` nor `"not found"`.
    pub async fn delete_alias(&self, uuid: &str) -> Result<(), OpnsenseError> {
        validate_uuid(uuid)?;
        let raw = self
            .post(&endpoints::aliases_del_item(uuid), &serde_json::json!({}))
            .await?;
        match raw.get("result").and_then(serde_json::Value::as_str) {
            Some("deleted" | "not found") => Ok(()),
            _ => Err(OpnsenseError::WriteRefused(format!(
                "device did not confirm the delete: {}",
                crate::error::sanitize_detail(&raw.to_string())
            ))),
        }
    }

    /// Load staged alias writes into the live `pf` alias tables.
    ///
    /// This is the closest thing to a commit OPNsense's alias API has:
    /// nothing written by [`Self::add_alias`], [`Self::set_alias`], or
    /// [`Self::delete_alias`] takes effect until this runs.
    ///
    /// # Errors
    ///
    /// Returns [`OpnsenseError::WriteRefused`] if the device does not report
    /// success.
    pub async fn reconfigure_aliases(&self) -> Result<(), OpnsenseError> {
        let raw = self
            .post(endpoints::ALIASES_RECONFIGURE, &serde_json::json!({}))
            .await?;
        interpret_reconfigure_response(&raw)
    }

    /// Require an `addItem`/`setItem` response to report `result: "saved"`.
    ///
    /// OPNsense reports a validation failure as HTTP 200 with
    /// `{"result": "failed", "validations": {...}}`, not as a non-2xx
    /// status, so [`Self::post`] alone cannot detect it.
    fn require_saved(raw: &serde_json::Value) -> Result<(), OpnsenseError> {
        if raw.get("result").and_then(serde_json::Value::as_str) == Some("saved") {
            return Ok(());
        }
        let detail = raw.get("validations").unwrap_or(raw).to_string();
        Err(OpnsenseError::WriteRefused(format!(
            "device rejected the write: {}",
            crate::error::sanitize_detail(&detail)
        )))
    }
}

/// Interpret a raw `getItem` response into the pre-image shape.
///
/// OPNsense's `getItem` wraps the item's fields under a top-level `"alias"`
/// key and does not echo the UUID back into the body, so this unwraps that
/// envelope and inserts `uuid` itself, which is what
/// [`crate::changeset::Preimage`] keys entries by.
///
/// OPNsense answers an unknown UUID with HTTP 200 and a bare `[]`, not a 404
/// status — a device response this crate's HTTP layer never turns into an
/// error — so that shape must be translated into the same "not found" signal
/// callers of [`crate::changeset::ControllerOps::fetch_alias`] already expect
/// from a real 404. Without this, every delete would be misread as having
/// left the alias in place.
///
/// A URL-table alias's body can carry `username`/`password` for an
/// authenticated fetch. Those fields are dropped here, at the one place every
/// pre-image is built, rather than trusted to `WRITABLE_FIELDS` or the
/// caller: the pre-image is echoed back in previews and persisted in the
/// change-set store, and neither is a place for a credential to end up.
///
/// # Errors
///
/// Returns [`OpnsenseError::Upstream`] with `status: 404` for an empty-array
/// response, and [`OpnsenseError::Malformed`] if the response has no
/// `"alias"` object.
fn interpret_get_item_response(
    raw: serde_json::Value,
    uuid: &str,
) -> Result<serde_json::Value, OpnsenseError> {
    if matches!(&raw, serde_json::Value::Array(items) if items.is_empty()) {
        return Err(OpnsenseError::Upstream {
            status: 404,
            detail: "alias not found".to_owned(),
        });
    }

    let Some(alias) = raw.get("alias").filter(|value| value.is_object()) else {
        return Err(OpnsenseError::Malformed(
            "getItem response has no alias object".to_owned(),
        ));
    };

    let mut body = alias.clone();
    let object = body
        .as_object_mut()
        .expect("checked is_object via filter above");
    object.remove("username");
    object.remove("password");
    object.insert(
        "uuid".to_owned(),
        serde_json::Value::String(uuid.to_owned()),
    );
    Ok(body)
}

/// Interpret a raw `reconfigure` response.
///
/// A missing `status` field is not evidence of success — only an explicit
/// `"ok"` is. Treating an ambiguous or absent field as success is exactly the
/// "probably fine" default this server must not take: a genuine failure with
/// a differently-shaped body would otherwise be recorded as `Applied`.
///
/// # Errors
///
/// Returns [`OpnsenseError::WriteRefused`] for anything but `status: "ok"`.
fn interpret_reconfigure_response(raw: &serde_json::Value) -> Result<(), OpnsenseError> {
    match raw.get("status").and_then(serde_json::Value::as_str) {
        Some("ok") => Ok(()),
        _ => Err(OpnsenseError::WriteRefused(format!(
            "reconfigure did not report success: {}",
            crate::error::sanitize_detail(&raw.to_string())
        ))),
    }
}

/// Validate an alias UUID before it is interpolated into a URL path.
///
/// OPNsense alias UUIDs are canonical 36-character UUIDs
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, hex digits and hyphens only).
/// Restricting to that exact shape means a malformed value can never smuggle
/// an extra path segment, a `..`, or a query string into a request built by
/// `format!`.
///
/// # Errors
///
/// Returns [`OpnsenseError::WriteRefused`] if `uuid` is not that shape.
pub fn validate_uuid(uuid: &str) -> Result<(), OpnsenseError> {
    let is_canonical = uuid.len() == 36
        && uuid.bytes().enumerate().all(|(i, byte)| match i {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });

    if is_canonical {
        Ok(())
    } else {
        Err(OpnsenseError::WriteRefused(format!(
            "'{uuid}' is not a canonical UUID"
        )))
    }
}

/// Build the body `rollback_mutation` sends to restore an update's or
/// delete's pre-image state.
///
/// `prior` is `getItem` shape (option fields as `{value, selected}` maps);
/// `setItem`/`addItem` require the flat shape. Replaying `prior` verbatim
/// either gets refused as malformed or silently drops a field. Pulled out as
/// its own function, rather than inlining `flatten_for_write(prior)` at each
/// call site, so the exact value the wire call receives is directly
/// testable without a live device.
fn rollback_body(prior: &serde_json::Value) -> serde_json::Value {
    crate::changeset::flatten_for_write(prior)
}

impl crate::changeset::ControllerOps for OpnsenseClient {
    async fn apply_mutation(
        &self,
        mutation: &crate::changeset::StagedMutation,
    ) -> Result<Option<String>, OpnsenseError> {
        use crate::changeset::StagedMutation;

        match mutation {
            StagedMutation::Create { body } => self.add_alias(body).await.map(Some),
            StagedMutation::Update { uuid, body } => {
                self.set_alias(uuid, body).await?;
                Ok(None)
            }
            StagedMutation::Delete { uuid } => {
                self.delete_alias(uuid).await?;
                Ok(None)
            }
        }
    }

    async fn rollback_mutation(
        &self,
        mutation: &crate::changeset::StagedMutation,
        prior_value: Option<&serde_json::Value>,
        created_uuid: Option<&str>,
    ) -> Result<(), OpnsenseError> {
        use crate::changeset::StagedMutation;

        match mutation {
            StagedMutation::Create { .. } => {
                let uuid = created_uuid.ok_or_else(|| {
                    OpnsenseError::Malformed("rollback create: no created uuid provided".to_owned())
                })?;
                self.delete_alias(uuid).await
            }
            StagedMutation::Update { uuid, .. } => {
                let prior = prior_value.ok_or_else(|| {
                    OpnsenseError::Malformed(format!("rollback update {uuid}: no prior value"))
                })?;
                self.set_alias(uuid, &rollback_body(prior)).await
            }
            StagedMutation::Delete { uuid } => {
                let prior = prior_value.ok_or_else(|| {
                    OpnsenseError::Malformed(format!("rollback delete {uuid}: no prior value"))
                })?;
                // This runs whenever reconciliation read an indeterminate
                // delete as `NotApplied` or errored outright — either of
                // which can be wrong, the same way an update's `NotApplied`
                // read can be wrong (see `flatten_for_write`'s field-order
                // sensitivity). If the alias is still there under this same
                // uuid, the delete never landed and there is nothing to
                // restore; re-creating it anyway would leave a duplicate
                // under a fresh uuid rather than the idempotent no-op this
                // rollback is supposed to be.
                if self.fetch_alias(uuid).await?.is_some() {
                    return Ok(());
                }
                // `uuid` is not in `WRITABLE_FIELDS`, so flattening also
                // drops the bookkeeping key `get_alias_item` inserted; the
                // device assigns a fresh one on re-create.
                self.add_alias(&rollback_body(prior)).await.map(|_| ())
            }
        }
    }

    async fn preimage_matches(
        &self,
        preimage: &crate::changeset::Preimage,
        mutations: &[crate::changeset::StagedMutation],
    ) -> Result<bool, OpnsenseError> {
        for mutation in mutations {
            let Some(uuid) = mutation.resource_uuid() else {
                continue;
            };

            let Some(recorded) = preimage.get(uuid) else {
                return Ok(false);
            };

            let current = self.fetch_alias(uuid).await?;
            match current {
                Some(live) if live == recorded => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    async fn fetch_alias(&self, uuid: &str) -> Result<Option<serde_json::Value>, OpnsenseError> {
        match self.get_alias_item(uuid).await {
            Ok(body) => Ok(Some(body)),
            Err(OpnsenseError::Upstream { status: 404, .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn reconfigure(&self) -> Result<(), OpnsenseError> {
        self.reconfigure_aliases().await
    }

    async fn reconcile_indeterminate(
        &self,
        mutation: &crate::changeset::StagedMutation,
    ) -> Result<crate::changeset::Reconciled, OpnsenseError> {
        use crate::changeset::{Reconciled, StagedMutation, flatten_for_write};

        match mutation {
            StagedMutation::Create { body } => {
                let Some(name) = body.get("name").and_then(serde_json::Value::as_str) else {
                    return Ok(Reconciled::NotApplied);
                };
                Ok(match self.find_alias_uuid_by_name(name).await? {
                    Some(uuid) => Reconciled::Applied(Some(uuid)),
                    None => Reconciled::NotApplied,
                })
            }
            StagedMutation::Update { uuid, body } => {
                let Some(current) = self.fetch_alias(uuid).await? else {
                    return Ok(Reconciled::NotApplied);
                };
                let flattened = flatten_for_write(&current);
                let landed = body.as_object().is_some_and(|fields| {
                    fields
                        .iter()
                        .all(|(key, value)| flattened.get(key) == Some(value))
                });
                Ok(if landed {
                    Reconciled::Applied(None)
                } else {
                    Reconciled::NotApplied
                })
            }
            StagedMutation::Delete { uuid } => Ok(match self.fetch_alias(uuid).await? {
                None => Reconciled::Applied(None),
                Some(_) => Reconciled::NotApplied,
            }),
        }
    }
}

/// Build the `Authorization: Basic ...` header value from the API key and
/// secret, without ever materializing the combined credential outside an
/// `OutboundSecret`-owned value, or a zeroized buffer, for longer than the
/// encode itself takes.
fn build_basic_auth(api_key: &OutboundSecret, api_secret: &OutboundSecret) -> OutboundSecret {
    use base64::Engine as _;
    use zeroize::Zeroizing;

    let combined = Zeroizing::new(format!("{}:{}", api_key.expose(), api_secret.expose()));
    let encoded =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(combined.as_bytes()));
    OutboundSecret::new_unchecked(format!("Basic {}", *encoded))
}

#[cfg(test)]
mod tests {
    use super::OpnsenseClient;

    /// The Basic-auth header must combine key and secret with exactly one
    /// colon, base64-encoded, and it must never surface either value in
    /// plaintext through anything but the header itself.
    #[test]
    fn basic_auth_combines_key_and_secret() {
        use base64::Engine as _;
        use mecmcp_secret::OutboundSecret;

        let key = OutboundSecret::new_unchecked("mykey".to_owned());
        let secret = OutboundSecret::new_unchecked("mysecret".to_owned());
        let header = super::build_basic_auth(&key, &secret);

        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(b"mykey:mysecret")
        );
        assert_eq!(header.expose(), expected);
    }

    /// A device that fails validation (e.g. a plaintext endpoint) must be
    /// refused before any HTTP client is built.
    #[test]
    fn an_invalid_device_is_refused_before_client_construction() {
        let device: crate::inventory::Device = serde_json::from_str(
            r#"{
                "endpoint": "http://fw.example.org",
                "api_key_env": "OPNSENSE_TEST_KEY",
                "api_secret_env": "OPNSENSE_TEST_SECRET"
            }"#,
        )
        .expect("parses");
        assert!(OpnsenseClient::new(device).is_err());
    }

    /// A canonical UUID is accepted; anything that could smuggle an extra
    /// path segment, `..`, or a query string into a `format!`-built URL must
    /// be refused before it ever reaches one.
    #[test]
    fn validate_uuid_accepts_canonical_and_refuses_everything_else() {
        assert!(super::validate_uuid("dddddddd-dddd-4ddd-8ddd-dddddddddddd").is_ok());

        for bad in [
            "",
            "not-a-uuid",
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd/../etc",
            "dddddddd-dddd-4ddd-8ddd-ddddddddddd",
            "dddddddd/dddd/4ddd/8ddd/dddddddddddd",
            "dddddddd-dddd-4ddd-8ddd-ddddddddddd?x=1",
        ] {
            assert!(super::validate_uuid(bad).is_err(), "{bad} must be refused");
        }
    }

    /// OPNsense reports a validation failure as HTTP 200 with
    /// `result: "failed"`, not as a non-2xx status. `require_saved` is the
    /// only thing standing between that and a write this server reports as
    /// successful.
    #[test]
    fn require_saved_rejects_a_200_with_result_failed() {
        let raw =
            serde_json::json!({"result": "failed", "validations": {"alias.name": "required"}});
        let error = OpnsenseClient::require_saved(&raw).expect_err("failed must be rejected");
        assert!(error.to_string().contains("name"), "{error}");
    }

    #[test]
    fn require_saved_accepts_result_saved() {
        let raw = serde_json::json!({"result": "saved", "uuid": "x"});
        assert!(OpnsenseClient::require_saved(&raw).is_ok());
    }

    /// OPNsense answers an unknown UUID with HTTP 200 and a bare `[]`, not a
    /// 404 — without this translation, `fetch_alias`'s `Ok(None)` arm (which
    /// only fires on a real 404) can never be reached, and every successful
    /// delete would be misread as having left the alias in place.
    #[test]
    fn get_item_interprets_an_empty_array_as_not_found() {
        let raw = serde_json::json!([]);
        let error = super::interpret_get_item_response(raw, "u1").expect_err("must be refused");
        assert!(
            matches!(
                error,
                crate::error::OpnsenseError::Upstream { status: 404, .. }
            ),
            "{error}"
        );
    }

    /// A response with no `"alias"` object — the fallback the old code took
    /// instead of refusing — must be rejected rather than silently accepted
    /// as the alias body.
    #[test]
    fn get_item_rejects_a_response_with_no_alias_object() {
        let raw = serde_json::json!({"unrelated": true});
        assert!(super::interpret_get_item_response(raw, "u1").is_err());
    }

    /// A well-formed response is unwrapped from its `"alias"` envelope and
    /// gets the UUID inserted, since `getItem` never echoes it back.
    #[test]
    fn get_item_unwraps_the_alias_envelope_and_inserts_the_uuid() {
        let raw = serde_json::json!({"alias": {"name": "web_servers"}});
        let body = super::interpret_get_item_response(raw, "u1").expect("parses");
        assert_eq!(body.get("name"), Some(&serde_json::json!("web_servers")));
        assert_eq!(body.get("uuid"), Some(&serde_json::json!("u1")));
    }

    /// A URL-table alias's `username`/`password` must never survive into the
    /// pre-image: it is echoed back in previews and persisted in the
    /// change-set store, and neither is a place for a credential to end up.
    #[test]
    fn get_item_strips_username_and_password_from_the_body() {
        let raw = serde_json::json!({
            "alias": {
                "name": "blocklist",
                "type": "urltable",
                "content": "https://example.org/list.txt",
                "username": "svc-account",
                "password": "hunter2",
            }
        });
        let body = super::interpret_get_item_response(raw, "u1").expect("parses");
        assert!(body.get("username").is_none());
        assert!(body.get("password").is_none());
        assert_eq!(body.get("name"), Some(&serde_json::json!("blocklist")));
    }

    /// `rollback_mutation`'s update and delete arms both send this value to
    /// `setItem`/`addItem`. Without this test, nothing in the suite ever
    /// checks that the flattened shape rollback actually needs is what
    /// reaches the wire, only that `flatten_for_write` behaves correctly in
    /// isolation.
    #[test]
    fn rollback_body_is_the_flattened_prior_value() {
        let prior = serde_json::json!({
            "uuid": "11111111-1111-4111-8111-111111111111",
            "name": "web_servers",
            "type": {
                "host": {"value": "Host(s)", "selected": 1},
                "network": {"value": "Network(s)", "selected": 0},
            },
        });

        let body = super::rollback_body(&prior);

        assert_eq!(body.get("name"), Some(&serde_json::json!("web_servers")));
        assert_eq!(body.get("type"), Some(&serde_json::json!("host")));
        // The read-only uuid must not be replayed as a write field.
        assert!(body.get("uuid").is_none());
    }

    /// A missing `status` field must not be read as success — only an
    /// explicit `"ok"` is accepted, so a genuine failure with a
    /// differently-shaped body cannot be misrecorded as applied.
    #[test]
    fn reconfigure_requires_an_explicit_ok_status() {
        assert!(
            super::interpret_reconfigure_response(&serde_json::json!({"status": "ok"})).is_ok()
        );
        assert!(super::interpret_reconfigure_response(&serde_json::json!({})).is_err());
        assert!(
            super::interpret_reconfigure_response(&serde_json::json!({"status": "failed"}))
                .is_err()
        );
    }
}
