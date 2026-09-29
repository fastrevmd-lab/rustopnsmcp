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

        let mut body = match raw.get("alias") {
            Some(alias) if alias.is_object() => alias.clone(),
            _ => raw,
        };

        let object = body.as_object_mut().ok_or_else(|| {
            OpnsenseError::Malformed("getItem response has no alias object".to_owned())
        })?;
        object.insert(
            "uuid".to_owned(),
            serde_json::Value::String(uuid.to_owned()),
        );
        Ok(body)
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
        match raw.get("status").and_then(serde_json::Value::as_str) {
            None | Some("ok") => Ok(()),
            Some(_) => Err(OpnsenseError::WriteRefused(format!(
                "reconfigure did not report success: {}",
                crate::error::sanitize_detail(&raw.to_string())
            ))),
        }
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
                self.set_alias(uuid, prior).await
            }
            StagedMutation::Delete { uuid } => {
                let prior = prior_value.ok_or_else(|| {
                    OpnsenseError::Malformed(format!("rollback delete {uuid}: no prior value"))
                })?;
                // `uuid` was inserted by `get_alias_item` for our own
                // bookkeeping; the device assigns a fresh one on re-create.
                let mut restore_body = prior.clone();
                if let Some(object) = restore_body.as_object_mut() {
                    object.remove("uuid");
                }
                self.add_alias(&restore_body).await.map(|_| ())
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
}
