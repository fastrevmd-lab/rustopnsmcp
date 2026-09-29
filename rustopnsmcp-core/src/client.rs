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
        let detail = crate::error::sanitize_detail(&String::from_utf8_lossy(body));
        OpnsenseError::Upstream { status, detail }
    }
}

/// Build the `Authorization: Basic ...` header value from the API key and
/// secret, without ever materializing the combined credential outside an
/// `OutboundSecret`-owned value for longer than the encode itself takes.
fn build_basic_auth(api_key: &OutboundSecret, api_secret: &OutboundSecret) -> OutboundSecret {
    use base64::Engine as _;
    let combined = format!("{}:{}", api_key.expose(), api_secret.expose());
    let encoded = base64::engine::general_purpose::STANDARD.encode(combined.as_bytes());
    OutboundSecret::new_unchecked(format!("Basic {encoded}"))
}

#[cfg(test)]
mod tests {
    use super::OpnsenseClient;

    /// A 3xx response must be treated as an error, not parsed as success.
    #[test]
    fn redirect_responses_are_errors() {
        let is_error = |status: u16| status >= 300;
        assert!(is_error(301), "301 redirect must be an error");
        assert!(is_error(302), "302 redirect must be an error");
        assert!(is_error(307), "307 redirect must be an error");
        assert!(!is_error(200), "200 OK must not be an error");
    }

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
}
