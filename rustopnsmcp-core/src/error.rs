//! The one error type for the core crate.
//!
//! No variant carries a URL or a header: the device's API key and secret
//! travel in an `Authorization` header on every request, and an error string
//! is the easiest place for one to leak.

/// Maximum bytes for server-supplied detail text before truncation.
const MAX_DETAIL_BYTES: usize = 300;

/// Anything that can go wrong talking to an OPNsense device.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpnsenseError {
    /// The device returned a non-success status.
    ///
    /// Deliberately carries no URL. The `detail` field is bounded and
    /// sanitized at construction to prevent unbounded server-supplied text
    /// from reaching logs or audit records.
    #[error("device returned {status}: {detail}")]
    Upstream {
        /// HTTP status code.
        status: u16,
        /// Server-supplied detail, bounded and sanitized at construction.
        detail: String,
    },

    /// A response did not match the shape the model expects.
    #[error("unexpected response shape: {0}")]
    Malformed(String),

    /// The device's configuration in `devices.json` is invalid.
    #[error("{0}")]
    Config(String),

    /// Transport, TLS, timeout, or rate-limit failure from `mecmcp-http`.
    ///
    /// The underlying error is classified and rendered without URLs, because
    /// several `HttpError` variants carry a redacted URL. This crate's
    /// contract is that no variant carries a URL of any kind, including the
    /// source chain.
    #[error("{}", http_error_class(.0))]
    Http(mecmcp_http::HttpError),

    /// Inventory load or validation failure.
    #[error(transparent)]
    Inventory(#[from] mecmcp_inventory::InventoryError),

    /// Credential load failure — bad mode, symlink, oversized, or absent.
    #[error(transparent)]
    Secret(#[from] mecmcp_secret::SecretError),
}

impl From<mecmcp_http::HttpError> for OpnsenseError {
    fn from(error: mecmcp_http::HttpError) -> Self {
        Self::Http(error)
    }
}

/// Render the class of HTTP failure without the URL.
fn http_error_class(error: &mecmcp_http::HttpError) -> String {
    use mecmcp_http::HttpError;
    match error {
        HttpError::InvalidUrl { .. } => "invalid URL".to_owned(),
        HttpError::InsecureScheme { scheme, .. } => {
            format!("insecure scheme '{scheme}' (only https:// is allowed)")
        }
        HttpError::MissingHost { .. } => "URL has no host component".to_owned(),
        HttpError::UrlHasEmbeddedCredentials { .. } => "URL embeds credentials".to_owned(),
        HttpError::InvalidHeaderName { name } => format!("invalid header name '{name}'"),
        HttpError::FramingHeaderNotAllowed { name } => {
            format!("header '{name}' cannot be supplied")
        }
        HttpError::InvalidHeaderValue { name } => format!("invalid header value for '{name}'"),
        HttpError::ConfigValidation { field, detail } => {
            format!("configuration field '{field}': {detail}")
        }
        HttpError::NoCryptoProvider => "no rustls CryptoProvider installed".to_owned(),
        HttpError::InvalidRootCertificate { index, .. } => {
            format!("extra_root_certificates[{index}] is not a usable certificate")
        }
        HttpError::ClientConstruction { .. } => "failed to construct HTTP client".to_owned(),
        HttpError::Timeout { timeout, .. } => format!("request timed out after {timeout:?}"),
        HttpError::QueueFull => "HTTP client queue is full".to_owned(),
        HttpError::LimiterClosed => "HTTP client concurrency limiter is closed".to_owned(),
        HttpError::Connect { .. } => "failed to connect".to_owned(),
        HttpError::ResponseTooLarge { limit, .. } => {
            format!("response exceeded the {limit}-byte limit")
        }
        HttpError::BodyRead { .. } => "failed to read response body".to_owned(),
        HttpError::RequestFailed { .. } => "request failed".to_owned(),
    }
}

/// Bound and sanitize server-supplied detail text.
///
/// Caps the text to [`MAX_DETAIL_BYTES`] and strips control characters,
/// including newlines and carriage returns, so a single-line error stays a
/// single line. A hostile or merely broken upstream cannot inject unbounded
/// text or forge log entries.
pub(crate) fn sanitize_detail(input: &str) -> String {
    let bounded = input
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DETAIL_BYTES)
        .collect::<String>();

    if bounded.len() < input.len() {
        format!("{bounded} [truncated]")
    } else {
        bounded
    }
}

#[cfg(test)]
mod tests {
    use super::OpnsenseError;

    /// The device's API key and secret must never reach an error string.
    #[test]
    fn no_variant_carries_a_url_or_header() {
        use std::error::Error;

        let test_cases: Vec<OpnsenseError> = vec![
            OpnsenseError::Upstream {
                status: 401,
                detail: "unauthorized".to_owned(),
            },
            OpnsenseError::Malformed("test error".to_owned()),
            OpnsenseError::Config("test config error".to_owned()),
            OpnsenseError::Http(mecmcp_http::HttpError::Timeout {
                url: mecmcp_http::SafeUrl::from_unparsed("https://opnsense.example/api/test"),
                timeout: std::time::Duration::from_secs(30),
            }),
            OpnsenseError::Http(mecmcp_http::HttpError::Connect {
                url: mecmcp_http::SafeUrl::from_unparsed("https://opnsense.example/api/test"),
                detail: "connection refused".to_owned(),
            }),
        ];

        for error in test_cases {
            let rendered = error.to_string();
            assert!(
                !rendered.contains("://"),
                "variant rendered a URL: {rendered}"
            );
            assert!(
                !rendered.contains("Authorization"),
                "variant rendered a header: {rendered}"
            );

            let alternate = format!("{error:#}");
            assert!(
                !alternate.contains("://"),
                "source chain contains URL: {alternate}"
            );

            let mut current: &dyn Error = &error;
            while let Some(source) = current.source() {
                let source_str = source.to_string();
                assert!(
                    !source_str.contains("://"),
                    "source chain contains URL: {source_str}"
                );
                current = source;
            }
        }
    }

    /// Detail text is bounded and stripped of control characters, so a
    /// hostile upstream cannot inject unbounded text or forge log entries.
    #[test]
    fn detail_is_bounded_and_control_chars_stripped() {
        let raw = format!("line1\nline2\r{}", "x".repeat(400));
        let sanitized = super::sanitize_detail(&raw);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(sanitized.len() < raw.len());
        assert!(sanitized.ends_with("[truncated]"));
    }
}
