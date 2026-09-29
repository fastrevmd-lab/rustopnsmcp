//! End-to-end regression test for the delete-rollback idempotency fix.
//!
//! `rollback_mutation`'s `Delete` arm runs whenever an indeterminate delete's
//! reconciliation read `NotApplied` or errored outright — either of which can
//! be wrong. Before this fix it unconditionally re-created the alias from the
//! pre-image via `addItem`. If the delete had in fact landed, that recreated
//! an alias `apply_sequentially` believed it had removed; if the delete had
//! *not* landed (the alias is still there under its original uuid), a
//! `setItem`-style re-create is not idempotent the way an update's rollback
//! is — OPNsense either rejects a duplicate name or, for firewall rules in a
//! later phase with no name uniqueness, would create a live duplicate.
//!
//! This drives the real [`OpnsenseClient`] (not the `apply.rs` mock) against
//! a local TLS fixture server, the same harness `read_tools.rs` uses. The
//! `addItem` route is deliberately left unregistered: if the fix regresses
//! and rollback re-creates the alias anyway, that request has nowhere to
//! land and the call errors instead of silently passing.

use rustopnsmcp_core::changeset::{ControllerOps, StagedMutation};
use rustopnsmcp_core::client::OpnsenseClient;
use rustopnsmcp_core::inventory::Device;
use std::collections::HashMap;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;

fn tls_material() -> (String, rustls::ServerConfig) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let cert_pem = cert.pem();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .expect("server config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    (cert_pem, server_config)
}

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Serve fixture responses keyed by request path; anything unmapped answers
/// 404, which is exactly what proves an unwanted `addItem` call would fail
/// rather than silently succeed.
fn serve_fixtures(
    listener: tokio::net::TcpListener,
    server_config: rustls::ServerConfig,
    routes: HashMap<String, serde_json::Value>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let routes = Arc::clone(&routes);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };

                let mut header_bytes = Vec::new();
                let mut byte = [0u8; 1];
                while tls.read_exact(&mut byte).await.is_ok() {
                    header_bytes.push(byte[0]);
                    if header_bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let headers = String::from_utf8_lossy(&header_bytes);
                let path = headers
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();

                if let Some(content_length) = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                {
                    let mut body = vec![0u8; content_length];
                    let _ = tls.read_exact(&mut body).await;
                }

                let response = match routes.get(&path) {
                    Some(fixture) => {
                        let body = fixture.to_string();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                    None => {
                        let body = format!(r#"{{"error":"no fixture for {path}"}}"#);
                        format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    }
                };
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
}

async fn bind_local() -> (tokio::net::TcpListener, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    (listener, port)
}

fn write_pem(pem: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(pem.as_bytes()).expect("write pem");
    file.flush().expect("flush");
    file
}

fn write_secret(value: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(value.as_bytes()).expect("write secret");
    file.flush().expect("flush");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(file.path())
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(file.path(), perms).expect("chmod");
    }
    file
}

fn device_for(
    port: u16,
    ca_pem_path: &std::path::Path,
    api_key_file: &std::path::Path,
    api_secret_file: &std::path::Path,
) -> Device {
    serde_json::from_value(serde_json::json!({
        "endpoint": format!("https://localhost:{port}"),
        "api_key_file": api_key_file,
        "api_secret_file": api_secret_file,
        "ca_pem_path": ca_pem_path,
    }))
    .expect("device parses")
}

async fn client_against(routes: HashMap<String, serde_json::Value>) -> OpnsenseClient {
    ensure_crypto_provider();
    let (cert_pem, server_config) = tls_material();
    let (listener, port) = bind_local().await;
    serve_fixtures(listener, server_config, routes);

    let ca_file = write_pem(&cert_pem);
    let key_file = write_secret("test-key");
    let secret_file = write_secret("test-secret");
    let device = device_for(port, ca_file.path(), key_file.path(), secret_file.path());

    std::mem::forget(ca_file);
    std::mem::forget(key_file);
    std::mem::forget(secret_file);

    OpnsenseClient::new(device).expect("client builds")
}

/// Rolling back a delete whose reconciliation could not confirm it landed,
/// when the alias in fact still exists, must be a no-op — not an attempt to
/// re-create it. Before the fix, this unconditionally called `addItem`,
/// which has no fixture registered here and would fail the request.
#[tokio::test]
async fn rollback_of_a_delete_that_still_exists_is_a_noop_not_a_recreate() {
    let uuid = "11111111-1111-4111-8111-111111111111";
    let mut routes = HashMap::new();
    routes.insert(
        rustopnsmcp_core::endpoints::aliases_get_item(uuid),
        serde_json::json!({
            "alias": {
                "name": "still_here",
                "type": {"host": {"value": "Host(s)", "selected": 1}},
            }
        }),
    );
    // Deliberately no ALIASES_ADD_ITEM route.
    let client = client_against(routes).await;

    let mutation = StagedMutation::delete(uuid);
    let prior = serde_json::json!({"uuid": uuid, "name": "still_here", "type": "host"});

    client
        .rollback_mutation(&mutation, Some(&prior), None)
        .await
        .expect(
            "rollback of a delete whose alias still exists must be a no-op, not attempt a \
             re-create against a device with no addItem fixture",
        );
}

/// The mirror case: the alias is genuinely gone, so rollback must actually
/// re-create it from the pre-image.
#[tokio::test]
async fn rollback_of_a_delete_that_landed_recreates_the_alias() {
    let uuid = "22222222-2222-4222-8222-222222222222";
    let mut routes = HashMap::new();
    routes.insert(
        rustopnsmcp_core::endpoints::aliases_get_item(uuid),
        serde_json::json!([]),
    );
    routes.insert(
        rustopnsmcp_core::endpoints::ALIASES_ADD_ITEM.to_owned(),
        serde_json::json!({"result": "saved", "uuid": "33333333-3333-4333-8333-333333333333"}),
    );
    let client = client_against(routes).await;

    let mutation = StagedMutation::delete(uuid);
    let prior = serde_json::json!({"uuid": uuid, "name": "gone", "type": "host"});

    client
        .rollback_mutation(&mutation, Some(&prior), None)
        .await
        .expect("rollback of a delete that actually landed must re-create the alias");
}
