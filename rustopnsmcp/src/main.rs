//! `rustopnsmcp` — enterprise MCP server for OPNsense.

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use mecmcp_audit::AuditFileSink;
use mecmcp_runtime::cli::Command;
use mecmcp_transport::serve_router;
use rmcp::ServiceExt;
use rustopnsmcp::cli::OpnsCli;
use rustopnsmcp::http_transport::build_http_router;
use rustopnsmcp::server::OpnsenseServer;
use rustopnsmcp_core::inventory::DeviceRegistry;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Install a minimal audit subscriber for token operations.
///
/// Token commands are dispatched before the server's full `init_audit`, so
/// without a subscriber every token mutation is written to disk having left
/// no record. A pre-existing subscriber already installed is not an error
/// worth refusing a token operation over.
fn init_token_audit() {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, filter::filter_fn, fmt};

    let audit_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(filter_fn(|metadata| metadata.target() == "audit"));

    let general_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_filter(filter_fn(|metadata| metadata.target() != "audit"));

    let _ = tracing_subscriber::registry()
        .with(audit_layer)
        .with(general_layer)
        .try_init();
}

/// Install the server's audit subscriber: stderr, an optional audit-file
/// sink, and optional journald — configured from the shared `--audit-*`
/// flags, the same way every sibling mecmcp server wires them.
///
/// # Errors
///
/// Returns an error when `--audit-redact` does not parse, or when
/// `mecmcp_audit::init_tracing` could not open a configured audit file or
/// construct the journald layer. A server that starts anyway is a server
/// that runs with no audit trail while believing it has one.
fn init_audit(args: &mecmcp_runtime::cli::Cli) -> Result<Option<Arc<AuditFileSink>>> {
    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    let audit_config = mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
        otel: None,
    };

    match mecmcp_audit::init_tracing(&audit_config) {
        Ok(Some(sink)) => Ok(Some(Arc::new(sink))),
        Ok(None) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("initializing audit tracing: {e}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // aws-lc-rs, not ring: every mecmcp server in this family standardizes on
    // this provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = OpnsCli::parse();

    if let Some(Command::Token { action }) = cli.common.command {
        init_token_audit();
        let known_tools: Vec<&str> = rustopnsmcp_core::tools::TOOL_NAMES.to_vec();
        return mecmcp_runtime::token_cmd::run(action, &[], &known_tools)
            .map_err(|error| anyhow::anyhow!("{error}"));
    }

    mecmcp_runtime::cli_validate::validate(&cli.common)
        .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;

    let audit_sink = init_audit(&cli.common)?;

    if cli.lab_mode() {
        tracing::warn!(
            target: "audit",
            "lab mode is enabled: change sets may be approved by their own creator, \
             recorded as a waiver rather than a genuine two-person approval"
        );
    }
    if cli.state_file.is_none() {
        tracing::warn!(
            target: "audit",
            "no --state-file configured: change sets, approvals, and previews are kept \
             in memory only and are lost on restart"
        );
    }

    let coordinator = rustopnsmcp::changeset_state::build_coordinator(
        cli.state_file.as_deref(),
        std::time::Duration::from_secs(cli.approval_timeout_secs),
        cli.lab_mode(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    let registry = Arc::new(DeviceRegistry::load(&cli.common.device_mapping)?);
    let server = OpnsenseServer::new(Arc::clone(&registry), cli.lab_mode(), coordinator)?;

    match cli.common.transport {
        mecmcp_runtime::cli::Transport::Stdio => {
            install_sighup_reload(registry, Some(server.clone()), None, audit_sink)?;
            serve_stdio(server).await
        }
        mecmcp_runtime::cli::Transport::StreamableHttp => {
            serve_http(server, &cli, registry, audit_sink).await
        }
    }
}

/// Load TLS configuration for the listener.
///
/// # Errors
///
/// Returns an error when only one of cert or key is provided, or when the
/// certificate/key cannot be read, parsed, or paired.
fn load_listener_tls(args: &mecmcp_runtime::cli::Cli) -> Result<Option<Arc<rustls::ServerConfig>>> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(_), None) => bail!("--tls-cert provided without --tls-key"),
        (None, Some(_)) => bail!("--tls-key provided without --tls-cert"),
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            mecmcp_transport::load_tls(cert, key, Arc::new(provider))
                .context("loading listener TLS")
                .map(Some)
        }
    }
}

/// One SIGHUP reload pass: reload the inventory, rebuild clients on success,
/// reload the token store, and reopen the audit file.
fn perform_sighup_reload(
    registry: &DeviceRegistry,
    server: Option<&OpnsenseServer>,
    token_store: Option<&mecmcp_auth::TokenStoreFile<mecmcp_auth::NoGrant>>,
    audit_sink: Option<&AuditFileSink>,
) {
    let registry_reloaded = match registry.reload() {
        Ok(count) => {
            tracing::info!(target: "audit", devices = count, "device inventory reloaded");
            true
        }
        Err(error) => {
            tracing::warn!(
                target: "audit",
                %error,
                "device inventory reload failed; retaining previous snapshot"
            );
            false
        }
    };

    if registry_reloaded && let Some(srv) = server {
        match srv.rebuild_clients() {
            Ok(count) => {
                tracing::info!(target: "audit", clients = count, "HTTP clients rebuilt from reloaded inventory");
            }
            Err(error) => {
                tracing::warn!(target: "audit", %error, "client rebuild failed; retaining previous clients");
            }
        }
    }

    if let Some(store) = token_store {
        match store.reload() {
            Ok(()) => {
                let count = store.store().len();
                tracing::info!(target: "audit", tokens = count, "token store reloaded");
            }
            Err(error) => {
                tracing::warn!(target: "audit", %error, "token store reload failed; retaining previous snapshot");
            }
        }
    }

    if let Some(sink) = audit_sink {
        match sink.reopen() {
            Ok(()) => {
                tracing::info!(target: "audit", path = %sink.path().display(), "audit file reopened");
            }
            Err(error) => {
                tracing::warn!(target: "audit", %error, path = %sink.path().display(), "audit file reopen failed");
            }
        }
    }
}

fn install_sighup_reload(
    registry: Arc<DeviceRegistry>,
    server: Option<OpnsenseServer>,
    token_store: Option<Arc<mecmcp_auth::TokenStoreFile<mecmcp_auth::NoGrant>>>,
    audit_sink: Option<Arc<AuditFileSink>>,
) -> std::io::Result<()> {
    mecmcp_runtime::signals::install_hup_handler(move || {
        perform_sighup_reload(
            &registry,
            server.as_ref(),
            token_store.as_deref(),
            audit_sink.as_deref(),
        );
    })
}

async fn serve_stdio(handler: OpnsenseServer) -> Result<()> {
    tracing::info!("Starting MCP stdio service");
    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;
    Ok(())
}

async fn serve_http(
    handler: OpnsenseServer,
    cli: &OpnsCli,
    registry: Arc<DeviceRegistry>,
    audit_sink: Option<Arc<AuditFileSink>>,
) -> Result<()> {
    let token_store = if let Some(ref path) = cli.common.tokens_file {
        Some(Arc::new(mecmcp_auth::TokenStoreFile::load(path)?))
    } else {
        None
    };

    install_sighup_reload(
        registry,
        Some(handler.clone()),
        token_store.clone(),
        audit_sink,
    )?;

    let limits = cli.limits.to_limits_config();
    limits
        .validate()
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    let shutdown = CancellationToken::new();
    let router = build_http_router(
        handler,
        token_store,
        cli.common.allowed_host.clone(),
        cli.common.allowed_origin.clone(),
        limits,
        cli.enable_metrics,
        cli.common.allow_insecure_bind,
        shutdown.clone(),
    )?;

    let bind_addr = format!("{}:{}", cli.common.host, cli.common.port).parse()?;
    let tls_config = load_listener_tls(&cli.common).context("TLS configuration failed")?;
    let is_tls = tls_config.is_some();

    tracing::info!(
        target: "audit",
        "attempting to bind {} listener on {bind_addr}",
        if is_tls { "HTTPS" } else { "plain HTTP" }
    );

    serve_router(
        router,
        bind_addr,
        tls_config,
        std::time::Duration::from_secs(30),
    )
    .await
    .context("failed to serve HTTP router")?;

    tracing::info!(
        target: "audit",
        "{} listener on {bind_addr} shut down",
        if is_tls { "HTTPS" } else { "plain HTTP" }
    );

    Ok(())
}
