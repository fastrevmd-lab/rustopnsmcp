//! Command-line surface.
//!
//! `mecmcp_runtime::cli::Cli` is flattened rather than reimplemented, so every
//! shared flag — transport, bind, TLS, allowed hosts, audit, and the `token`
//! subcommand — behaves exactly as it does on the sibling servers.
//!
//! Phase 1 has no change-set lifecycle, so this carries none of the
//! `--lab-mode` / `--state-file` / `--approval-timeout-secs` flags those
//! servers add: there is nothing here for them to configure yet.

use clap::Parser;

/// `rustopnsmcp` command line.
#[derive(Debug, Parser)]
#[command(name = "rustopnsmcp", version)]
pub struct OpnsCli {
    /// Flags shared with the rest of the mechub MCP family.
    #[command(flatten)]
    pub common: mecmcp_runtime::cli::Cli,

    /// Expose the `/metrics` (Prometheus) endpoint (streamable-http only).
    /// OFF by default: `/metrics` carries no MCP bearer auth of its own, so
    /// turning it on is an operator decision, not a default. As of
    /// `mecmcp-transport` 0.24.0, `/metrics` is restricted to loopback
    /// callers by `metrics_access_middleware`, independent of this flag.
    #[arg(long = "enable-metrics")]
    pub enable_metrics: bool,

    /// HTTP resource limits (streamable-http only). Defaults match
    /// `mecmcp_transport::LimitsConfig::default()` so an upgrade with no
    /// flags passed behaves exactly as before.
    #[command(flatten)]
    pub limits: LimitsArgs,
}

/// CLI-configurable mirror of `mecmcp_transport::LimitsConfig`.
#[derive(Debug, clap::Args)]
pub struct LimitsArgs {
    /// Max request body bytes before HTTP 413. 0 = unlimited.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_inflight_requests_per_token: usize,

    /// Max requests per second per source IP address. Set together with
    /// `--max-request-burst-per-ip`; `0`/`0` disables per-IP rate limiting.
    #[arg(long, default_value_t = 50)]
    pub max_requests_per_second_per_ip: u64,

    /// Max immediate request burst per source IP address.
    #[arg(long, default_value_t = 100)]
    pub max_request_burst_per_ip: u64,

    /// Max requests per second per bearer token.
    #[arg(long, default_value_t = 20)]
    pub max_requests_per_second_per_token: u64,

    /// Max immediate request burst per bearer token.
    #[arg(long, default_value_t = 40)]
    pub max_request_burst_per_token: u64,

    /// Max concurrent in-flight requests per target device. 0 = unlimited.
    #[arg(long, default_value_t = 4)]
    pub max_inflight_requests_per_device: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, default_value_t = 128)]
    pub max_sessions: usize,

    /// Max concurrent MCP sessions per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_sessions_per_token: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(long, default_value_t = 300)]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(long, default_value_t = 3600)]
    pub session_max_lifetime_secs: u64,
}

impl LimitsArgs {
    /// Build the transport's `LimitsConfig` from the parsed flags.
    #[must_use]
    pub fn to_limits_config(&self) -> mecmcp_transport::LimitsConfig {
        mecmcp_transport::LimitsConfig {
            max_request_body_bytes: self.max_request_body_bytes,
            max_inflight_requests: self.max_inflight_requests,
            max_inflight_requests_per_token: self.max_inflight_requests_per_token,
            max_requests_per_second_per_ip: self.max_requests_per_second_per_ip,
            max_request_burst_per_ip: self.max_request_burst_per_ip,
            max_requests_per_second_per_token: self.max_requests_per_second_per_token,
            max_request_burst_per_token: self.max_request_burst_per_token,
            max_inflight_requests_per_device: self.max_inflight_requests_per_device,
            max_sessions: self.max_sessions,
            max_sessions_per_token: self.max_sessions_per_token,
            session_idle_timeout_secs: self.session_idle_timeout_secs,
            session_max_lifetime_secs: self.session_max_lifetime_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// There must be no way to ask for unverified TLS. If this test ever
    /// needs changing, the deployment is wrong, not the test.
    #[test]
    fn there_is_no_insecure_tls_flag() {
        for flag in [
            "--insecure",
            "--no-verify-tls",
            "--insecure-skip-verify",
            "--tls-no-verify",
        ] {
            let parsed = OpnsCli::try_parse_from(["rustopnsmcp", flag]);
            assert!(parsed.is_err(), "{flag} must not be accepted");
        }
    }

    #[test]
    fn fresh_install_gets_nonzero_rate_limits_without_operator_action() {
        let cli = OpnsCli::try_parse_from(["rustopnsmcp"]).expect("parses");
        assert!(cli.limits.max_requests_per_second_per_ip > 0);
        assert!(cli.limits.max_request_burst_per_ip > 0);
        assert!(cli.limits.max_requests_per_second_per_token > 0);
        assert!(cli.limits.max_request_burst_per_token > 0);
    }

    /// Every `LimitsArgs` default must match `LimitsConfig::default()` byte
    /// for byte: a mismatch here means the documented default and the
    /// enforced one have drifted.
    #[test]
    fn limits_defaults_match_transport_defaults() {
        let cli = OpnsCli::try_parse_from(["rustopnsmcp"]).expect("parses");
        let got = cli.limits.to_limits_config();
        let want = mecmcp_transport::LimitsConfig::default();
        assert_eq!(got.max_request_body_bytes, want.max_request_body_bytes);
        assert_eq!(got.max_inflight_requests, want.max_inflight_requests);
        assert_eq!(
            got.max_inflight_requests_per_token,
            want.max_inflight_requests_per_token
        );
        assert_eq!(
            got.max_requests_per_second_per_ip,
            want.max_requests_per_second_per_ip
        );
        assert_eq!(got.max_request_burst_per_ip, want.max_request_burst_per_ip);
        assert_eq!(
            got.max_requests_per_second_per_token,
            want.max_requests_per_second_per_token
        );
        assert_eq!(
            got.max_request_burst_per_token,
            want.max_request_burst_per_token
        );
        assert_eq!(
            got.max_inflight_requests_per_device,
            want.max_inflight_requests_per_device
        );
        assert_eq!(got.max_sessions, want.max_sessions);
        assert_eq!(got.max_sessions_per_token, want.max_sessions_per_token);
        assert_eq!(
            got.session_idle_timeout_secs,
            want.session_idle_timeout_secs
        );
        assert_eq!(
            got.session_max_lifetime_secs,
            want.session_max_lifetime_secs
        );
    }

    #[test]
    fn metrics_are_off_by_default_but_operator_configurable() {
        let cli = OpnsCli::try_parse_from(["rustopnsmcp"]).expect("parses");
        assert!(!cli.enable_metrics);

        let cli = OpnsCli::try_parse_from(["rustopnsmcp", "--enable-metrics"]).expect("parses");
        assert!(cli.enable_metrics);
    }

    /// The shared `token` subcommand must remain reachable through the
    /// flattened CLI, since this is how an operator mints, revokes, and
    /// rotates bearer tokens.
    #[test]
    fn the_token_subcommand_is_reachable() {
        let cli = OpnsCli::try_parse_from([
            "rustopnsmcp",
            "token",
            "list",
            "--tokens-file",
            "/etc/rustopnsmcp/tokens.json",
        ])
        .expect("parses");
        assert!(matches!(
            cli.common.command,
            Some(mecmcp_runtime::cli::Command::Token { .. })
        ));
    }
}
