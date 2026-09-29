//! `rustopnsmcp` — enterprise MCP server for OPNsense.
//!
//! Library surface exposed so integration tests can exercise the same
//! transport and server assembly `main` uses.

pub mod changeset_state;
pub mod cli;
pub mod http_transport;
pub mod server;
