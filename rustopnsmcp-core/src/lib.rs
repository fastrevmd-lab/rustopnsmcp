//! OPNsense client, resource model, and MCP tool surface.
//!
//! Phase 1 covered read tools over OPNsense's core REST API. Phase 2a adds
//! governed writes for firewall aliases through mecmcp's change-set
//! lifecycle, the same way `rustunifimcp` and `rustpanosmcp` gate theirs.
//! Firewall rules follow in a later phase.

pub mod changeset;
pub mod client;
pub mod endpoints;
pub mod error;
pub mod inventory;
pub mod model;
pub mod testing;
pub mod tools;
