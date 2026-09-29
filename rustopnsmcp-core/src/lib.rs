//! OPNsense client, resource model, and MCP read-tool surface.
//!
//! Phase 1 only: read tools over OPNsense's core REST API. Governed writes
//! land in phase 2 through mecmcp's change-set lifecycle, the same way
//! `rustunifimcp` and `rustpanosmcp` gate theirs.

pub mod client;
pub mod endpoints;
pub mod error;
pub mod inventory;
pub mod model;
pub mod testing;
pub mod tools;
