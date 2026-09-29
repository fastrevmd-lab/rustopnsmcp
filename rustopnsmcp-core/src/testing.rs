//! Test helper for loading synthetic OPNsense API responses.
//!
//! There is no live OPNsense lab device behind this crate's tests. Every
//! fixture under `tests/fixtures/` is hand-written, matching the documented
//! `search_*` envelope shape and plausible status-endpoint payloads, not a
//! capture from a real device. Treat a passing test as evidence the parser
//! accepts the documented shape, not as evidence about a specific OPNsense
//! release.

use std::path::PathBuf;

/// Load a synthetic fixture by name (without the `.json` extension).
///
/// # Panics
///
/// Panics if the fixture is absent or is not valid JSON. Both are
/// test-authoring errors, and a panic naming the path is the fastest way to
/// fix them.
#[must_use]
pub fn fixture(name: &str) -> serde_json::Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        &format!("{name}.json"),
    ]
    .iter()
    .collect();

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no fixture at {}: {error}", path.display()));

    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("fixture {} is not JSON: {error}", path.display()))
}
