//! Pre-image capture and staged mutations for OPNsense firewall aliases.
//!
//! OPNsense's alias controller has no discardable candidate: `addItem`,
//! `setItem`, and `delItem` persist to `config.xml` immediately, and only
//! `reconfigure` loads that into the live `pf` tables. There is nothing to
//! diff a candidate against, so the pre-image — the alias as it stood before
//! staging touched it — is what apply checks for drift against and what
//! rollback replays.

use crate::error::OpnsenseError;
use serde_json::Value;

/// A snapshot of the aliases a change set will touch, captured before
/// staging writes anything.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Preimage {
    /// Alias bodies as they stood at capture time, keyed by UUID.
    entries: Vec<Value>,
}

impl Preimage {
    /// Construct a pre-image from already-fetched alias bodies.
    ///
    /// Used both to build a fresh pre-image from live reads and to
    /// reconstruct one stored in a change set's actions.
    #[must_use]
    pub fn from_resources(entries: Vec<Value>) -> Self {
        Self { entries }
    }

    /// Capture a pre-image from a live device.
    ///
    /// Fetches the current body of every alias a staged [`Update`](StagedMutation::Update)
    /// or [`Delete`](StagedMutation::Delete) addresses. A [`Create`](StagedMutation::Create)
    /// has no prior state to capture.
    ///
    /// # Errors
    ///
    /// Returns an error if any fetch fails, including "alias not found" for a
    /// UUID the plan names but the device does not have.
    pub async fn capture(
        client: &crate::client::OpnsenseClient,
        mutations: &[StagedMutation],
    ) -> Result<Self, OpnsenseError> {
        let mut entries = Vec::new();
        for mutation in mutations {
            let Some(uuid) = mutation.resource_uuid() else {
                continue;
            };
            let body = client.get_alias_item(uuid).await?;
            entries.push(body);
        }
        Ok(Self { entries })
    }

    /// Whether this pre-image covers a given mutation.
    ///
    /// A create needs no coverage. An update or delete must name a UUID the
    /// pre-image actually captured, or the mutation addresses a resource
    /// nobody looked at before staging.
    #[must_use]
    pub fn covers(&self, mutation: &StagedMutation) -> bool {
        match mutation.resource_uuid() {
            None => true,
            Some(uuid) => self.get(uuid).is_some(),
        }
    }

    /// The captured body for a UUID, if this pre-image holds one.
    #[must_use]
    pub fn get(&self, uuid: &str) -> Option<Value> {
        self.entries
            .iter()
            .find(|entry| entry.get("uuid").and_then(Value::as_str) == Some(uuid))
            .cloned()
    }

    /// The captured entries, for folding into a stored change set's actions.
    #[must_use]
    pub fn entries(&self) -> &[Value] {
        &self.entries
    }
}

/// A planned mutation against one firewall alias.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum StagedMutation {
    /// Create a new alias.
    Create {
        /// The alias body: `name`, `type`, `content`, and any other field
        /// OPNsense's alias model accepts.
        body: Value,
    },
    /// Update an existing alias, addressed by UUID.
    Update {
        /// The alias UUID.
        uuid: String,
        /// The new alias body.
        body: Value,
    },
    /// Delete an existing alias, addressed by UUID.
    Delete {
        /// The alias UUID.
        uuid: String,
    },
}

impl StagedMutation {
    /// Stage an alias creation.
    #[must_use]
    pub fn create(body: Value) -> Self {
        Self::Create { body }
    }

    /// Stage an alias update.
    #[must_use]
    pub fn update(uuid: impl Into<String>, body: Value) -> Self {
        Self::Update {
            uuid: uuid.into(),
            body,
        }
    }

    /// Stage an alias deletion.
    #[must_use]
    pub fn delete(uuid: impl Into<String>) -> Self {
        Self::Delete { uuid: uuid.into() }
    }

    /// The alias this mutation addresses by UUID.
    ///
    /// `None` for a create, which has no UUID until apply assigns one.
    #[must_use]
    pub fn resource_uuid(&self) -> Option<&str> {
        match self {
            Self::Update { uuid, .. } | Self::Delete { uuid } => Some(uuid.as_str()),
            Self::Create { .. } => None,
        }
    }

    /// Preview this mutation as a human-readable string.
    #[must_use]
    pub fn preview(&self) -> String {
        match self {
            Self::Create { body } => {
                let name = body.get("name").and_then(Value::as_str).unwrap_or("?");
                format!("create alias '{name}'")
            }
            Self::Update { uuid, .. } => format!("update alias {uuid}"),
            Self::Delete { uuid } => format!("delete alias {uuid}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Preimage, StagedMutation};
    use serde_json::json;

    /// A mutation addressing a UUID the pre-image never captured must not be
    /// treated as covered — that is the only thing standing between a partial
    /// apply and an unrecoverable one.
    #[test]
    fn a_mutation_outside_the_preimage_is_not_covered() {
        let preimage = Preimage::from_resources(vec![json!({"uuid": "a", "name": "known"})]);
        let staged = StagedMutation::update("b", json!({"name": "x"}));
        assert!(!preimage.covers(&staged));
        assert!(preimage.covers(&StagedMutation::update("a", json!({}))));
    }

    /// Creates need no pre-image coverage: there is nothing to have captured.
    #[test]
    fn a_create_is_always_covered() {
        let preimage = Preimage::from_resources(Vec::new());
        assert!(preimage.covers(&StagedMutation::create(json!({"name": "new"}))));
    }

    #[test]
    fn get_finds_an_entry_by_uuid() {
        let preimage = Preimage::from_resources(vec![
            json!({"uuid": "a", "name": "one"}),
            json!({"uuid": "b", "name": "two"}),
        ]);
        assert_eq!(
            preimage.get("b").and_then(|v| v.get("name").cloned()),
            Some(json!("two"))
        );
        assert!(preimage.get("c").is_none());
    }
}
