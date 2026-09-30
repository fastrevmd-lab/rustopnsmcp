//! Pre-image capture and staged mutations for OPNsense firewall aliases and
//! filter rules.
//!
//! OPNsense's alias and filter controllers have no discardable candidate:
//! `addItem`/`addRule`, `setItem`/`setRule`, and `delItem`/`delRule` persist to
//! `config.xml` immediately, and only `reconfigure`/`apply` loads that into
//! the live `pf` tables/ruleset. There is nothing to diff a candidate against,
//! so the pre-image — the resource as it stood before staging touched it — is
//! what apply checks for drift against and what rollback replays.

use crate::error::OpnsenseError;
use serde_json::Value;

/// Which OPNsense resource controller a staged mutation targets.
///
/// A change set may stage mutations against exactly one kind: `reconfigure`
/// for aliases and `apply` for filter rules are separate device-side commits,
/// and mixing kinds in one change set would need both to run together for the
/// batch to be fully loaded — see
/// [`crate::changeset::validate::check_single_resource_kind`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A firewall alias, governed by phase 2a.
    Alias,
    /// A firewall filter rule, governed by phase 2b.
    Rule,
}

impl ResourceKind {
    /// The noun this kind uses in previews and error messages.
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Alias => "alias",
            Self::Rule => "firewall rule",
        }
    }

    /// The name of the device-side call that loads staged writes from
    /// `config.xml` into the live `pf` tables/ruleset for this kind.
    #[must_use]
    pub const fn commit_verb(self) -> &'static str {
        match self {
            Self::Alias => "reconfigure",
            Self::Rule => "apply",
        }
    }
}

/// A snapshot of the resources a change set will touch, captured before
/// staging writes anything.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Preimage {
    /// Resource bodies as they stood at capture time, keyed by UUID.
    entries: Vec<Value>,
}

impl Preimage {
    /// Construct a pre-image from already-fetched resource bodies.
    ///
    /// Used both to build a fresh pre-image from live reads and to
    /// reconstruct one stored in a change set's actions.
    #[must_use]
    pub fn from_resources(entries: Vec<Value>) -> Self {
        Self { entries }
    }

    /// Capture a pre-image from a live device.
    ///
    /// Fetches the current body of every resource a staged [`Update`](StagedMutation::Update)
    /// or [`Delete`](StagedMutation::Delete) addresses. A [`Create`](StagedMutation::Create)
    /// has no prior state to capture.
    ///
    /// # Errors
    ///
    /// Returns an error if any fetch fails, including "not found" for a UUID
    /// the plan names but the device does not have.
    pub async fn capture(
        client: &crate::client::OpnsenseClient,
        mutations: &[StagedMutation],
    ) -> Result<Self, OpnsenseError> {
        let mut entries = Vec::new();
        for mutation in mutations {
            let Some(uuid) = mutation.resource_uuid() else {
                continue;
            };
            let body = client.get_item(mutation.kind(), uuid).await?;
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

/// A planned mutation against one firewall alias or filter rule.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum StagedMutation {
    /// Create a new resource.
    Create {
        /// Which controller this mutation targets.
        kind: ResourceKind,
        /// The resource body: for an alias, `name`, `type`, `content`, and
        /// any other field OPNsense's alias model accepts; for a rule,
        /// `action`, `interface`, and any other field OPNsense's filter rule
        /// model accepts.
        body: Value,
    },
    /// Update an existing resource, addressed by UUID.
    Update {
        /// Which controller this mutation targets.
        kind: ResourceKind,
        /// The resource UUID.
        uuid: String,
        /// The new resource body.
        body: Value,
    },
    /// Delete an existing resource, addressed by UUID.
    Delete {
        /// Which controller this mutation targets.
        kind: ResourceKind,
        /// The resource UUID.
        uuid: String,
    },
}

impl StagedMutation {
    /// Stage a resource creation.
    #[must_use]
    pub fn create(kind: ResourceKind, body: Value) -> Self {
        Self::Create { kind, body }
    }

    /// Stage a resource update.
    #[must_use]
    pub fn update(kind: ResourceKind, uuid: impl Into<String>, body: Value) -> Self {
        Self::Update {
            kind,
            uuid: uuid.into(),
            body,
        }
    }

    /// Stage a resource deletion.
    #[must_use]
    pub fn delete(kind: ResourceKind, uuid: impl Into<String>) -> Self {
        Self::Delete {
            kind,
            uuid: uuid.into(),
        }
    }

    /// Which controller this mutation targets.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Create { kind, .. } | Self::Update { kind, .. } | Self::Delete { kind, .. } => {
                *kind
            }
        }
    }

    /// The resource this mutation addresses by UUID.
    ///
    /// `None` for a create, which has no UUID until apply assigns one.
    #[must_use]
    pub fn resource_uuid(&self) -> Option<&str> {
        match self {
            Self::Update { uuid, .. } | Self::Delete { uuid, .. } => Some(uuid.as_str()),
            Self::Create { .. } => None,
        }
    }

    /// Preview this mutation as a human-readable string.
    #[must_use]
    pub fn preview(&self) -> String {
        match self {
            Self::Create { kind, body } => {
                let name = body
                    .get("name")
                    .or_else(|| body.get("description"))
                    .and_then(Value::as_str)
                    .unwrap_or("?");
                format!("create {} '{name}'", kind.noun())
            }
            Self::Update { kind, uuid, .. } => format!("update {} {uuid}", kind.noun()),
            Self::Delete { kind, uuid } => format!("delete {} {uuid}", kind.noun()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Preimage, ResourceKind, StagedMutation};
    use serde_json::json;

    /// A mutation addressing a UUID the pre-image never captured must not be
    /// treated as covered — that is the only thing standing between a partial
    /// apply and an unrecoverable one.
    #[test]
    fn a_mutation_outside_the_preimage_is_not_covered() {
        let preimage = Preimage::from_resources(vec![json!({"uuid": "a", "name": "known"})]);
        let staged = StagedMutation::update(ResourceKind::Alias, "b", json!({"name": "x"}));
        assert!(!preimage.covers(&staged));
        assert!(preimage.covers(&StagedMutation::update(ResourceKind::Alias, "a", json!({}))));
    }

    /// Creates need no pre-image coverage: there is nothing to have captured.
    #[test]
    fn a_create_is_always_covered() {
        let preimage = Preimage::from_resources(Vec::new());
        assert!(preimage.covers(&StagedMutation::create(
            ResourceKind::Alias,
            json!({"name": "new"})
        )));
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

    #[test]
    fn a_rule_mutation_previews_with_the_rule_noun() {
        let create = StagedMutation::create(
            ResourceKind::Rule,
            json!({"description": "Allow LAN to any", "action": "pass", "interface": "lan"}),
        );
        assert_eq!(create.preview(), "create firewall rule 'Allow LAN to any'");
        assert_eq!(create.kind(), ResourceKind::Rule);
    }
}
