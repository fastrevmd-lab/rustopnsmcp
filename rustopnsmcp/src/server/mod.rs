//! The MCP server handler.

use mecmcp_auth::NoGrant;
use mecmcp_changeset::{
    ApplyHandle, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, PreviewRecord,
    change_set_digest, preview_digest,
};
use mecmcp_server::{
    ResultFormat, ResultLimits, authorize_call, caller_from_extensions, filter_tools_for_scope,
    tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerConfig,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rustopnsmcp_core::{
    changeset::{
        OpnsenseTransaction, Preimage, StagedMutation, State, actions_for, apply_sequentially,
        check_writable_fields, diff_against_preimage, fingerprint_of, mutations_of, preimage_of,
        validate_locally,
    },
    client::OpnsenseClient,
    error::OpnsenseError,
    inventory::DeviceRegistry,
    tools::{WRITE_TOOLS, changeset, read},
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// How many unstaged change sets may be held at once.
///
/// Bounded because a draft is reachable without touching a device, so an
/// unbounded map is a way to grow the process with no write ever happening.
const MAX_DRAFTS: usize = 32;

/// Seconds since the Unix epoch.
///
/// A clock before the epoch is not a case worth branching on; it reports 0,
/// which makes every approval look old and therefore expired — the safe
/// direction for a gate.
fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A change set that exists but has nothing staged into it.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The device it was created against.
    device: String,
    /// The principal who created it.
    owner: String,
    /// What it is for, which becomes the preview's description.
    description: String,
    /// When it was created, so a forgotten draft does not live forever.
    created_at_unix: u64,
}

/// The OPNsense MCP server.
#[derive(Clone)]
pub struct OpnsenseServer {
    /// Device inventory.
    registry: Arc<DeviceRegistry>,
    /// Clients per device. `RwLock` allows rebuild on SIGHUP.
    clients: Arc<std::sync::RwLock<BTreeMap<String, OpnsenseClient>>>,
    /// Whether lab mode is enabled.
    lab_mode: bool,
    /// The change-set lifecycle.
    ///
    /// `mecmcp-changeset`'s coordinator, not a map: it owns the transition
    /// policy, the claim-before-apply, and the preview-bound approval, and
    /// the approval TTL that `--approval-timeout-secs` configures.
    coordinator: Arc<ChangesetCoordinator>,
    /// Change sets created but not yet staged into.
    ///
    /// The coordinator cannot hold one: its persistence layer refuses to
    /// load a state file containing a change set with no actions, so
    /// persisting an empty plan would make the *whole* store unloadable at
    /// the next start. An empty change set has nothing to protect either —
    /// no plan, no pre-image, no approval — so it is held here until the
    /// first mutation is staged, and a restart loses exactly nothing.
    drafts: Arc<std::sync::RwLock<BTreeMap<String, Draft>>>,
    /// Serialises changing a plan against approving one.
    ///
    /// A plan write and an approval read/write must not interleave: an
    /// approval landing between a plan becoming visible and its digest being
    /// computed would attest to the wrong plan. Contention is negligible —
    /// the coordinator already allows one pending change set per principal
    /// per device.
    plan_lock: Arc<tokio::sync::Mutex<()>>,
    /// Tool router.
    tool_router: ToolRouter<Self>,
}

impl OpnsenseServer {
    /// Create a new server with the given registry, lab mode, and
    /// coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error if any device's client cannot be built.
    pub fn new(
        registry: Arc<DeviceRegistry>,
        lab_mode: bool,
        coordinator: Arc<ChangesetCoordinator>,
    ) -> Result<Self, OpnsenseError> {
        let clients = Self::build_clients(&registry)?;
        Ok(Self {
            registry,
            clients: Arc::new(std::sync::RwLock::new(clients)),
            lab_mode,
            coordinator,
            drafts: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
            plan_lock: Arc::new(tokio::sync::Mutex::new(())),
            tool_router: Self::opns_tool_router(),
        })
    }

    /// Build HTTP clients for all devices in the registry.
    fn build_clients(
        registry: &DeviceRegistry,
    ) -> Result<BTreeMap<String, OpnsenseClient>, OpnsenseError> {
        let mut clients = BTreeMap::new();
        for name in registry.names() {
            let device = registry.get(&name)?;
            clients.insert(name.clone(), OpnsenseClient::new(device)?);
        }
        Ok(clients)
    }

    /// Rebuild all clients from the current registry state.
    ///
    /// Called on SIGHUP after the registry has been reloaded, so that
    /// configuration changes (endpoint, credential, CA) take effect without
    /// restarting the server.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built. On error, the previous
    /// clients are retained.
    pub fn rebuild_clients(&self) -> Result<usize, OpnsenseError> {
        let new_clients = Self::build_clients(&self.registry)?;
        let count = new_clients.len();

        let mut clients = self
            .clients
            .write()
            .map_err(|_| OpnsenseError::Malformed("clients lock poisoned".to_owned()))?;

        *clients = new_clients;
        Ok(count)
    }

    /// Get a reference to the client for a device.
    fn client_for(&self, device: &str) -> Result<OpnsenseClient, Box<CallToolResult>> {
        let clients = self
            .clients
            .read()
            .map_err(|_| Box::new(tool_error("clients lock poisoned".to_owned())))?;

        clients
            .get(device)
            .cloned()
            .ok_or_else(|| Box::new(tool_error(format!("unknown device: {device}"))))
    }

    /// Recover the caller from the request context.
    fn caller(context: &RequestContext<RoleServer>) -> Option<mecmcp_auth::CallerCtx<NoGrant>> {
        caller_from_extensions::<NoGrant>(&context.extensions).cloned()
    }

    /// The principal behind this call.
    fn principal(caller: Option<&mecmcp_auth::CallerCtx<NoGrant>>) -> String {
        caller.map_or_else(|| "unknown".to_owned(), |ctx| ctx.token_name.clone())
    }

    /// Map a caller's server-verified `mecmcp_auth::ActorType` to the
    /// `mecmcp_audit::ActorType` `approve_change_set` requires.
    ///
    /// `None` — no authenticated caller context, i.e. the stdio transport —
    /// maps to `Unknown` rather than `Human`. Inventing `Human` for an
    /// unattributed caller would let stdio silently satisfy the human-approver
    /// gate; `Unknown` is the honest fact, and `approve_change_set` refuses it
    /// exactly like it refuses `Agent`.
    fn approver_actor_type(
        caller: Option<&mecmcp_auth::CallerCtx<NoGrant>>,
    ) -> mecmcp_audit::ActorType {
        match caller {
            Some(ctx) => match ctx.actor_type {
                mecmcp_auth::ActorType::Human => mecmcp_audit::ActorType::Human,
                mecmcp_auth::ActorType::Agent => mecmcp_audit::ActorType::Agent,
                mecmcp_auth::ActorType::Unknown => mecmcp_audit::ActorType::Unknown,
            },
            None => mecmcp_audit::ActorType::Unknown,
        }
    }

    /// Fetch a change set, refusing a device that does not own it.
    async fn record_for(
        &self,
        change_set_id: &str,
        device: &str,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        self.coordinator
            .change_set(change_set_id, device)
            .await
            .map_err(|error| {
                Box::new(tool_error(format!(
                    "change set {change_set_id} on {device} ({}): {}",
                    error.field(),
                    error.message()
                )))
            })
    }

    /// Read the plan back off a stored record.
    fn plan_of(
        record: &ChangeSetRecord,
    ) -> Result<(Vec<StagedMutation>, Preimage), Box<CallToolResult>> {
        let mutations = mutations_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        let preimage = preimage_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        Ok((mutations, preimage))
    }

    /// Render the preview an approver signs off on.
    ///
    /// Stored as JSON rather than prose because it is read by a model relaying
    /// to an operator, and because it is also where the description lives:
    /// `ChangeSetRecord` has no field for one.
    ///
    /// The atomicity declaration is part of the preview deliberately.
    /// OPNsense offers no atomic apply, no dry run, and no guaranteed
    /// rollback, and an approver who is not told that is approving something
    /// else.
    fn render_preview(
        device: &str,
        description: &str,
        mutations: &[StagedMutation],
        preimage: &Preimage,
    ) -> Result<String, Box<CallToolResult>> {
        let diff = diff_against_preimage(preimage, mutations)
            .map_err(|error| Box::new(tool_error(format!("failed to compute diff: {error}"))))?;
        let atomicity = OpnsenseTransaction::atomicity();

        serde_json::to_string_pretty(&serde_json::json!({
            "device": device,
            "description": description,
            "staged_count": mutations.len(),
            "atomicity": {
                "atomic_apply": atomicity.atomic_apply,
                "dry_run_validation": atomicity.dry_run_validation,
                "guaranteed_rollback": atomicity.guaranteed_rollback,
                "note": "OPNsense writes each alias to config.xml immediately and only \
                         loads it into the live pf tables on reconfigure: a partial apply \
                         is reachable and rollback is best-effort",
            },
            "changes": diff.changes,
        }))
        .map_err(|error| Box::new(tool_error(format!("failed to render the preview: {error}"))))
    }

    /// The description carried in a record's preview.
    fn description_of(record: &ChangeSetRecord) -> Result<String, Box<CallToolResult>> {
        let Some(preview) = record.preview.as_ref() else {
            return Err(Box::new(tool_error(
                "change set has no stored preview; create it again",
            )));
        };
        let parsed: serde_json::Value = serde_json::from_str(&preview.artifact).map_err(|_| {
            Box::new(tool_error(
                "stored change set: the preview is not the shape this server writes",
            ))
        })?;
        Ok(parsed
            .get("description")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned())
    }

    /// Record a change set that has nothing staged yet.
    ///
    /// Mirrors the coordinator's own rule — one pending change set per
    /// principal per device — so a draft cannot be used to sidestep it, and
    /// sweeps drafts older than the approval window on the way in.
    async fn hold_draft(&self, id: String, draft: Draft) -> Result<(), Box<CallToolResult>> {
        if let Some(blocker) = self
            .coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| {
                if record.owner != draft.owner || record.device != draft.device {
                    return false;
                }
                match record.state {
                    ChangeSetState::Applying => true,
                    ChangeSetState::Planned | ChangeSetState::Approved => {
                        unix_seconds_now() < record.expires_at_unix
                    }
                    _ => false,
                }
            })
        {
            return Err(Box::new(tool_error(format!(
                "change set {} on '{}' is still {}; finish or cancel it before creating \
                 another",
                blocker.id,
                draft.device,
                blocker.state.as_str()
            ))));
        }

        let deadline = self.coordinator.approval_ttl().as_secs();
        let now = unix_seconds_now();

        let mut drafts = self
            .drafts
            .write()
            .map_err(|_| Box::new(tool_error("drafts lock poisoned".to_owned())))?;

        drafts.retain(|_, held| now.saturating_sub(held.created_at_unix) < deadline);

        if let Some((existing, _)) = drafts
            .iter()
            .find(|(_, held)| held.owner == draft.owner && held.device == draft.device)
        {
            return Err(Box::new(tool_error(format!(
                "change set {existing} on '{}' has nothing staged yet; stage into it or \
                 let it lapse before creating another",
                draft.device
            ))));
        }

        if drafts.len() >= MAX_DRAFTS {
            return Err(Box::new(tool_error(format!(
                "{MAX_DRAFTS} change sets are open with nothing staged; stage into one or \
                 let them lapse"
            ))));
        }

        drafts.insert(id, draft);
        Ok(())
    }

    /// The draft for this id, if it is one, the caller named its device, and
    /// it has not lapsed.
    fn draft(&self, change_set_id: &str, device: &str) -> Option<Draft> {
        let deadline = self.coordinator.approval_ttl().as_secs();
        let now = unix_seconds_now();

        let held = self
            .drafts
            .read()
            .ok()?
            .get(change_set_id)
            .filter(|draft| draft.device == device)
            .cloned()?;

        if now.saturating_sub(held.created_at_unix) >= deadline {
            self.release_draft(change_set_id);
            return None;
        }

        Some(held)
    }

    /// Forget a draft that has become a real change set.
    fn release_draft(&self, change_set_id: &str) {
        if let Ok(mut drafts) = self.drafts.write() {
            drafts.remove(change_set_id);
        }
    }

    /// Refuse a plan the state file could not be reloaded with.
    fn check_plan_limits(record: &ChangeSetRecord) -> Result<(), Box<CallToolResult>> {
        let limits = crate::changeset_state::limits();

        mecmcp_changeset::validate_change_set_actions(&record.actions, &limits).map_err(
            |error| {
                Box::new(tool_error(format!(
                    "staged plan refused ({}): {}",
                    error.field(),
                    error.message()
                )))
            },
        )?;

        if let Some(preview) = record.preview.as_ref()
            && preview.artifact.len() > limits.max_preview_bytes
        {
            return Err(Box::new(tool_error(format!(
                "the preview for this change set is {} bytes, over the {} the store \
                 accepts; stage fewer changes at once",
                preview.artifact.len(),
                limits.max_preview_bytes
            ))));
        }

        Ok(())
    }

    /// Rewrite a record's plan, its fingerprint, its digest, and its preview.
    ///
    /// All four move together. The digest binds `(owner, device, fingerprint,
    /// actions)` and the approval binds the digest, so a plan changed without
    /// its digest would carry an approval for a plan nobody approved.
    fn with_plan(
        mut record: ChangeSetRecord,
        mutations: &[StagedMutation],
        preimage: &Preimage,
        description: &str,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        let actions = actions_for(mutations, preimage);
        let fingerprint = fingerprint_of(&actions)
            .map_err(|error| Box::new(tool_error(format!("failed to fingerprint: {error}"))))?;
        let artifact = Self::render_preview(&record.device, description, mutations, preimage)?;

        record.actions = actions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Box::new(tool_error(format!("failed to store the plan: {error}"))))?;
        record.expected_candidate_fingerprint = fingerprint;
        record.digest = change_set_digest(
            &record.owner,
            &record.device,
            &record.expected_candidate_fingerprint,
            &record.actions,
        )
        .map_err(|error| Box::new(tool_error(format!("failed to digest the plan: {error}"))))?;
        record.preview = Some(PreviewRecord {
            digest: preview_digest(&artifact),
            artifact,
            job_id: None,
        });

        Ok(record)
    }
}

#[tool_router(router = opns_tool_router, vis = "pub(crate)")]
impl OpnsenseServer {
    #[tool(
        name = "opnsense_system_status",
        description = "OPNsense system status"
    )]
    async fn opnsense_system_status(
        &self,
        Parameters(args): Parameters<read::DeviceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_system_status",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::system_status(&client).await)
    }

    #[tool(
        name = "opnsense_firmware_status",
        description = "OPNsense installed firmware and available-update status"
    )]
    async fn opnsense_firmware_status(
        &self,
        Parameters(args): Parameters<read::DeviceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_firmware_status",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::firmware_status(&client).await)
    }

    #[tool(
        name = "opnsense_list_interfaces",
        description = "OPNsense interfaces overview"
    )]
    async fn opnsense_list_interfaces(
        &self,
        Parameters(args): Parameters<read::DeviceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_list_interfaces",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::list_interfaces(&client).await)
    }

    #[tool(
        name = "opnsense_list_gateways",
        description = "OPNsense gateway status"
    )]
    async fn opnsense_list_gateways(
        &self,
        Parameters(args): Parameters<read::DeviceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_list_gateways",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::list_gateways(&client).await)
    }

    #[tool(
        name = "opnsense_list_firewall_rules",
        description = "OPNsense firewall filter rules, one page, optionally filtered by \
                        search_phrase. Legacy GUI rules are included only on OPNsense 25.1 \
                        and later; on 24.7 and earlier this returns only MVC/automation rules \
                        and may be incomplete."
    )]
    async fn opnsense_list_firewall_rules(
        &self,
        Parameters(args): Parameters<read::SearchArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_list_firewall_rules",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::list_firewall_rules(&client, &args).await)
    }

    #[tool(
        name = "opnsense_list_aliases",
        description = "OPNsense firewall aliases, one page, optionally filtered by search_phrase"
    )]
    async fn opnsense_list_aliases(
        &self,
        Parameters(args): Parameters<read::SearchArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_list_aliases",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::list_aliases(&client, &args).await)
    }

    #[tool(
        name = "opnsense_list_nat_rules",
        description = "OPNsense outbound and 1:1 NAT rules, one page each. Port forwards \
                        (destination NAT) are NOT included."
    )]
    async fn opnsense_list_nat_rules(
        &self,
        Parameters(args): Parameters<read::SearchArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_list_nat_rules",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::list_nat_rules(&client, &args).await)
    }

    #[tool(
        name = "opnsense_list_routes",
        description = "OPNsense static routes, one page, optionally filtered by search_phrase"
    )]
    async fn opnsense_list_routes(
        &self,
        Parameters(args): Parameters<read::SearchArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_list_routes",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::list_routes(&client, &args).await)
    }

    #[tool(
        name = "opnsense_list_dhcp_leases",
        description = "OPNsense DHCPv4 leases, one page, optionally filtered by search_phrase. \
                        ISC DHCPv4 only; Kea and Dnsmasq leases are NOT covered."
    )]
    async fn opnsense_list_dhcp_leases(
        &self,
        Parameters(args): Parameters<read::SearchArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_list_dhcp_leases",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        Self::respond(read::list_dhcp_leases(&client, &args).await)
    }

    #[tool(
        name = "opnsense_create_change_set",
        description = "Creates a new change set for firewall alias writes"
    )]
    async fn opnsense_create_change_set(
        &self,
        Parameters(args): Parameters<changeset::CreateChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_create_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let owner = Self::principal(caller.as_ref());

        if let Err(result) = self.client_for(&args.device) {
            return *result;
        }

        // Held as a draft, not written to the store. The coordinator's
        // persistence layer refuses to load a state file containing a change
        // set with no actions, so writing an empty plan here would make the
        // whole store unloadable at the next restart. The record is created
        // on the first stage, which is also when there is a plan to propose.
        let preview_budget = crate::changeset_state::limits().max_preview_bytes;
        let smallest_preview = match Self::render_preview(
            &args.device,
            &args.description,
            &[],
            &Preimage::from_resources(Vec::new()),
        ) {
            Ok(rendered) => rendered.len(),
            Err(result) => return *result,
        };
        if smallest_preview >= preview_budget {
            return tool_error(format!(
                "the description does not leave room for a preview: an empty change set \
                 carrying it already renders to {smallest_preview} bytes, against a cap \
                 of {preview_budget}"
            ));
        }

        let id = crate::changeset_state::new_change_set_id();
        let draft = Draft {
            device: args.device.clone(),
            owner,
            description: args.description,
            created_at_unix: unix_seconds_now(),
        };

        if let Err(result) = self.hold_draft(id.clone(), draft).await {
            return *result;
        }

        let result = serde_json::json!({
            "change_set_id": id,
            "device": args.device,
            "state": "draft",
            "note": "nothing is staged yet; a draft is held in memory and is lost on \
                     restart. It becomes a change set on the first opnsense_stage_change.",
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "opnsense_stage_change",
        description = "Stages one or more alias changes into an existing change set"
    )]
    async fn opnsense_stage_change(
        &self,
        Parameters(args): Parameters<changeset::StageChangeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_stage_change",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let draft = self.draft(&args.change_set_id, &args.device);
        let existing = match draft {
            Some(_) => None,
            None => match self.record_for(&args.change_set_id, &args.device).await {
                Ok(record) => Some(record),
                Err(result) => return *result,
            },
        };

        if let Some(ref record) = existing
            && record.state != ChangeSetState::Planned
        {
            return tool_error(format!(
                "change set is {} and can no longer be staged into; create a new one",
                record.state.as_str()
            ));
        }

        let (description, owner) = match (&draft, &existing) {
            (Some(draft), _) => (draft.description.clone(), draft.owner.clone()),
            (None, Some(record)) => match Self::description_of(record) {
                Ok(description) => (description, record.owner.clone()),
                Err(result) => return *result,
            },
            (None, None) => unreachable!("one of the two is always present"),
        };

        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let mut mutations = match &existing {
            Some(record) => match Self::plan_of(record) {
                Ok(plan) => plan.0,
                Err(result) => return *result,
            },
            None => Vec::new(),
        };

        for spec in args.mutations {
            mutations.push(match spec {
                changeset::MutationSpec::Create { body } => StagedMutation::create(body),
                changeset::MutationSpec::Update { uuid, body } => {
                    StagedMutation::update(uuid, body)
                }
                changeset::MutationSpec::Delete { uuid } => StagedMutation::delete(uuid),
            });
        }

        // Checked over the whole plan, not only the new mutations, and before
        // the pre-image is captured: a mutation setting a disallowed field
        // must never enter a change set a human could approve.
        if let Err(e) = check_writable_fields(&mutations) {
            return tool_error(format!("staged mutation refused: {e}"));
        }

        let preimage = match Preimage::capture(&client, &mutations).await {
            Ok(preimage) => preimage,
            Err(e) => return tool_error(format!("failed to capture pre-image: {e}")),
        };

        let staged_count = mutations.len();
        let base = existing.unwrap_or_else(|| ChangeSetRecord {
            id: args.change_set_id.clone(),
            owner,
            device: args.device.clone(),
            expected_candidate_fingerprint: String::new(),
            actions: Vec::new(),
            digest: String::new(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now()
                .saturating_add(self.coordinator.approval_ttl().as_secs()),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            task_id: None,
            apply_without_handle: false,
        });

        let staged = match Self::with_plan(base, &mutations, &preimage, &description) {
            Ok(record) => record,
            Err(result) => return *result,
        };

        if let Err(result) = Self::check_plan_limits(&staged) {
            return *result;
        }

        // Held across the write, so no approval can land between the plan
        // becoming visible and the digest it carries.
        let _publishing = self.plan_lock.lock().await;

        let write_result = if draft.is_some() {
            self.coordinator.insert_change_set(staged).await
        } else {
            self.coordinator
                .update_change_set_from(ChangeSetState::Planned, staged)
                .await
        };

        if let Err(error) = write_result {
            return tool_error(format!(
                "failed to store change set ({}): {}",
                error.field(),
                error.message()
            ));
        }

        if draft.is_some() {
            self.release_draft(&args.change_set_id);
        }

        drop(_publishing);

        let result = serde_json::json!({
            "change_set_id": args.change_set_id,
            "staged_count": staged_count,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "opnsense_diff_change_set",
        description = "Returns a diff showing what applying the change set would do"
    )]
    async fn opnsense_diff_change_set(
        &self,
        Parameters(args): Parameters<changeset::DiffChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_diff_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let record = match self.record_for(&args.change_set_id, &args.device).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let (mutations, preimage) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };

        let diff = match diff_against_preimage(&preimage, &mutations) {
            Ok(diff) => diff,
            Err(e) => return tool_error(format!("failed to compute diff: {e}")),
        };

        let result = serde_json::json!({
            "change_set_id": record.id,
            "computed": diff.computed,
            "changes": diff.changes,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "opnsense_validate_change_set",
        description = "Validates the change set as far as possible without applying it"
    )]
    async fn opnsense_validate_change_set(
        &self,
        Parameters(args): Parameters<changeset::ValidateChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_validate_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let record = match self.record_for(&args.change_set_id, &args.device).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let (mutations, preimage) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };

        if let Err(e) = validate_locally(&preimage, &mutations) {
            return tool_error(format!("local validation failed: {e}"));
        }

        // Schema constraints: staging already refuses these, but a change set
        // can outlive a server restart (it round-trips through
        // --state-file), so a plan built before this check existed must
        // still be caught by the tool whose description already promises it.
        if let Err(e) = check_writable_fields(&mutations) {
            return tool_error(format!("schema constraints failed: {e}"));
        }

        let result = serde_json::json!({
            "change_set_id": record.id,
            "valid": true,
            "note": "OPNsense has no server-side dry-run validation for aliases; this is \
                     client-side only",
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "opnsense_approve_change_set",
        description = "Approves a change set for apply. Two-person control: the creating \
                       token cannot approve its own set unless lab mode waives it, and a \
                       waiver is recorded as a waiver rather than as an approval. Pass \
                       expected_digest to bind the approval to the plan you read."
    )]
    async fn opnsense_approve_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApproveChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_approve_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let approver = Self::principal(caller.as_ref());

        let record = match self.record_for(&args.change_set_id, &args.device).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        if record.actions.is_empty() {
            return tool_error("change set has nothing staged; there is nothing to approve");
        }

        let Some(preview) = record.preview.clone() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Create it again.",
            );
        };

        let (approval_mutations, _) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };
        if let Err(e) = check_writable_fields(&approval_mutations) {
            return tool_error(format!("approval refused: {e}"));
        }

        if let Some(ref expected) = args.expected_digest
            && expected != &record.digest
        {
            return tool_error(format!(
                "approval refused: the plan has changed since you read it. You named \
                 digest {expected}; the change set now holds {}. Read it again before \
                 approving.",
                record.digest
            ));
        }

        let _approving = self.plan_lock.lock().await;

        let approver_actor_type = Self::approver_actor_type(caller.as_ref());

        let outcome = if approver == record.owner {
            if !self.lab_mode {
                return tool_error(
                    "two-person control: the creating token cannot approve its own change set",
                );
            }
            self.coordinator
                .waive_approval(
                    args.change_set_id.clone(),
                    args.device.clone(),
                    approver.clone(),
                    record.digest.clone(),
                )
                .await
        } else {
            self.coordinator
                .approve_change_set(
                    args.change_set_id.clone(),
                    args.device.clone(),
                    approver.clone(),
                    record.digest.clone(),
                    approver_actor_type,
                )
                .await
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return tool_error(format!(
                    "approval refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        };

        let result = serde_json::json!({
            "change_set_id": outcome.change_set_id,
            "state": outcome.state.as_str(),
            "approved_by": outcome.approver,
            "approval_waiver": outcome.approval_waiver,
            "expires_at_unix": outcome.expires_at_unix,
            "approved_digest": outcome.digest,
            "preview": preview.artifact,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "opnsense_apply_change_set",
        description = "Applies the staged alias writes as a sequence of independent REST \
                       calls, then loads them with reconfigure"
    )]
    async fn opnsense_apply_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApplyChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_apply_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.device) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Claim first, and only then read the plan. The claim is the single
        // legal route from `Approved` to `Applying`, and it does the check
        // and the write under one lock, so two concurrent applies cannot
        // both observe `Approved` and both proceed.
        if let Err(error) = self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.device.clone())
            .await
        {
            return tool_error(format!(
                "apply refused ({}): {}",
                error.field(),
                error.message()
            ));
        }

        let claimed = match self
            .coordinator
            .claim_change_set_for_apply(&args.change_set_id, &args.device, ApplyHandle::None)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                return tool_error(format!(
                    "apply refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        };

        if unix_seconds_now() >= claimed.expires_at_unix {
            let deadline = claimed.expires_at_unix;
            let mut lapsed = claimed;
            lapsed.state = ChangeSetState::Failed;
            if let Err(error) = self.coordinator.update_change_set(lapsed).await {
                tracing::error!(
                    change_set_id = %args.change_set_id,
                    field = error.field(),
                    message = error.message(),
                    "an expired change set could not be settled after its claim"
                );
            }
            return tool_error(format!(
                "apply refused: the approval window closed at {deadline}; nothing was \
                 written. Re-plan and re-approve before applying."
            ));
        }

        let (mutations, preimage) = match Self::plan_of(&claimed) {
            Ok(plan) => plan,
            Err(result) => {
                let mut abandoned = claimed;
                abandoned.state = ChangeSetState::Failed;
                if let Err(error) = self.coordinator.update_change_set(abandoned).await {
                    tracing::error!(
                        change_set_id = %args.change_set_id,
                        field = error.field(),
                        message = error.message(),
                        "a claimed change set could not be settled after its plan failed \
                         to read; it will stay Applying"
                    );
                }
                return *result;
            }
        };

        if let Err(e) = check_writable_fields(&mutations) {
            let mut abandoned = claimed;
            abandoned.state = ChangeSetState::Failed;
            if let Err(error) = self.coordinator.update_change_set(abandoned).await {
                tracing::error!(
                    change_set_id = %args.change_set_id,
                    field = error.field(),
                    message = error.message(),
                    "a claimed change set could not be settled after its writable-field \
                     check failed; it will stay Applying"
                );
            }
            return tool_error(format!("apply refused: {e}"));
        }

        let principal = Self::principal(caller.as_ref());
        let outcome = apply_sequentially(&client, &preimage, &mutations).await;

        let state_str = match outcome.state {
            State::Applied => "applied",
            State::AppliedUnverified => "applied_unverified",
            State::Partial => "partial",
            State::PartialRollbackFailed => "partial_rollback_failed",
            State::RefusedStale => "refused_stale",
        };

        let succeeded = matches!(outcome.state, State::Applied | State::AppliedUnverified);

        tracing::info!(
            target: "audit",
            event = "opnsense_change_set_applied",
            change_set_id = %args.change_set_id,
            device = %args.device,
            principal = %principal,
            outcome = state_str,
            succeeded = outcome.succeeded.len(),
            failed = outcome.failed.len(),
            attempted_and_failed = outcome.attempted_and_failed.len(),
            never_attempted = outcome.never_attempted.len(),
            rollback_failures = outcome.rollback_failures.len(),
            "change set applied"
        );

        let mut settled = claimed;
        settled.state = if succeeded {
            ChangeSetState::Applied
        } else {
            ChangeSetState::Failed
        };

        // The device has acted, so this cannot fail closed — refusing now
        // would not un-act it. Reported instead.
        if let Err(error) = self.coordinator.update_change_set(settled).await {
            tracing::error!(
                change_set_id = %args.change_set_id,
                field = error.field(),
                message = error.message(),
                "the apply outcome could not be recorded"
            );
        }

        let result = serde_json::json!({
            "change_set_id": args.change_set_id,
            "state": state_str,
            "succeeded": outcome.succeeded.len(),
            "failed": outcome.failed.len(),
            "attempted_and_failed": outcome.attempted_and_failed.len(),
            "never_attempted": outcome.never_attempted.len(),
            "rollback_failures": outcome.rollback_failures,
            "verification_failure": outcome.verification_failure,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }

    #[tool(
        name = "opnsense_get_change_set",
        description = "Returns the current status and contents of a change set"
    )]
    async fn opnsense_get_change_set(
        &self,
        Parameters(args): Parameters<changeset::GetChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "opnsense_get_change_set",
            Some(&args.device),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        if let Some(draft) = self.draft(&args.change_set_id, &args.device) {
            return tool_result(
                Ok::<_, String>(serde_json::json!({
                    "change_set_id": args.change_set_id,
                    "device": draft.device,
                    "description": draft.description,
                    "creator": draft.owner,
                    "state": "draft",
                    "mutation_count": 0,
                    "note": "nothing is staged yet; this draft is held in memory and is \
                             lost on restart",
                })),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
            );
        }

        if let Err(error) = self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.device.clone())
            .await
        {
            return tool_error(format!(
                "change set {} on {} ({}): {}",
                args.change_set_id,
                args.device,
                error.field(),
                error.message()
            ));
        }

        let record = match self.record_for(&args.change_set_id, &args.device).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let description = Self::description_of(&record).unwrap_or_default();

        let result = serde_json::json!({
            "change_set_id": record.id,
            "device": record.device,
            "description": description,
            "creator": record.owner,
            "approver": record.approval.as_ref().and_then(|a| a.approver.clone()),
            "approval_waiver": record
                .approval
                .as_ref()
                .and_then(|a| a.waived.as_ref())
                .map(|waiver| waiver.kind.as_str()),
            "state": record.state.as_str(),
            "mutation_count": record.actions.len(),
            "expires_at_unix": record.expires_at_unix,
            "plan_digest": record.digest,
            "expected_preimage_fingerprint": record.expected_candidate_fingerprint,
            "preview": record.preview.as_ref().map(|preview| preview.artifact.clone()),
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
        )
    }
}

impl OpnsenseServer {
    /// Turn a tool result into a `CallToolResult`, redacting secret-shaped
    /// values in the JSON body first.
    ///
    /// This runs for every read tool, unconditionally — a device response
    /// carries whatever it carries, and this is the one place a VPN PSK or an
    /// embedded credential in a description field is scrubbed before it
    /// reaches the caller.
    fn respond(result: Result<serde_json::Value, OpnsenseError>) -> CallToolResult {
        match result {
            Ok(mut json) => {
                mecmcp_redact::redact_json_value(&mut json);
                tool_result(
                    Ok::<_, String>(json),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                )
            }
            Err(error) => tool_error(error),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OpnsenseServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rustopnsmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "OPNsense MCP server. Device-addressed tools take (device, ...); the server \
                 routes to the device by name from devices.json. Phase 2a adds governed \
                 writes for firewall aliases through a plan -> digest -> human approve -> \
                 apply-with-drift-check lifecycle; firewall rules remain read-only.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&context.extensions);
        let all_tools = self.tool_router.list_all();
        let visible = filter_tools_for_scope(all_tools, caller, WRITE_TOOLS);
        Ok(ListToolsResult::with_all_items(visible))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The router and the registry must agree, in both directions.
    #[test]
    fn the_router_serves_exactly_the_registered_tools() {
        use rustopnsmcp_core::tools::TOOL_NAMES;
        use std::collections::BTreeSet;

        let router = OpnsenseServer::opns_tool_router();
        let all_tools = router.list_all();
        let served_names: BTreeSet<String> =
            all_tools.iter().map(|tool| tool.name.to_string()).collect();
        let registered_names: BTreeSet<String> =
            TOOL_NAMES.iter().map(|s| (*s).to_owned()).collect();

        assert_eq!(
            served_names, registered_names,
            "TOOL_NAMES and the tool router must list exactly the same tools"
        );
    }

    /// Phase 2a's seven change-set tools are the only mutating surface;
    /// this is meant to stay visible rather than silently assumed.
    #[test]
    fn write_tools_covers_the_change_set_lifecycle() {
        assert_eq!(WRITE_TOOLS.len(), 7);
        assert!(WRITE_TOOLS.contains(&"opnsense_apply_change_set"));
    }

    /// A stdio caller carries no verified token entry, so its actor type
    /// must map to `Unknown` rather than `Human` — approving with that
    /// identity must fail exactly as an agent's approval would.
    #[test]
    fn approver_actor_type_maps_stdio_to_unknown_not_human() {
        assert_eq!(
            OpnsenseServer::approver_actor_type(None),
            mecmcp_audit::ActorType::Unknown
        );
    }

    fn coordinator_at(path: Option<&std::path::Path>) -> Arc<ChangesetCoordinator> {
        crate::changeset_state::build_coordinator(path, std::time::Duration::from_secs(300), true)
            .expect("coordinator")
    }

    fn planned_record(owner: &str, device: &str, ttl: u64) -> ChangeSetRecord {
        let mutations = vec![StagedMutation::create(serde_json::json!({
            "name": "test_alias",
            "type": "host",
            "content": "10.0.0.1"
        }))];
        let preimage = Preimage::from_resources(Vec::new());
        let actions = actions_for(&mutations, &preimage);
        let fingerprint = fingerprint_of(&actions).expect("fingerprint");
        let stored_actions: Vec<serde_json::Value> = actions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<_, _>>()
            .expect("serialize");
        let digest =
            change_set_digest(owner, device, &fingerprint, &stored_actions).expect("digest");

        ChangeSetRecord {
            id: crate::changeset_state::new_change_set_id(),
            owner: owner.to_owned(),
            device: device.to_owned(),
            expected_candidate_fingerprint: fingerprint,
            actions: stored_actions,
            digest,
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now().saturating_add(ttl),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: Some(PreviewRecord {
                digest: preview_digest("preview"),
                artifact: "preview".to_owned(),
                job_id: None,
            }),
            task_id: None,
            apply_without_handle: false,
        }
    }

    /// An unapproved change set must not be claimable for apply: the claim
    /// is the coordinator's single legal route from `Approved` to
    /// `Applying`, and a `Planned` record has no business reaching it.
    #[tokio::test]
    async fn an_unapproved_change_set_cannot_be_claimed_for_apply() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
            .await
            .expect_err("a planned change set cannot be claimed");
        assert!(error.message().contains("Approved"), "{}", error.message());
    }

    /// Two-person control: the owner cannot approve their own plan outside
    /// lab mode, and the coordinator itself enforces this — not just this
    /// server's UI-level check.
    #[tokio::test]
    async fn the_owner_cannot_approve_their_own_plan() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        let digest = record.digest.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .approve_change_set(
                id,
                "home".to_owned(),
                "alice".to_owned(),
                digest,
                mecmcp_audit::ActorType::Human,
            )
            .await
            .expect_err("self-approval must be refused");
        assert!(error.message().contains("own plan"), "{}", error.message());
    }

    /// An agent or unattributed caller cannot serve as the second principal,
    /// even naming the right digest and a different owner: the house rule is
    /// a human approves, not merely "not the owner".
    #[tokio::test]
    async fn only_a_human_actor_type_can_approve() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        let digest = record.digest.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .approve_change_set(
                id,
                "home".to_owned(),
                "bob".to_owned(),
                digest,
                mecmcp_audit::ActorType::Agent,
            )
            .await
            .expect_err("an agent approver must be refused");
        assert!(error.field() == "approver_actor_type", "{}", error.field());
    }

    /// A waiver requires lab mode; without it, waiving is refused exactly
    /// like a bare self-approval would be.
    #[tokio::test]
    async fn a_waiver_is_refused_when_lab_mode_is_off() {
        let coordinator = crate::changeset_state::build_coordinator(
            None,
            std::time::Duration::from_secs(300),
            false,
        )
        .expect("coordinator");
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        let digest = record.digest.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .waive_approval(id, "home".to_owned(), "alice".to_owned(), digest)
            .await
            .expect_err("lab mode is off");
        assert!(error.message().contains("lab mode"), "{}", error.message());
    }

    /// An approval naming a digest the plan has since moved past must be
    /// refused: the whole point of `expected_digest` is that it binds to a
    /// plan the approver actually read.
    #[tokio::test]
    async fn approving_a_digest_the_plan_has_moved_past_is_refused() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        let error = coordinator
            .approve_change_set(
                id,
                "home".to_owned(),
                "bob".to_owned(),
                format!("sha256:{}", "0".repeat(64)),
                mecmcp_audit::ActorType::Human,
            )
            .await
            .expect_err("a stale digest must be refused");
        assert!(error.field() == "expected_digest", "{}", error.field());
    }

    /// A change set is not reachable from a device it was not planned
    /// against — the coordinator addresses records by `(id, device)`.
    #[tokio::test]
    async fn a_change_set_is_not_reachable_from_another_device() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(coordinator.change_set(&id, "home").await.is_ok());
        assert!(coordinator.change_set(&id, "office").await.is_err());
    }
}
