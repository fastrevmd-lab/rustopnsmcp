//! The MCP server handler.

use mecmcp_auth::NoGrant;
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
    client::OpnsenseClient,
    error::OpnsenseError,
    inventory::DeviceRegistry,
    tools::{WRITE_TOOLS, read},
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// The OPNsense MCP server.
#[derive(Clone)]
pub struct OpnsenseServer {
    /// Device inventory.
    registry: Arc<DeviceRegistry>,
    /// Clients per device. `RwLock` allows rebuild on SIGHUP.
    clients: Arc<std::sync::RwLock<BTreeMap<String, OpnsenseClient>>>,
    /// Tool router.
    tool_router: ToolRouter<Self>,
}

impl OpnsenseServer {
    /// Create a new server over the given device registry.
    ///
    /// # Errors
    ///
    /// Returns an error if any device's client cannot be built.
    pub fn new(registry: Arc<DeviceRegistry>) -> Result<Self, OpnsenseError> {
        let clients = Self::build_clients(&registry)?;
        Ok(Self {
            registry,
            clients: Arc::new(std::sync::RwLock::new(clients)),
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
        description = "OPNsense firewall filter rules, one page, optionally filtered by search_phrase"
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
        description = "OPNsense outbound and 1:1 NAT rules, one page each"
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
        description = "OPNsense DHCPv4 leases, one page, optionally filtered by search_phrase"
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
                "OPNsense MCP server, phase 1 (read-only). Device-addressed tools take \
                 (device, ...); the server routes to the device by name from devices.json.",
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

    /// The router and the registry must agree, in both directions. A name in
    /// `TOOL_NAMES` the server does not serve is a promise it cannot keep; a
    /// tool the server serves that is absent from `TOOL_NAMES` escapes the
    /// `WRITE_TOOLS` classification entirely.
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

    /// Phase 1 registers no write tools, and this is meant to stay visible
    /// rather than silently true.
    #[test]
    fn write_tools_is_empty_in_phase_1() {
        assert!(WRITE_TOOLS.is_empty());
    }
}
