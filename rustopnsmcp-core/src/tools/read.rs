//! The nine read tools.
//!
//! Each function is transport-independent: it takes an already-resolved
//! [`OpnsenseClient`] and returns JSON, so the MCP wiring in the binary crate
//! is the only place that knows about `rmcp`.

use crate::client::OpnsenseClient;
use crate::endpoints;
use crate::error::OpnsenseError;
use crate::model::{SearchResponse, require_object};
use schemars::JsonSchema;
use serde::Deserialize;

/// Arguments shared by every read tool: which device to query.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
}

/// Arguments for a paginated `search_*` read tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// Which device, by its name in `devices.json`.
    pub device: String,
    /// Free-text filter, matched against the resource's usual search fields.
    #[serde(default)]
    pub search_phrase: Option<String>,
    /// Maximum items to return. Defaults to 200.
    ///
    /// A response holding exactly this many items may not be the whole
    /// collection — advance the page with a future paging argument once one
    /// is needed; phase 1 always requests page 1.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Build the standard `search_*` request body.
fn search_body(args: &SearchArgs) -> serde_json::Value {
    serde_json::json!({
        "current": 1,
        "rowCount": args.limit.unwrap_or(endpoints::DEFAULT_ROW_COUNT),
        "searchPhrase": args.search_phrase.clone().unwrap_or_default(),
    })
}

/// `opnsense_system_status`: the device's system status.
///
/// # Errors
/// Returns [`OpnsenseError`] on a transport failure, a non-2xx response, or a
/// response that is not a JSON object.
pub async fn system_status(client: &OpnsenseClient) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client.get(endpoints::SYSTEM_STATUS).await?;
    require_object(&raw)?;
    Ok(raw)
}

/// `opnsense_firmware_status`: installed firmware and available-update status.
///
/// # Errors
/// As [`system_status`].
pub async fn firmware_status(client: &OpnsenseClient) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client.get(endpoints::FIRMWARE_STATUS).await?;
    require_object(&raw)?;
    Ok(raw)
}

/// `opnsense_list_interfaces`: the interfaces overview.
///
/// # Errors
/// As [`system_status`].
pub async fn list_interfaces(client: &OpnsenseClient) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client.get(endpoints::INTERFACES_OVERVIEW).await?;
    require_object(&raw)?;
    Ok(raw)
}

/// `opnsense_list_gateways`: gateway status.
///
/// # Errors
/// As [`system_status`].
pub async fn list_gateways(client: &OpnsenseClient) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client.get(endpoints::GATEWAYS_STATUS).await?;
    require_object(&raw)?;
    Ok(raw)
}

/// `opnsense_list_firewall_rules`: firewall filter rules, one page.
///
/// # Errors
/// Returns [`OpnsenseError`] on a transport failure, a non-2xx response, or a
/// response missing the `rows` envelope.
pub async fn list_firewall_rules(
    client: &OpnsenseClient,
    args: &SearchArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client
        .post(endpoints::FIREWALL_RULES_SEARCH, &search_body(args))
        .await?;
    let parsed = SearchResponse::parse(&raw)?;
    serde_json::to_value(parsed).map_err(|error| OpnsenseError::Malformed(error.to_string()))
}

/// `opnsense_list_aliases`: firewall aliases, one page.
///
/// # Errors
/// As [`list_firewall_rules`].
pub async fn list_aliases(
    client: &OpnsenseClient,
    args: &SearchArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client
        .post(endpoints::ALIASES_SEARCH, &search_body(args))
        .await?;
    let parsed = SearchResponse::parse(&raw)?;
    serde_json::to_value(parsed).map_err(|error| OpnsenseError::Malformed(error.to_string()))
}

/// `opnsense_list_routes`: static routes, one page.
///
/// # Errors
/// As [`list_firewall_rules`].
pub async fn list_routes(
    client: &OpnsenseClient,
    args: &SearchArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client
        .post(endpoints::ROUTES_SEARCH, &search_body(args))
        .await?;
    let parsed = SearchResponse::parse(&raw)?;
    serde_json::to_value(parsed).map_err(|error| OpnsenseError::Malformed(error.to_string()))
}

/// `opnsense_list_dhcp_leases`: DHCPv4 leases, one page.
///
/// # Errors
/// As [`list_firewall_rules`].
pub async fn list_dhcp_leases(
    client: &OpnsenseClient,
    args: &SearchArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let raw = client
        .post(endpoints::DHCP_LEASES_SEARCH, &search_body(args))
        .await?;
    let parsed = SearchResponse::parse(&raw)?;
    serde_json::to_value(parsed).map_err(|error| OpnsenseError::Malformed(error.to_string()))
}

/// `opnsense_list_nat_rules`: outbound and 1:1 NAT rules, one page each.
///
/// OPNsense splits NAT across two controllers with no combined listing
/// endpoint, so this tool fetches both and returns them side by side rather
/// than making a caller learn the split to see NAT at all.
///
/// # Errors
/// As [`list_firewall_rules`], for either sub-request.
pub async fn list_nat_rules(
    client: &OpnsenseClient,
    args: &SearchArgs,
) -> Result<serde_json::Value, OpnsenseError> {
    let body = search_body(args);
    let outbound_raw = client.post(endpoints::NAT_OUTBOUND_SEARCH, &body).await?;
    let one_to_one_raw = client.post(endpoints::NAT_ONE_TO_ONE_SEARCH, &body).await?;

    let outbound = SearchResponse::parse(&outbound_raw)?;
    let one_to_one = SearchResponse::parse(&one_to_one_raw)?;

    serde_json::to_value(serde_json::json!({
        "outbound": outbound,
        "one_to_one": one_to_one,
    }))
    .map_err(|error| OpnsenseError::Malformed(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{SearchArgs, search_body};

    #[test]
    fn search_body_defaults_row_count_and_empty_phrase() {
        let args = SearchArgs {
            device: "fw".to_owned(),
            search_phrase: None,
            limit: None,
        };
        let body = search_body(&args);
        assert_eq!(body["current"], 1);
        assert_eq!(body["rowCount"], crate::endpoints::DEFAULT_ROW_COUNT);
        assert_eq!(body["searchPhrase"], "");
    }

    #[test]
    fn search_body_passes_through_supplied_values() {
        let args = SearchArgs {
            device: "fw".to_owned(),
            search_phrase: Some("wan".to_owned()),
            limit: Some(50),
        };
        let body = search_body(&args);
        assert_eq!(body["rowCount"], 50);
        assert_eq!(body["searchPhrase"], "wan");
    }
}
