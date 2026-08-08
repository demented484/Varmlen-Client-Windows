//! Proxy URI and subscription parser.
//!
//! Supports Xray share links for VLESS, VMess, Trojan, Shadowsocks, Hysteria2,
//! WireGuard, HTTP and SOCKS, plus standard WireGuard `[Interface]` / `[Peer]`
//! configurations. Subscription bodies may be plaintext or base64-encoded;
//! whitespace-only lines and comment lines (`#…`) are ignored.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    #[error("unsupported scheme '{0}'")]
    UnsupportedScheme(String),
    #[error("missing credentials")]
    MissingCredentials,
    #[error("missing host")]
    MissingHost,
    #[error("missing port")]
    MissingPort,
    #[error("auto-select / balancer entry — not a connectable server")]
    BalancerEntry,
}

/// Some providers ship an "auto-select"/balancer entry as a sentinel host (e.g.
/// borealisvpn's `balancer.host`) instead of a real server. The plain-vless
/// subscription doesn't carry the balancer's member list, so these aren't
/// connectable — we drop them rather than show a broken server.
fn is_balancer_sentinel(host: &str) -> bool {
    matches!(host.trim().to_ascii_lowercase().as_str(), "balancer.host")
}

fn default_protocol() -> String {
    "vless".to_string()
}

/// Deserialize `protocol`, tolerating a missing key, an explicit `null`, or an
/// empty string from subscriptions persisted before multi-protocol support —
/// all of which mean the legacy default, vless.
fn de_protocol<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(d)?;
    Ok(opt
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_protocol))
}

/// A single VPN endpoint parsed from a proxy URI. The struct keeps its
/// historical name; `protocol` distinguishes every supported Xray proxy
/// outbound, and credential fields are filled per protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessServer {
    pub id: String,
    /// One of the supported Xray proxy outbound protocols. Missing/null/empty
    /// legacy data defaults to `vless`.
    #[serde(default = "default_protocol", deserialize_with = "de_protocol")]
    pub protocol: String,
    /// VLESS/VMess UUID, or Trojan password. Empty for Shadowsocks.
    pub uuid: String,
    /// Shadowsocks/Trojan password (Shadowsocks keeps it separate from method).
    #[serde(default)]
    pub password: Option<String>,
    /// Shadowsocks cipher method.
    #[serde(default)]
    pub method: Option<String>,
    pub host: String,
    pub port: u16,
    pub label: String,
    pub transport: String,
    pub security: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub short_id: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub raw_params: HashMap<String, String>,
    /// The provider's actual JSON object for this location. This is absent for
    /// URI/Base64 locations and is shown verbatim (pretty-printed) by the UI.
    #[serde(default)]
    pub source_json: Option<String>,
    /// Exact proxy outbound extracted from `source_json`. Config generation
    /// reuses only this object; provider routing/DNS/inbounds are never adopted.
    #[serde(default)]
    pub raw_outbound: Option<serde_json::Value>,
    /// Complete Xray location profile. A profile may contain several proxy
    /// outbounds plus a balancer/observatory, but is still one UI location.
    #[serde(default)]
    pub raw_profile: Option<serde_json::Value>,
}

impl VlessServer {
    fn base(protocol: &str, host: String, port: u16, label: String) -> Self {
        VlessServer {
            id: format!("{host}_{port}"),
            protocol: protocol.to_string(),
            uuid: String::new(),
            password: None,
            method: None,
            host,
            port,
            label,
            transport: "tcp".to_string(),
            security: "none".to_string(),
            sni: None,
            fingerprint: None,
            public_key: None,
            short_id: None,
            flow: None,
            path: None,
            mode: None,
            packet_encoding: None,
            raw_params: HashMap::new(),
            source_json: None,
            raw_outbound: None,
            raw_profile: None,
        }
    }
}

/// Server-side subscription metadata parsed from HTTP response headers.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SubscriptionMeta {
    /// `Profile-Title` header — used as the subscription display name.
    pub title: Option<String>,
    /// `Profile-Update-Interval` (hours).
    pub update_interval_hours: Option<u32>,
    /// `Subscription-Userinfo`: upload bytes used.
    pub upload_bytes: Option<u64>,
    /// `Subscription-Userinfo`: download bytes used.
    pub download_bytes: Option<u64>,
    /// `Subscription-Userinfo`: total quota in bytes. 0/absent means unlimited
    /// (normalized to None).
    pub total_bytes: Option<u64>,
    /// `Subscription-Userinfo`: expiry as unix seconds. 0/absent means never
    /// (normalized to None).
    pub expires_at_unix: Option<i64>,
    /// Whether a `Subscription-Userinfo` header was present at all. When true,
    /// the header is AUTHORITATIVE: an absent key means "no quota / no expiry"
    /// and stored values must be cleared, not kept. When false (panel doesn't
    /// send userinfo), the client keeps what it knew.
    pub has_userinfo: bool,
    /// `Support-Url` — a human support contact (channel / chat).
    pub support_url: Option<String>,
    /// `Profile-Web-Page-Url` — the provider's bot / web page.
    pub web_page_url: Option<String>,
}

/// Bundled result of an import: headers + parsed servers + free-text
/// description extracted from leading `# …` comments in the body.
#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub meta: SubscriptionMeta,
    pub servers: Vec<VlessServer>,
    pub description: Option<String>,
    /// Original JSON payload for editable JSON subscriptions. None for
    /// share-link/base64 subscriptions.
    pub source_json: Option<String>,
}

/// Metadata keys that panels (Marzban / Happ-style) inline into the body as
/// `#key: value` lines, duplicating the HTTP response headers. These are NOT
/// human-readable description — they carry client settings — so we route them
/// to metadata and keep them out of the shown description.
fn is_meta_key(key: &str) -> bool {
    matches!(
        key,
        "profile-title"
            | "profile-update-interval"
            | "support-url"
            | "profile-web-page-url"
            | "subscription-userinfo"
            | "announce"
            | "hide-settings"
            | "subscriptions-collapse"
            | "subscriptions-expand-now"
            | "encrypted-subscription"
            | "allow-insecure"
            | "subscription-ping-onopen-enabled"
            | "mux-enable"
            | "mux-tcp-connections"
            | "mux-xudp-connections"
            | "mux-quic"
            | "routing"
            | "dns"
    )
}

/// Parse the leading comment block of a subscription body. Panels prepend two
/// very different things there:
///   1. `#key: value` lines duplicating the HTTP headers (profile-title,
///      subscription-userinfo, mux-*, …) — collected into `headers`.
///   2. Free-text lines (a real human note, or a base64 `announce` banner) —
///      joined into `description`.
///
/// Stops at the first non-comment, non-blank line (the first proxy URI).
pub fn parse_body_meta(body: &str) -> (std::collections::HashMap<String, String>, Option<String>) {
    let text = decode_body(body);
    let mut headers = std::collections::HashMap::new();
    let mut desc_lines = Vec::<String>::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            if headers.is_empty() && desc_lines.is_empty() {
                continue; // skip leading blank lines
            }
            break; // blank line ends the comment block
        }
        let Some(rest) = line.strip_prefix('#') else {
            break; // first real (non-comment) line — stop
        };
        let rest = rest.trim();
        // `#key: value` where key looks like a metadata field → header, not desc.
        if let Some((k, v)) = rest.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            if is_meta_key(&key) {
                headers.insert(key, v.trim().to_string());
                continue;
            }
        }
        desc_lines.push(rest.to_string());
    }
    let description = if desc_lines.is_empty() {
        None
    } else {
        Some(desc_lines.join("\n"))
    };
    (headers, description)
}

/// Schemes we know how to parse inside a subscription or pasted share-link.
pub fn is_supported_uri(line: &str) -> bool {
    let l = line.trim();
    [
        "vless://",
        "trojan://",
        "ss://",
        "vmess://",
        "hysteria2://",
        "hy2://",
        "wireguard://",
        "socks://",
        "socks5://",
        "http://",
        "https://",
    ]
    .iter()
    .any(|scheme| l.starts_with(scheme))
}

/// HTTP(S) is ambiguous in the main import field: it usually names the
/// subscription endpoint, but authenticated/root URLs are also conventional
/// HTTP-proxy links. Treat only a URL with credentials or a fragment label as
/// an unambiguous directly pasted proxy; HTTP links inside a fetched/multiline
/// subscription are already in proxy-list context and do not need this test.
pub fn is_unambiguous_direct_proxy_uri(line: &str) -> bool {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return is_supported_uri(trimmed);
    }
    Url::parse(trimmed).is_ok_and(|url| {
        url.port().is_some()
            && (!url.username().is_empty() || url.password().is_some() || url.fragment().is_some())
    })
}

/// Parse any supported proxy URI, dispatching on its scheme.
pub fn parse_proxy_uri(uri: &str) -> Result<VlessServer, ParseError> {
    let uri = uri.trim();
    let lower = uri.to_ascii_lowercase();
    let server = if lower.starts_with("vless://") {
        parse_vless(uri)?
    } else if lower.starts_with("trojan://") {
        parse_trojan(uri)?
    } else if lower.starts_with("ss://") {
        parse_shadowsocks(uri)?
    } else if lower.starts_with("vmess://") {
        parse_vmess(uri)?
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        parse_hysteria2(uri)?
    } else if lower.starts_with("wireguard://") {
        parse_wireguard_uri(uri)?
    } else if lower.starts_with("socks://") || lower.starts_with("socks5://") {
        parse_socks_uri(uri)?
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        parse_simple_proxy_uri(uri, "http")?
    } else {
        let scheme = uri.split("://").next().unwrap_or(uri);
        return Err(ParseError::UnsupportedScheme(scheme.to_string()));
    };
    // Drop balancer/auto-select sentinels — they aren't real, connectable servers.
    if is_balancer_sentinel(&server.host) {
        return Err(ParseError::BalancerEntry);
    }
    Ok(server)
}

fn label_from(fragment: Option<&str>, host: &str, port: u16) -> String {
    match fragment {
        Some(f) if !f.is_empty() => percent_decode(f),
        _ => format!("{host}:{port}"),
    }
}

fn url_host(url: &Url) -> Option<String> {
    match url.host()? {
        url::Host::Domain(host) => Some(host.to_string()),
        url::Host::Ipv4(host) => Some(host.to_string()),
        url::Host::Ipv6(host) => Some(host.to_string()),
    }
}

fn query_params(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn query_value<'a>(params: &'a HashMap<String, String>, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        params
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
    })
}

fn query_has(
    params: &HashMap<String, String>,
    names: &[&str],
    predicate: impl Fn(&str) -> bool,
) -> bool {
    params.iter().any(|(key, value)| {
        names.iter().any(|name| key.eq_ignore_ascii_case(name)) && predicate(value)
    })
}

fn restored_base64(value: &str) -> String {
    // application/x-www-form-urlencoded query decoding maps '+' to a space;
    // unescaped WireGuard keys in real-world links still use raw base64 '+'.
    value.replace(' ', "+")
}

fn userinfo(url: &Url, allow_base64_pair: bool) -> (String, Option<String>) {
    let username = percent_decode(url.username());
    let password = url.password().map(percent_decode);
    if allow_base64_pair && password.is_none() && !username.is_empty() {
        if let Some(decoded) = b64_decode_str(&username) {
            if let Some((user, pass)) = decoded.split_once(':') {
                return (user.to_string(), Some(pass.to_string()));
            }
        }
    }
    (username, password)
}

fn require_root_path(url: &Url) -> Result<(), ParseError> {
    if matches!(url.path(), "" | "/") {
        Ok(())
    } else {
        Err(ParseError::InvalidUri(
            "proxy share-link must not contain a request path".into(),
        ))
    }
}

/// Parse JSON-form import input into (display name, servers). Accepts an
/// xray/v2ray config (object with an `outbounds` array), a single outbound
/// object, an array of outbound objects and/or share-link strings, or an object
/// embedding those under common keys (servers/links/proxies/configs/list). The
/// name comes from a top-level `remarks`/`name`/`ps`/`title` field.
pub fn parse_json_subscription(body: &str) -> (Option<String>, Vec<VlessServer>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return (None, Vec::new());
    };
    let name = json_str_any(&v, &["remarks", "name", "ps", "title", "Profile-Title"]);
    let mut out = Vec::new();
    collect_json_servers(&v, &mut out, 0, None);
    // A single-server config has no per-server label worth showing (the outbound
    // tag is usually just "proxy"), so use the config's own name for it.
    if out.len() == 1 {
        if let Some(n) = &name {
            out[0].label = n.clone();
        }
    }
    (name, out)
}

/// First non-empty string value among `keys` on a JSON object.
fn json_str_any(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn is_proxy_protocol(p: &str) -> bool {
    matches!(
        p,
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria" | "wireguard" | "http" | "socks"
    )
}

fn collect_json_servers(
    v: &serde_json::Value,
    out: &mut Vec<VlessServer>,
    depth: u8,
    location_source: Option<&serde_json::Value>,
) {
    if depth > 6 {
        return;
    }
    match v {
        serde_json::Value::Array(arr) => {
            for el in arr {
                // At a location-list boundary, each JSON object is its own
                // editable source. Inside a full config, keep the parent config
                // while traversing its `outbounds` array.
                let source = location_source.or_else(|| el.is_object().then_some(el));
                collect_json_servers(el, out, depth + 1, source);
            }
        }
        serde_json::Value::String(s) => {
            let t = s.trim();
            if is_supported_uri(t) {
                if let Ok(srv) = parse_proxy_uri(t) {
                    out.push(srv);
                }
            }
        }
        serde_json::Value::Object(obj) => {
            // A complete Xray profile is ONE logical location. Its internal
            // proxy outbounds are alternatives/chains selected by routing and
            // balancers, not separate countries to expose in the UI.
            if let Some(proxy_outbounds) = obj
                .get("outbounds")
                .and_then(|value| value.as_array())
                .map(|outbounds| {
                    outbounds
                        .iter()
                        .filter(|outbound| {
                            outbound
                                .get("protocol")
                                .and_then(|protocol| protocol.as_str())
                                .map(is_proxy_protocol)
                                .unwrap_or(false)
                        })
                        .collect::<Vec<_>>()
                })
                .filter(|outbounds| !outbounds.is_empty())
            {
                if let Some(mut server) = proxy_outbounds
                    .iter()
                    .find_map(|outbound| parse_outbound(outbound))
                {
                    let source = location_source.unwrap_or(v);
                    if let Some(name) = json_str_any(source, &["remarks", "name", "ps", "title"]) {
                        server.label = name;
                    }
                    server.source_json = serde_json::to_string(source).ok();
                    server.raw_outbound = Some((*proxy_outbounds[0]).clone());
                    server.raw_profile = Some(v.clone());
                    out.push(server);
                }
                return;
            }

            // A proxy outbound: { "protocol": "vless", "settings": …, "streamSettings": … }.
            if obj
                .get("protocol")
                .and_then(|p| p.as_str())
                .map(is_proxy_protocol)
                .unwrap_or(false)
            {
                if let Some(mut s) = parse_outbound(v) {
                    let source = location_source.unwrap_or(v);
                    if let Some(name) = json_str_any(source, &["remarks", "name", "ps", "title"]) {
                        s.label = name;
                    }
                    s.source_json = serde_json::to_string(source).ok();
                    s.raw_outbound = Some(v.clone());
                    out.push(s);
                }
                return;
            }
            // A full Xray config is the location source for every proxy
            // outbound it contains. Utility outbounds are filtered above.
            if let Some(child) = obj.get("outbounds") {
                let source = location_source.unwrap_or(v);
                collect_json_servers(child, out, depth + 1, Some(source));
            }
            // Generic wrappers contain a list of independent locations, so
            // reset the source and let each child object become its own.
            for key in ["servers", "links", "proxies", "configs", "list"] {
                if let Some(child) = obj.get(key) {
                    collect_json_servers(child, out, depth + 1, None);
                }
            }
        }
        _ => {}
    }
}

fn json_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn json_port(v: Option<&serde_json::Value>) -> Option<u16> {
    match v? {
        serde_json::Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
        serde_json::Value::String(st) => st.parse().ok(),
        _ => None,
    }
}

fn endpoint_host_port(endpoint: &str) -> Option<(String, u16)> {
    let parsed = Url::parse(&format!("tcp://{endpoint}")).ok()?;
    Some((url_host(&parsed)?, parsed.port()?))
}

fn direct_or_first<'a>(
    settings: &'a serde_json::Value,
    array_key: &str,
) -> Option<&'a serde_json::Value> {
    if settings.get("address").is_some() {
        Some(settings)
    } else {
        settings.get(array_key)?.as_array()?.first()
    }
}

/// Map an xray streamSettings `network` back to our transport name (the inverse
/// of `xray::xray_network`).
fn normalize_network(net: &str) -> String {
    match net {
        "raw" | "tcp" => "tcp",
        "splithttp" | "xhttp" => "xhttp",
        "h2" => "http",
        other => other,
    }
    .to_string()
}

/// Build a `VlessServer` from one xray outbound object (inverse of
/// `xray::build_proxy_outbound` + `build_stream_settings`).
fn parse_outbound(ob: &serde_json::Value) -> Option<VlessServer> {
    let protocol = ob.get("protocol")?.as_str()?;
    let settings = ob.get("settings");
    let stream = ob.get("streamSettings");
    let tag = ob.get("tag").and_then(|t| t.as_str()).unwrap_or("");
    let label = |host: &str, port: u16| -> String {
        if !tag.is_empty() && !matches!(tag, "proxy" | "direct" | "block" | "dns-out") {
            tag.to_string()
        } else {
            format!("{host}:{port}")
        }
    };

    let mut s = match protocol {
        "vless" | "vmess" => {
            let settings = settings?;
            let endpoint = direct_or_first(settings, "vnext")?;
            let host = json_str(endpoint, "address")?;
            let port = json_port(endpoint.get("port"))?;
            let user = endpoint
                .get("users")
                .and_then(|users| users.as_array()?.first())
                .unwrap_or(endpoint);
            let mut s = VlessServer::base(protocol, host.clone(), port, label(&host, port));
            s.uuid = json_str(user, "id")?;
            s.flow = json_str(user, "flow");
            if protocol == "vmess" {
                if let Some(scy) = json_str(user, "security") {
                    s.raw_params.insert("scy".into(), scy);
                }
                if let Some(aid) = user.get("alterId").and_then(|x| x.as_u64()) {
                    s.raw_params.insert("aid".into(), aid.to_string());
                }
            }
            s
        }
        "trojan" => {
            let srv = direct_or_first(settings?, "servers")?;
            let host = json_str(srv, "address")?;
            let port = json_port(srv.get("port"))?;
            let pw = json_str(srv, "password")?;
            let mut s = VlessServer::base("trojan", host.clone(), port, label(&host, port));
            s.uuid = pw.clone();
            s.password = Some(pw);
            s.flow = json_str(srv, "flow");
            s
        }
        "shadowsocks" => {
            let srv = direct_or_first(settings?, "servers")?;
            let host = json_str(srv, "address")?;
            let port = json_port(srv.get("port"))?;
            let mut s = VlessServer::base("shadowsocks", host.clone(), port, label(&host, port));
            s.method = json_str(srv, "method");
            s.password = json_str(srv, "password");
            s
        }
        "hysteria" => {
            let settings = settings?;
            let host = json_str(settings, "address")?;
            let port = json_port(settings.get("port"))?;
            let mut s = VlessServer::base("hysteria", host.clone(), port, label(&host, port));
            s.uuid = stream
                .and_then(|value| value.get("hysteriaSettings"))
                .and_then(|value| json_str(value, "auth"))
                .or_else(|| json_str(settings, "auth"))
                .unwrap_or_default();
            s
        }
        "wireguard" => {
            let settings = settings?;
            let peer = settings.get("peers")?.as_array()?.first()?;
            let endpoint = json_str(peer, "endpoint")?;
            let (host, port) = endpoint_host_port(&endpoint)?;
            let mut s = VlessServer::base("wireguard", host.clone(), port, label(&host, port));
            s.uuid = json_str(settings, "secretKey").unwrap_or_default();
            s.transport = "wireguard".into();
            s
        }
        "http" | "socks" => {
            let srv = direct_or_first(settings?, "servers")?;
            let host = json_str(srv, "address")?;
            let port = json_port(srv.get("port"))?;
            let mut s = VlessServer::base(protocol, host.clone(), port, label(&host, port));
            if let Some(user) = srv.get("users").and_then(|users| users.as_array()?.first()) {
                s.uuid = json_str_any(user, &["user", "username"]).unwrap_or_default();
                s.password = json_str_any(user, &["pass", "password"]);
            } else {
                s.uuid = json_str_any(srv, &["user", "username"]).unwrap_or_default();
                s.password = json_str_any(srv, &["pass", "password"]);
            }
            s
        }
        _ => return None,
    };
    apply_stream(&mut s, stream);
    if is_balancer_sentinel(&s.host) {
        return None;
    }
    Some(s)
}

/// Every remote endpoint a logical location can dial. Full Xray profiles may
/// contain several proxy outbounds behind one balancer; Linux must pin all of
/// them outside the TUN, not only the representative endpoint shown in the UI.
#[allow(dead_code)]
pub fn server_endpoints(server: &VlessServer) -> Vec<(String, u16)> {
    let mut endpoints = std::collections::BTreeSet::new();
    if let Some(profile) = server.raw_profile.as_ref() {
        if let Some(outbounds) = profile
            .get("outbounds")
            .and_then(serde_json::Value::as_array)
        {
            for outbound in outbounds {
                if let Some(parsed) = parse_outbound(outbound) {
                    endpoints.insert((parsed.host, parsed.port));
                }
            }
        }
    } else if let Some(outbound) = server.raw_outbound.as_ref() {
        if let Some(parsed) = parse_outbound(outbound) {
            endpoints.insert((parsed.host, parsed.port));
        }
    }
    if endpoints.is_empty() {
        endpoints.insert((server.host.clone(), server.port));
    }
    endpoints.into_iter().collect()
}

fn apply_stream(s: &mut VlessServer, stream: Option<&serde_json::Value>) {
    let Some(st) = stream else { return };
    if let Some(net) = st.get("network").and_then(|n| n.as_str()) {
        s.transport = normalize_network(net);
    }
    s.security = st
        .get("security")
        .and_then(|x| x.as_str())
        .unwrap_or("none")
        .to_string();

    if let Some(r) = st.get("realitySettings") {
        s.sni = json_str(r, "serverName");
        s.public_key = json_str(r, "publicKey");
        s.short_id = json_str(r, "shortId");
        s.fingerprint = json_str(r, "fingerprint");
        if let Some(spx) = json_str(r, "spiderX") {
            s.raw_params.insert("spx".into(), spx);
        }
    }
    if let Some(tls) = st.get("tlsSettings") {
        if s.sni.is_none() {
            s.sni = json_str(tls, "serverName");
        }
        if s.fingerprint.is_none() {
            s.fingerprint = json_str(tls, "fingerprint");
        }
        if tls
            .get("allowInsecure")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
        {
            s.raw_params.insert("allowInsecure".into(), "1".into());
        }
        if let Some(alpn) = tls.get("alpn").and_then(|a| a.as_array()) {
            let list: Vec<String> = alpn
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect();
            if !list.is_empty() {
                s.raw_params.insert("alpn".into(), list.join(","));
            }
        }
    }

    match s.transport.as_str() {
        "ws" => {
            if let Some(ws) = st.get("wsSettings") {
                s.path = json_str(ws, "path");
                if let Some(h) = ws
                    .get("headers")
                    .and_then(|h| h.get("Host"))
                    .and_then(|x| x.as_str())
                {
                    s.raw_params.insert("host".into(), h.into());
                }
            }
        }
        "xhttp" => {
            if let Some(x) = st
                .get("xhttpSettings")
                .or_else(|| st.get("splithttpSettings"))
            {
                s.path = json_str(x, "path");
                s.mode = json_str(x, "mode");
                if let Some(h) = json_str(x, "host") {
                    s.raw_params.insert("host".into(), h);
                }
            }
        }
        "httpupgrade" => {
            if let Some(hu) = st.get("httpupgradeSettings") {
                s.path = json_str(hu, "path");
                if let Some(h) = json_str(hu, "host") {
                    s.raw_params.insert("host".into(), h);
                }
            }
        }
        "grpc" => {
            if let Some(g) = st.get("grpcSettings") {
                if let Some(svc) = json_str(g, "serviceName") {
                    s.raw_params.insert("serviceName".into(), svc);
                }
                if g.get("multiMode")
                    .and_then(|m| m.as_bool())
                    .unwrap_or(false)
                {
                    s.mode = Some("multi".into());
                }
                if let Some(auth) = json_str(g, "authority") {
                    s.raw_params.insert("authority".into(), auth);
                }
            }
        }
        _ => {}
    }
}

fn parse_socks_uri(uri: &str) -> Result<VlessServer, ParseError> {
    if let Ok(server) = parse_simple_proxy_uri(uri, "socks") {
        return Ok(server);
    }

    // Legacy v2rayN form: socks://base64(username:password@host:port)#label.
    let rest = uri.split_once("://").map(|(_, rest)| rest).unwrap_or("");
    let (payload, fragment) = rest
        .split_once('#')
        .map_or((rest, None), |(payload, fragment)| {
            (payload, Some(fragment))
        });
    let decoded = b64_decode_str(payload)
        .ok_or_else(|| ParseError::InvalidUri("SOCKS base64 payload".into()))?;
    let (credentials, endpoint) = decoded.rsplit_once('@').ok_or(ParseError::MissingHost)?;
    let (username, password) = credentials
        .split_once(':')
        .ok_or(ParseError::MissingCredentials)?;
    let (host, port) = endpoint_host_port(endpoint).ok_or(ParseError::MissingPort)?;
    let mut server = VlessServer::base(
        "socks",
        host.clone(),
        port,
        label_from(fragment, &host, port),
    );
    server.uuid = username.to_string();
    server.password = Some(password.to_string());
    Ok(server)
}

/// Parse an HTTP(S) or SOCKS5 proxy URL. An explicit port and root path are
/// required so ordinary web URLs in subscription descriptions are not mistaken
/// for anonymous proxies.
fn parse_simple_proxy_uri(uri: &str, protocol: &str) -> Result<VlessServer, ParseError> {
    let url = Url::parse(uri.trim()).map_err(|error| ParseError::InvalidUri(error.to_string()))?;
    require_root_path(&url)?;
    let host = url_host(&url).ok_or(ParseError::MissingHost)?;
    let port = url.port().ok_or(ParseError::MissingPort)?;
    let (username, password) = userinfo(&url, protocol == "socks");
    let params = query_params(&url);

    let mut server = VlessServer::base(
        protocol,
        host.clone(),
        port,
        label_from(url.fragment(), &host, port),
    );
    server.uuid = username;
    server.password = password;
    server.security = if url.scheme().eq_ignore_ascii_case("https") {
        "tls".into()
    } else {
        "none".into()
    };
    server.sni = query_value(&params, &["sni", "serverName"]).map(str::to_string);
    server.fingerprint = query_value(&params, &["fp", "fingerprint"]).map(str::to_string);
    server.raw_params = params;
    Ok(server)
}

/// Parse the widely used Hysteria2 URI scheme. Xray's Hysteria2 transport does
/// not implement every extension used by standalone Hysteria clients, so links
/// requiring certificate bypass, pin-only trust, obfuscation or port hopping
/// are rejected instead of being imported with silently changed semantics.
pub fn parse_hysteria2(uri: &str) -> Result<VlessServer, ParseError> {
    let url = Url::parse(uri.trim()).map_err(|error| ParseError::InvalidUri(error.to_string()))?;
    if !matches!(url.scheme(), "hysteria2" | "hy2") {
        return Err(ParseError::UnsupportedScheme(url.scheme().to_string()));
    }
    require_root_path(&url)?;
    let host = url_host(&url).ok_or(ParseError::MissingHost)?;
    // The official Hysteria2 URI scheme defaults an omitted port to 443.
    let port = url.port().unwrap_or(443);
    let params = query_params(&url);
    let (username, password) = userinfo(&url, false);
    let auth = if username.is_empty() {
        query_value(&params, &["auth"])
            .map(str::to_string)
            .unwrap_or_default()
    } else if let Some(password) = password {
        format!("{username}:{password}")
    } else {
        username
    };
    if auth.is_empty() {
        return Err(ParseError::MissingCredentials);
    }

    if query_has(&params, &["insecure", "allowInsecure"], |value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    }) {
        return Err(ParseError::InvalidUri(
            "Hysteria2 link disables TLS certificate validation".into(),
        ));
    }
    for (names, feature) in [
        (&["obfs", "obfs-password"][..], "obfuscation"),
        (&["mport", "ports"][..], "port hopping"),
        (&["pinSHA256"][..], "certificate pin-only trust"),
        (&["ech"][..], "ECH configuration"),
    ] {
        if query_has(&params, names, |value| {
            !value.is_empty() && !value.eq_ignore_ascii_case("none")
        }) {
            return Err(ParseError::InvalidUri(format!(
                "Hysteria2 {feature} is not supported by the bundled Xray transport"
            )));
        }
    }

    let mut server = VlessServer::base(
        "hysteria",
        host.clone(),
        port,
        label_from(url.fragment(), &host, port),
    );
    server.uuid = auth.clone();
    server.password = Some(auth);
    server.transport = "hysteria".into();
    server.security = "tls".into();
    server.sni = query_value(&params, &["sni", "peer"]).map(str::to_string);
    server.fingerprint = query_value(&params, &["fp", "fingerprint"]).map(str::to_string);
    server.raw_params = params;
    Ok(server)
}

/// Parse v2rayN-compatible WireGuard URIs and the common query-key proposal:
/// `wireguard://<private-key>@host:port?publickey=...&address=...` or
/// `wireguard://host:port?private_key=...&peer_public_key=...`.
pub fn parse_wireguard_uri(uri: &str) -> Result<VlessServer, ParseError> {
    let url = Url::parse(uri.trim()).map_err(|error| ParseError::InvalidUri(error.to_string()))?;
    if url.scheme() != "wireguard" {
        return Err(ParseError::UnsupportedScheme(url.scheme().to_string()));
    }
    require_root_path(&url)?;
    let host = url_host(&url).ok_or(ParseError::MissingHost)?;
    let port = url.port().ok_or(ParseError::MissingPort)?;
    let params = query_params(&url);
    let private_key = if url.username().is_empty() {
        query_value(&params, &["private_key", "privatekey", "secretKey"])
            .map(restored_base64)
            .unwrap_or_default()
    } else {
        restored_base64(&percent_decode(url.username()))
    };
    if private_key.is_empty() {
        return Err(ParseError::MissingCredentials);
    }
    let public_key = query_value(&params, &["publickey", "publicKey", "peer_public_key"])
        .map(restored_base64)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ParseError::InvalidUri("WireGuard public key is required".into()))?;

    let mut server = VlessServer::base(
        "wireguard",
        host.clone(),
        port,
        label_from(url.fragment(), &host, port),
    );
    server.uuid = private_key;
    server.public_key = Some(public_key);
    server.transport = "wireguard".into();
    if let Some(value) = query_value(&params, &["presharedkey", "preSharedKey", "pre_shared_key"]) {
        server
            .raw_params
            .insert("preSharedKey".into(), restored_base64(value));
    }
    if let Some(value) = query_value(&params, &["address", "localAddress"]) {
        server
            .raw_params
            .insert("localAddress".into(), value.to_string());
    }
    for (input, output) in [
        ("reserved", "reserved"),
        ("mtu", "mtu"),
        ("domainStrategy", "domainStrategy"),
        ("allowedIPs", "allowedIPs"),
        ("allowed_ips", "allowedIPs"),
        ("keepAlive", "keepAlive"),
        ("persistent_keepalive", "keepAlive"),
    ] {
        if let Some(value) = query_value(&params, &[input]) {
            server.raw_params.insert(output.into(), value.to_string());
        }
    }
    Ok(server)
}

/// Parse a standard WireGuard configuration. Every connectable `[Peer]`
/// becomes a location that shares the interface private key/address.
pub fn parse_wireguard_config(body: &str) -> Vec<VlessServer> {
    let mut interface = HashMap::<String, String>::new();
    let mut peers = Vec::<HashMap<String, String>>::new();
    let mut section: Option<usize> = None; // 0 = interface, n+1 = peer n

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            section = Some(0);
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            peers.push(HashMap::new());
            section = Some(peers.len());
            continue;
        }
        if line.starts_with('[') {
            section = None;
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let value = raw_value
            .split(['#', ';'])
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if value.is_empty() {
            continue;
        }
        let key = key.trim().to_ascii_lowercase();
        match section {
            Some(0) => {
                interface.insert(key, value);
            }
            Some(peer) => {
                if let Some(target) = peers.get_mut(peer - 1) {
                    target.insert(key, value);
                }
            }
            None => {}
        }
    }

    let Some(private_key) = interface
        .get("privatekey")
        .filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };
    peers
        .into_iter()
        .enumerate()
        .filter_map(|(index, peer)| {
            let endpoint = peer.get("endpoint")?;
            let (host, port) = endpoint_host_port(endpoint)?;
            let public_key = peer.get("publickey").filter(|value| !value.is_empty())?;
            let mut server = VlessServer::base(
                "wireguard",
                host.clone(),
                port,
                format!("WireGuard Peer {} ({host}:{port})", index + 1),
            );
            server.uuid = private_key.clone();
            server.public_key = Some(public_key.clone());
            server.transport = "wireguard".into();
            if let Some(value) = interface.get("address") {
                server
                    .raw_params
                    .insert("localAddress".into(), value.clone());
            }
            if let Some(value) = interface.get("mtu") {
                server.raw_params.insert("mtu".into(), value.clone());
            }
            if let Some(value) = peer.get("presharedkey") {
                server
                    .raw_params
                    .insert("preSharedKey".into(), value.clone());
            }
            if let Some(value) = peer.get("reserved") {
                server.raw_params.insert("reserved".into(), value.clone());
            }
            if let Some(value) = peer.get("allowedips") {
                server.raw_params.insert("allowedIPs".into(), value.clone());
            }
            if let Some(value) = peer.get("persistentkeepalive") {
                server.raw_params.insert("keepAlive".into(), value.clone());
            }
            Some(server)
        })
        .collect()
}

pub fn looks_like_wireguard_config(body: &str) -> bool {
    let mut has_interface = false;
    let mut has_peer = false;
    for line in body.lines().map(str::trim) {
        has_interface |= line.eq_ignore_ascii_case("[Interface]");
        has_peer |= line.eq_ignore_ascii_case("[Peer]");
    }
    has_interface && has_peer
}

/// Parse a single `vless://` URI.
pub fn parse_vless(uri: &str) -> Result<VlessServer, ParseError> {
    let url = Url::parse(uri.trim()).map_err(|e| ParseError::InvalidUri(e.to_string()))?;
    if url.scheme() != "vless" {
        return Err(ParseError::UnsupportedScheme(url.scheme().to_string()));
    }

    let uuid = url.username();
    if uuid.is_empty() {
        return Err(ParseError::MissingCredentials);
    }
    let uuid = percent_decode(uuid);

    let host = url_host(&url).ok_or(ParseError::MissingHost)?;
    let port = url.port().ok_or(ParseError::MissingPort)?;

    let params: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if params.get("type").map(String::as_str) == Some("xhttp") {
        if let Some(extra) = params.get("extra") {
            let value: serde_json::Value = serde_json::from_str(extra)
                .map_err(|e| ParseError::InvalidUri(format!("xhttp extra JSON: {e}")))?;
            if !value.is_object() {
                return Err(ParseError::InvalidUri(
                    "xhttp extra JSON must be an object".into(),
                ));
            }
        }
    }

    let mut s = VlessServer::base(
        "vless",
        host.clone(),
        port,
        label_from(url.fragment(), &host, port),
    );
    s.uuid = uuid;
    s.transport = params
        .get("type")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string());
    s.security = params
        .get("security")
        .cloned()
        .unwrap_or_else(|| "none".to_string());
    s.sni = params.get("sni").cloned();
    s.fingerprint = params.get("fp").cloned();
    s.public_key = params.get("pbk").cloned();
    s.short_id = params.get("sid").cloned();
    s.flow = params.get("flow").cloned();
    s.path = params.get("path").cloned();
    s.mode = params.get("mode").cloned();
    s.packet_encoding = params.get("packetEncoding").cloned();
    s.raw_params = params;
    Ok(s)
}

/// Parse a single `trojan://<password>@<host>:<port>?<params>#<label>` URI.
pub fn parse_trojan(uri: &str) -> Result<VlessServer, ParseError> {
    let url = Url::parse(uri.trim()).map_err(|e| ParseError::InvalidUri(e.to_string()))?;
    if url.scheme() != "trojan" {
        return Err(ParseError::UnsupportedScheme(url.scheme().to_string()));
    }
    let password = percent_decode(url.username());
    if password.is_empty() {
        return Err(ParseError::MissingCredentials);
    }
    let host = url_host(&url).ok_or(ParseError::MissingHost)?;
    let port = url.port().ok_or(ParseError::MissingPort)?;
    let params: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut s = VlessServer::base(
        "trojan",
        host.clone(),
        port,
        label_from(url.fragment(), &host, port),
    );
    s.uuid = password.clone();
    s.password = Some(password);
    s.transport = params
        .get("type")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string());
    s.security = params
        .get("security")
        .cloned()
        .unwrap_or_else(|| "tls".to_string());
    s.sni = params.get("sni").cloned();
    s.fingerprint = params.get("fp").cloned();
    s.path = params.get("path").cloned();
    // Trojan can also run over REALITY/vision — capture those fields too.
    s.public_key = params.get("pbk").cloned();
    s.short_id = params.get("sid").cloned();
    s.flow = params.get("flow").cloned();
    s.mode = params.get("mode").cloned();
    s.raw_params = params;
    Ok(s)
}

/// Parse a Shadowsocks `ss://` URI. Handles SIP002 (base64 userinfo) and the
/// legacy fully-base64 form, with or without a trailing `?plugin=…`.
pub fn parse_shadowsocks(uri: &str) -> Result<VlessServer, ParseError> {
    let rest = uri.trim().strip_prefix("ss://").unwrap_or("");
    // Split off the #fragment label.
    let (main, fragment) = match rest.split_once('#') {
        Some((m, f)) => (m, Some(f)),
        None => (rest, None),
    };
    // Drop any ?plugin=… query.
    let main = main.split('?').next().unwrap_or(main);

    // Two layouts: "userinfo@host:port" or base64("method:password@host:port").
    let (creds, hostport) = if let Some((u, hp)) = main.rsplit_once('@') {
        // userinfo may itself be base64(method:password).
        let decoded = b64_decode_str(u).unwrap_or_else(|| percent_decode(u));
        (decoded, hp.to_string())
    } else {
        // Whole thing is base64.
        let decoded =
            b64_decode_str(main).ok_or_else(|| ParseError::InvalidUri("ss base64".into()))?;
        let (u, hp) = decoded.rsplit_once('@').ok_or(ParseError::MissingHost)?;
        (u.to_string(), hp.to_string())
    };

    let (method, password) = creds
        .split_once(':')
        .ok_or(ParseError::MissingCredentials)?;
    let (host, port_str) = hostport.rsplit_once(':').ok_or(ParseError::MissingPort)?;
    let port: u16 = port_str.parse().map_err(|_| ParseError::MissingPort)?;
    let host = host.trim_matches(['[', ']']).to_string();

    let mut s = VlessServer::base(
        "shadowsocks",
        host.clone(),
        port,
        label_from(fragment, &host, port),
    );
    s.method = Some(method.to_string());
    s.password = Some(password.to_string());
    Ok(s)
}

/// Parse a `vmess://<base64-json>` URI (the common v2rayN JSON form).
pub fn parse_vmess(uri: &str) -> Result<VlessServer, ParseError> {
    let payload = uri.trim().strip_prefix("vmess://").unwrap_or("");
    let json =
        b64_decode_str(payload).ok_or_else(|| ParseError::InvalidUri("vmess base64".into()))?;
    let v: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| ParseError::InvalidUri(e.to_string()))?;

    let host = v
        .get("add")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if host.is_empty() {
        return Err(ParseError::MissingHost);
    }
    // port may be a number or a string — validate the range instead of casting
    // (a bare `as u16` silently wraps 65616 -> 80).
    let port: u16 = match v.get("port") {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .filter(|p| (1..=65535).contains(p))
            .ok_or(ParseError::MissingPort)? as u16,
        Some(serde_json::Value::String(st)) => st.parse().map_err(|_| ParseError::MissingPort)?,
        _ => return Err(ParseError::MissingPort),
    };
    if port == 0 {
        return Err(ParseError::MissingPort);
    }
    let uuid = v
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if uuid.is_empty() {
        return Err(ParseError::MissingCredentials);
    }
    let ps = v.get("ps").and_then(|x| x.as_str()).map(|s| s.to_string());

    let mut s = VlessServer::base(
        "vmess",
        host.clone(),
        port,
        ps.unwrap_or_else(|| format!("{host}:{port}")),
    );
    s.uuid = uuid;
    let net = v
        .get("net")
        .and_then(|x| x.as_str())
        .unwrap_or("tcp")
        .to_string();
    s.transport = net.clone();
    s.security = match v.get("tls").and_then(|x| x.as_str()) {
        Some("tls") => "tls".to_string(),
        Some("reality") => "reality".to_string(),
        _ => "none".to_string(),
    };
    s.sni = v.get("sni").and_then(|x| x.as_str()).map(|s| s.to_string());
    s.path = v
        .get("path")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    s.fingerprint = v.get("fp").and_then(|x| x.as_str()).map(|s| s.to_string());

    // vmess overloads its keys per transport. Mirror them into raw_params under
    // the names the xray config generator reads, so ws/grpc/httpupgrade/h2 hosts
    // and grpc serviceName aren't silently dropped.
    let str_of = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
    let mut raw: HashMap<String, String> = HashMap::new();
    if let Some(h) = str_of("host").filter(|h| !h.is_empty()) {
        raw.insert("host".into(), h);
    }
    if let Some(a) = str_of("alpn").filter(|a| !a.is_empty()) {
        raw.insert("alpn".into(), a);
    }
    if let Some(scy) = str_of("scy").filter(|x| !x.is_empty()) {
        raw.insert("scy".into(), scy);
    }
    // `aid` may be a number or a string.
    if let Some(aid) = v.get("aid") {
        match aid {
            serde_json::Value::Number(n) => {
                raw.insert("aid".into(), n.to_string());
            }
            serde_json::Value::String(st) if !st.is_empty() => {
                raw.insert("aid".into(), st.clone());
            }
            _ => {}
        }
    }
    // `type` is the header-obfs type for tcp/kcp, and the gRPC mode for grpc.
    let header_type = str_of("type").filter(|t| !t.is_empty() && t != "none");
    if net == "grpc" {
        // grpc encodes serviceName in `path`; `type` carries multi/gun mode.
        if let Some(p) = s.path.take().filter(|p| !p.is_empty()) {
            raw.insert("serviceName".into(), p);
        }
        s.mode = header_type;
    } else if let Some(ht) = header_type {
        raw.insert("headerType".into(), ht);
    }
    s.raw_params = raw;
    Ok(s)
}

/// Parse a subscription body: JSON, a standard WireGuard config, or a list of
/// proxy URIs (plaintext or base64). Invalid/unsupported entries are skipped.
pub fn parse_subscription(body: &str) -> Vec<VlessServer> {
    let original = body.trim_start_matches('\u{feff}').trim_start();
    if original.starts_with('{')
        || (original.starts_with('[') && !looks_like_wireguard_config(original))
    {
        return parse_json_subscription(original).1;
    }

    let text = decode_body(body);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{')
        || (trimmed.starts_with('[') && !looks_like_wireguard_config(trimmed))
    {
        return parse_json_subscription(trimmed).1;
    }
    if looks_like_wireguard_config(trimmed) {
        return parse_wireguard_config(trimmed);
    }

    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || !is_supported_uri(trimmed) {
                return None;
            }
            parse_proxy_uri(trimmed).ok()
        })
        .collect()
}

/// Best-effort base64 decode (standard / url-safe, padded or not) to UTF-8.
fn b64_decode_str(s: &str) -> Option<String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(compact.as_bytes()) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

fn decode_body(body: &str) -> String {
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    // Already plaintext if it carries a proxy URI or WireGuard sections.
    if body.lines().any(|line| is_supported_uri(line.trim())) || looks_like_wireguard_config(body) {
        return body.to_string();
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(compact.as_bytes()) {
            if let Ok(s) = String::from_utf8(bytes) {
                return s;
            }
        }
    }
    body.to_string()
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Decode a header value that some panels base64-encode (e.g. a non-ASCII
/// `Profile-Title` or `announce`). The convention is a `base64:` prefix, but a
/// few panels send raw base64 with no prefix, so fall back to a best-effort
/// decode that only replaces the value when the result is valid UTF-8.
pub fn decode_maybe_b64(value: &str) -> String {
    let trimmed = value.trim();
    let payload = trimmed
        .strip_prefix("base64:")
        .or_else(|| trimmed.strip_prefix("Base64:"))
        .map(str::trim);

    // With an explicit prefix we always try to decode; without one we only
    // attempt it when the string can't already be meaningful text.
    let (candidate, explicit) = match payload {
        Some(p) => (p, true),
        None => (trimmed, false),
    };

    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(candidate.as_bytes()) {
            if let Ok(s) = String::from_utf8(bytes) {
                let s = s.trim().to_string();
                // Without a prefix, guard against false positives: only accept a
                // decode that yields printable text different from the input.
                if explicit || (!s.is_empty() && s != trimmed && s.chars().all(|c| !c.is_control()))
                {
                    return s;
                }
            }
        }
    }
    trimmed.to_string()
}

/// Extract subscription metadata from response headers.
///
/// Header names are lowercase ASCII. `Subscription-Userinfo` looks like
/// `upload=0; download=0; total=10737418240; expire=1781461695`.
pub fn parse_headers<F>(get: F) -> SubscriptionMeta
where
    F: Fn(&str) -> Option<String>,
{
    let mut meta = SubscriptionMeta {
        title: get("profile-title")
            .map(|s| decode_maybe_b64(&s))
            .filter(|s| !s.is_empty()),
        update_interval_hours: get("profile-update-interval").and_then(|s| s.trim().parse().ok()),
        support_url: get("support-url")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        web_page_url: get("profile-web-page-url")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        ..Default::default()
    };

    if let Some(info) = get("subscription-userinfo") {
        meta.has_userinfo = true;
        for kv in info.split(';') {
            let kv = kv.trim();
            if let Some((k, v)) = kv.split_once('=') {
                let v = v.trim();
                match k.trim() {
                    "upload" => meta.upload_bytes = v.parse().ok(),
                    "download" => meta.download_bytes = v.parse().ok(),
                    // 0 = unlimited / never expires -> None, so the UI hides
                    // the badge instead of showing "0 B" or 01.01.1970.
                    "total" => meta.total_bytes = v.parse().ok().filter(|&x| x > 0),
                    "expire" => meta.expires_at_unix = v.parse().ok().filter(|&x| x > 0),
                    _ => {}
                }
            }
        }
    }
    meta
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multi_outbound_profile(name: &str) -> serde_json::Value {
        let proxy = |tag: &str, address: &str, port: u16, network: &str| {
            let transport_key = match network {
                "grpc" => "grpcSettings",
                "xhttp" => "xhttpSettings",
                _ => "rawSettings",
            };
            serde_json::json!({
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [{"id": "00000000-0000-0000-0000-000000000001"}]
                    }]
                },
                "streamSettings": {
                    "network": network,
                    "security": "reality",
                    transport_key: {}
                }
            })
        };
        serde_json::json!({
            "remarks": name,
            "dns": {"servers": ["8.8.8.8"]},
            "inbounds": [{"tag": "provider-in", "protocol": "socks", "port": 1080}],
            "outbounds": [
                proxy("proxy", "edge-a.example", 6436, "raw"),
                proxy("proxy-2", "edge-b.example", 6436, "raw"),
                proxy("proxy-3", "edge-b.example", 6437, "grpc"),
                proxy("proxy-4", "edge-b.example", 443, "xhttp"),
                proxy("proxy-5", "edge-c.example", 6436, "raw"),
                proxy("proxy-6", "edge-c.example", 6437, "grpc"),
                proxy("proxy-7", "edge-c.example", 443, "xhttp"),
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {
                "balancers": [{
                    "tag": "estonia-balancer",
                    "selector": ["proxy"],
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": "proxy"
                }],
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "network": "tcp,udp", "balancerTag": "estonia-balancer"}
                ]
            },
            "burstObservatory": {
                "subjectSelector": ["proxy"],
                "pingConfig": {
                    "destination": "https://example.com/generate_204",
                    "interval": "1m",
                    "timeout": "5s",
                    "sampling": 3
                }
            }
        })
    }

    #[test]
    fn full_multi_outbound_profile_is_one_logical_location() {
        let profile = multi_outbound_profile("🇪🇪 Эстония");
        let servers = parse_subscription(&profile.to_string());

        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].label, "🇪🇪 Эстония");
        let raw_profile = servers[0].raw_profile.as_ref().expect("raw profile");
        assert_eq!(raw_profile["outbounds"].as_array().unwrap().len(), 9);
        assert_eq!(
            raw_profile["routing"]["balancers"][0]["tag"],
            "estonia-balancer"
        );
        assert!(raw_profile.get("burstObservatory").is_some());
    }

    #[test]
    fn full_profile_exposes_every_unique_remote_endpoint() {
        let servers = parse_subscription(&multi_outbound_profile("Estonia").to_string());

        assert_eq!(
            server_endpoints(&servers[0]),
            vec![
                ("edge-a.example".into(), 6436),
                ("edge-b.example".into(), 443),
                ("edge-b.example".into(), 6436),
                ("edge-b.example".into(), 6437),
                ("edge-c.example".into(), 443),
                ("edge-c.example".into(), 6436),
                ("edge-c.example".into(), 6437),
            ]
        );
    }

    #[test]
    fn array_of_full_profiles_keeps_one_location_per_profile() {
        let body = serde_json::json!([
            multi_outbound_profile("Estonia"),
            multi_outbound_profile("Germany")
        ]);
        let servers = parse_subscription(&body.to_string());

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].label, "Estonia");
        assert_eq!(servers[1].label, "Germany");
        assert!(servers.iter().all(|server| server.raw_profile.is_some()));
    }

    #[test]
    fn parses_current_xray_json_shape_for_every_proxy_protocol() {
        let profiles = serde_json::json!([
            {"remarks":"VLESS","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"vless.example","port":443,"id":"id","encryption":"none"}}]},
            {"remarks":"VMess","outbounds":[{"tag":"proxy","protocol":"vmess","settings":{"address":"vmess.example","port":443,"id":"id","security":"auto"}}]},
            {"remarks":"Trojan","outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"address":"trojan.example","port":443,"password":"secret"}}]},
            {"remarks":"Shadowsocks","outbounds":[{"tag":"proxy","protocol":"shadowsocks","settings":{"address":"ss.example","port":8388,"method":"2022-blake3-aes-256-gcm","password":"secret"}}]},
            {"remarks":"Hysteria","outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"version":2,"address":"hy.example","port":443}}]},
            {"remarks":"WireGuard","outbounds":[{"tag":"proxy","protocol":"wireguard","settings":{"secretKey":"secret","address":["10.0.0.2/32"],"peers":[{"publicKey":"public","endpoint":"wg.example:2408"}]}}]},
            {"remarks":"HTTP","outbounds":[{"tag":"proxy","protocol":"http","settings":{"address":"http.example","port":3128,"user":"u","pass":"p"}}]},
            {"remarks":"SOCKS","outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"socks.example","port":1080,"user":"u","pass":"p"}}]}
        ]);

        let servers = parse_subscription(&profiles.to_string());
        assert_eq!(servers.len(), 8);
        assert_eq!(
            servers
                .iter()
                .map(|server| (server.protocol.as_str(), server.host.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("vless", "vless.example"),
                ("vmess", "vmess.example"),
                ("trojan", "trojan.example"),
                ("shadowsocks", "ss.example"),
                ("hysteria", "hy.example"),
                ("wireguard", "wg.example"),
                ("http", "http.example"),
                ("socks", "socks.example"),
            ]
        );
        assert!(servers.iter().all(|server| server.raw_profile.is_some()));
    }

    #[test]
    fn parses_full_vless_reality_xhttp() {
        let uri = "vless://3f7e7d8c-1234-5678-9abc-def012345678@89.125.181.236:443?type=xhttp&security=reality&sni=gateway.icloud.com&fp=chrome&pbk=ABC&sid=DEAD&path=/fi-exp-xh-1673aadd&mode=packet-up&packetEncoding=xudp#Finland%20Exp";
        let s = parse_vless(uri).expect("parse");
        assert_eq!(s.uuid, "3f7e7d8c-1234-5678-9abc-def012345678");
        assert_eq!(s.host, "89.125.181.236");
        assert_eq!(s.port, 443);
        assert_eq!(s.label, "Finland Exp");
        assert_eq!(s.transport, "xhttp");
        assert_eq!(s.security, "reality");
        assert_eq!(s.sni.as_deref(), Some("gateway.icloud.com"));
        assert_eq!(s.path.as_deref(), Some("/fi-exp-xh-1673aadd"));
    }

    #[test]
    fn rejects_non_vless() {
        let r = parse_vless("vmess://AAAA@1.2.3.4:443");
        assert!(matches!(r, Err(ParseError::UnsupportedScheme(_))));
    }

    #[test]
    fn drops_balancer_sentinel() {
        // borealisvpn-style auto-select entry: a sentinel host, not a real server.
        let uri = "vless://0eeff936-aa72-4e11-a18a-d3e996f1f37b@balancer.host:443?type=tcp&security=reality&sni=api-maps.yandex.ru&pbk=ABC&sid=DEAD&flow=xtls-rprx-vision#LTE";
        assert!(matches!(
            parse_proxy_uri(uri),
            Err(ParseError::BalancerEntry)
        ));
        // ...and it's silently skipped during a subscription import.
        let body = format!("vless://a@h-a:443?type=tcp&security=reality#Real\n{uri}");
        assert_eq!(parse_subscription(&body).len(), 1);
    }

    #[test]
    fn vmess_rejects_out_of_range_port() {
        use base64::Engine as _;
        // A numeric port above u16 must be rejected, not wrapped (65616 -> 80).
        let json = r#"{"v":"2","add":"1.2.3.4","port":65616,"id":"3f7e7d8c-1234-5678-9abc-def012345678","aid":"0","net":"tcp"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        assert!(matches!(
            parse_vmess(&format!("vmess://{b64}")),
            Err(ParseError::MissingPort)
        ));
    }

    #[test]
    fn parses_plaintext_subscription() {
        let body = "# c\nvless://a@h-a:443?type=tcp&security=reality#A\nvless://b@h-b:443?type=xhttp&security=reality#B\ngarbage";
        let v = parse_subscription(body);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn parse_subscription_accepts_json() {
        let body = r#"{
          "remarks": "Germany",
          "outbounds": [{
            "protocol": "vless",
            "settings": {
              "vnext": [{
                "address": "de.example.com",
                "port": 443,
                "users": [{ "id": "3f7e7d8c-1234-5678-9abc-def012345678" }]
              }]
            },
            "streamSettings": { "network": "tcp", "security": "none" }
          }]
        }"#;
        let servers = parse_subscription(body);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].host, "de.example.com");
        assert_eq!(servers[0].label, "Germany");
    }

    #[test]
    fn json_location_keeps_exact_source_and_proxy_outbound() {
        let body = r#"[{
          "remarks": "Germany | Frankfurt",
          "dns": {"servers": ["https://resolver.invalid/dns-query"]},
          "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
              "vnext": [{
                "address": "de.example.com",
                "port": 443,
                "users": [{ "id": "3f7e7d8c-1234-5678-9abc-def012345678" }]
              }]
            },
            "streamSettings": {
              "network": "xhttp",
              "security": "reality",
              "xhttpSettings": {
                "path": "/",
                "mode": "packet-up",
                "xmux": {"hKeepAlivePeriod": 15}
              }
            }
          }, {
            "tag": "direct",
            "protocol": "freedom"
          }]
        }]"#;
        let root: serde_json::Value = serde_json::from_str(body).unwrap();
        let servers = parse_subscription(body);
        assert_eq!(servers.len(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                servers[0].source_json.as_deref().expect("source JSON")
            )
            .unwrap(),
            root[0]
        );
        assert_eq!(
            servers[0]
                .raw_outbound
                .as_ref()
                .and_then(|outbound| outbound.get("protocol")),
            Some(&serde_json::json!("vless"))
        );
        assert!(servers[0]
            .raw_outbound
            .as_ref()
            .and_then(|outbound| outbound.get("dns"))
            .is_none());
        assert_eq!(servers[0].label, "Germany | Frankfurt");
    }

    #[test]
    fn json_locations_sharing_an_endpoint_are_not_collapsed() {
        let body = r#"[
          {
            "remarks": "Frankfurt primary",
            "outbounds": [{
              "protocol": "vless",
              "settings": {"vnext": [{
                "address": "shared.example.com",
                "port": 443,
                "users": [{"id": "11111111-1111-1111-1111-111111111111"}]
              }]}
            }]
          },
          {
            "remarks": "Frankfurt backup",
            "outbounds": [{
              "protocol": "vless",
              "settings": {"vnext": [{
                "address": "shared.example.com",
                "port": 443,
                "users": [{"id": "22222222-2222-2222-2222-222222222222"}]
              }]}
            }]
          }
        ]"#;

        let servers = parse_subscription(body);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].label, "Frankfurt primary");
        assert_eq!(servers[1].label, "Frankfurt backup");
    }

    #[test]
    fn parses_additional_xray_json_outbound_protocols() {
        let body = r#"[
          {
            "remarks": "Hysteria",
            "outbounds": [{
              "protocol": "hysteria",
              "settings": {"address": "hy.example.com", "port": 443, "version": 2},
              "streamSettings": {"network": "hysteria", "security": "tls"}
            }]
          },
          {
            "remarks": "WireGuard",
            "outbounds": [{
              "protocol": "wireguard",
              "settings": {
                "secretKey": "secret",
                "address": ["10.0.0.2/32"],
                "peers": [{"publicKey": "public", "endpoint": "wg.example.com:2408"}]
              }
            }]
          },
          {
            "remarks": "HTTP proxy",
            "outbounds": [{
              "protocol": "http",
              "settings": {"servers": [{"address": "http.example.com", "port": 8443}]}
            }]
          },
          {
            "remarks": "SOCKS proxy",
            "outbounds": [{
              "protocol": "socks",
              "settings": {"servers": [{"address": "socks.example.com", "port": 1080}]}
            }]
          }
        ]"#;
        let servers = parse_subscription(body);
        assert_eq!(
            servers
                .iter()
                .map(|server| server.protocol.as_str())
                .collect::<Vec<_>>(),
            vec!["hysteria", "wireguard", "http", "socks"]
        );
        assert_eq!(servers[0].host, "hy.example.com");
        assert_eq!(servers[1].host, "wg.example.com");
        assert_eq!(servers[1].port, 2408);
        assert_eq!(servers[2].label, "HTTP proxy");
        assert!(servers.iter().all(|server| server.raw_outbound.is_some()));
    }

    #[test]
    fn inline_headers_are_meta_not_description() {
        // Marzban / Happ-style: panel inlines #key: value lines at the top.
        // They must go to metadata, NOT be shown as the description.
        let body = concat!(
            "#profile-title: KurtaVPN\n",
            "#profile-update-interval: 3\n",
            "#subscription-userinfo: upload=10; download=20; total=0; expire=1780236569\n",
            "#mux-enable: 1\n",
            "#announce: base64:0J/RgNC40LLQtdGC\n", // "Привет"
            "vless://a@h-a:443?type=tcp&security=reality#A\n",
        );
        let (headers, desc) = parse_body_meta(body);
        assert_eq!(
            headers.get("profile-title").map(String::as_str),
            Some("KurtaVPN")
        );
        assert_eq!(headers.get("mux-enable").map(String::as_str), Some("1"));
        assert!(headers.contains_key("subscription-userinfo"));
        // None of the #key: value lines leak into description.
        assert!(desc.is_none(), "description should be empty, got {desc:?}");

        // And the inline userinfo parses into meta via the same path headers do.
        let m = parse_headers(|name| headers.get(name).cloned());
        assert_eq!(m.total_bytes, None); // total=0 -> unlimited
        assert_eq!(m.upload_bytes, Some(10));
        assert_eq!(m.expires_at_unix, Some(1780236569));
        assert!(m.has_userinfo);
    }

    #[test]
    fn freetext_comment_is_description() {
        let body = "# Обходы внизу списка\nvless://a@h-a:443?type=tcp&security=reality#A";
        let (headers, desc) = parse_body_meta(body);
        assert!(headers.is_empty());
        assert_eq!(desc.as_deref(), Some("Обходы внизу списка"));
    }

    #[test]
    fn parses_base64_subscription() {
        let plain = "vless://a@h-a:443?type=tcp&security=reality#A\nvless://b@h-b:443?type=xhttp&security=reality#B";
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain.as_bytes());
        let v = parse_subscription(&b64);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn parses_shadowsocks_sip002() {
        // base64("chacha20-ietf-poly1305:secretpass")
        let creds =
            base64::engine::general_purpose::STANDARD.encode("chacha20-ietf-poly1305:secretpass");
        let uri = format!("ss://{creds}@45.144.52.226:2060#%F0%9F%87%AB%F0%9F%87%AE%20FI");
        let s = parse_shadowsocks(&uri).unwrap();
        assert_eq!(s.protocol, "shadowsocks");
        assert_eq!(s.host, "45.144.52.226");
        assert_eq!(s.port, 2060);
        assert_eq!(s.method.as_deref(), Some("chacha20-ietf-poly1305"));
        assert_eq!(s.password.as_deref(), Some("secretpass"));
        assert!(s.label.contains("FI"));
    }

    #[test]
    fn parses_trojan() {
        let s =
            parse_trojan("trojan://pass123@h.example.com:443?sni=h.example.com#Trojan").unwrap();
        assert_eq!(s.protocol, "trojan");
        assert_eq!(s.host, "h.example.com");
        assert_eq!(s.port, 443);
        assert_eq!(s.password.as_deref(), Some("pass123"));
        assert_eq!(s.sni.as_deref(), Some("h.example.com"));
    }

    #[test]
    fn parses_vmess() {
        let json = r#"{"v":"2","ps":"My VMess","add":"1.2.3.4","port":"443","id":"uuid-1234","net":"ws","tls":"tls","path":"/p"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let s = parse_vmess(&format!("vmess://{b64}")).unwrap();
        assert_eq!(s.protocol, "vmess");
        assert_eq!(s.host, "1.2.3.4");
        assert_eq!(s.port, 443);
        assert_eq!(s.uuid, "uuid-1234");
        assert_eq!(s.transport, "ws");
        assert_eq!(s.security, "tls");
        assert_eq!(s.label, "My VMess");
    }

    #[test]
    fn parses_http_and_socks_proxy_links_without_mistaking_web_paths() {
        let http = parse_proxy_uri(
            "https://alice:p%40ss@proxy.example:8443/?sni=tls.example#Secure%20HTTP",
        )
        .unwrap();
        assert_eq!(http.protocol, "http");
        assert_eq!(http.uuid, "alice");
        assert_eq!(http.password.as_deref(), Some("p@ss"));
        assert_eq!(http.security, "tls");
        assert_eq!(http.sni.as_deref(), Some("tls.example"));
        assert_eq!(http.label, "Secure HTTP");

        let credentials = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("bob:s3cret");
        let socks =
            parse_proxy_uri(&format!("socks5://{credentials}@socks.example:1080#SOCKS")).unwrap();
        assert_eq!(socks.protocol, "socks");
        assert_eq!(socks.uuid, "bob");
        assert_eq!(socks.password.as_deref(), Some("s3cret"));

        let legacy = base64::engine::general_purpose::STANDARD
            .encode("legacy:secret@legacy-socks.example:1081");
        let legacy = parse_proxy_uri(&format!("socks://{legacy}#Legacy")).unwrap();
        assert_eq!(legacy.host, "legacy-socks.example");
        assert_eq!(legacy.uuid, "legacy");
        assert_eq!(legacy.password.as_deref(), Some("secret"));

        assert!(parse_proxy_uri("https://example.com:443/subscription/token").is_err());
        assert!(is_unambiguous_direct_proxy_uri(
            "http://user:pass@proxy.example:3128"
        ));
        assert!(!is_unambiguous_direct_proxy_uri(
            "https://provider.example:443/sub"
        ));
    }

    #[test]
    fn parses_strict_hysteria2_links_and_rejects_unsupported_weakening() {
        let server =
            parse_proxy_uri("hy2://auth%3Avalue@hy.example:443/?sni=edge.example&alpn=h3#Hysteria")
                .unwrap();
        assert_eq!(server.protocol, "hysteria");
        assert_eq!(server.uuid, "auth:value");
        assert_eq!(server.transport, "hysteria");
        assert_eq!(server.security, "tls");
        assert_eq!(server.sni.as_deref(), Some("edge.example"));
        assert_eq!(
            server.raw_params.get("alpn").map(String::as_str),
            Some("h3")
        );
        assert_eq!(
            parse_proxy_uri("hysteria2://auth@hy.example/#DefaultPort")
                .unwrap()
                .port,
            443
        );

        for query in [
            "insecure=1",
            "allowInsecure=true",
            "insecure=0&allowInsecure=true",
            "obfs=salamander&obfs-password=secret",
            "mport=20000-30000",
            "pinSHA256=deadbeef",
            "ech=AAAA",
        ] {
            assert!(
                parse_proxy_uri(&format!("hysteria2://auth@hy.example:443/?{query}")).is_err(),
                "unsafe/unsupported query was accepted: {query}"
            );
        }
    }

    #[test]
    fn parses_wireguard_uri_and_standard_config() {
        let uri = "wireguard://private%2Bkey%2F%3D@wg.example:51820?publickey=public%2Bkey%2F%3D&presharedkey=shared%2Bkey%2F%3D&address=10.7.0.2%2F32&reserved=1%2C2%2C3&mtu=1380#WG";
        let server = parse_proxy_uri(uri).unwrap();
        assert_eq!(server.protocol, "wireguard");
        assert_eq!(server.uuid, "private+key/=");
        assert_eq!(server.public_key.as_deref(), Some("public+key/="));
        assert_eq!(
            server.raw_params.get("preSharedKey").map(String::as_str),
            Some("shared+key/=")
        );
        assert_eq!(
            server.raw_params.get("localAddress").map(String::as_str),
            Some("10.7.0.2/32")
        );
        let proposed = parse_proxy_uri(
            "wireguard://wg-query.example:51820?private_key=private%2Bkey&peer_public_key=public%2Bkey&allowed_ips=0.0.0.0%2F0&persistent_keepalive=20",
        )
        .unwrap();
        assert_eq!(proposed.uuid, "private+key");
        assert_eq!(proposed.public_key.as_deref(), Some("public+key"));
        assert_eq!(
            proposed.raw_params.get("allowedIPs").map(String::as_str),
            Some("0.0.0.0/0")
        );
        assert_eq!(
            proposed.raw_params.get("keepAlive").map(String::as_str),
            Some("20")
        );

        let config = r#"
[Interface]
PrivateKey = private-key
Address = 10.8.0.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = public-one
PresharedKey = shared-one
Endpoint = wg-one.example:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

[Peer]
PublicKey = public-two
Endpoint = [2001:db8:1::10]:2408
AllowedIPs = 0.0.0.0/0
"#;
        assert!(looks_like_wireguard_config(config));
        let peers = parse_subscription(config);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].host, "wg-one.example");
        assert_eq!(peers[0].port, 51820);
        assert_eq!(peers[0].uuid, "private-key");
        assert_eq!(peers[0].public_key.as_deref(), Some("public-one"));
        assert_eq!(
            peers[0].raw_params.get("allowedIPs").map(String::as_str),
            Some("0.0.0.0/0, ::/0")
        );
        assert_eq!(
            peers[0].raw_params.get("keepAlive").map(String::as_str),
            Some("25")
        );
        let first_config = crate::xray::build_xray_config(
            &peers[0],
            &crate::split::SplitInput::default(),
            false,
            "warn",
        );
        assert_eq!(
            first_config["outbounds"][0]["settings"]["peers"][0]["allowedIPs"],
            serde_json::json!(["0.0.0.0/0", "::/0"])
        );
        assert_eq!(
            first_config["outbounds"][0]["settings"]["peers"][0]["keepAlive"],
            25
        );
        assert_eq!(
            peers[0].raw_params.get("localAddress").map(String::as_str),
            Some("10.8.0.2/32, fd00::2/128")
        );
        assert_eq!(peers[1].host, "2001:db8:1::10");
        assert_eq!(peers[1].port, 2408);
        crate::xray::validate_server(&peers[1]).unwrap();
        let xray_config = crate::xray::build_xray_config(
            &peers[1],
            &crate::split::SplitInput::default(),
            false,
            "warn",
        );
        assert_eq!(
            xray_config["outbounds"][0]["settings"]["peers"][0]["endpoint"],
            "[2001:db8:1::10]:2408"
        );

        let encoded = base64::engine::general_purpose::STANDARD.encode(config);
        assert_eq!(parse_subscription(&encoded).len(), 2);
    }

    #[test]
    fn subscription_share_links_cover_every_xray_proxy_protocol() {
        let ss = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:pw");
        let vmess_json =
            r#"{"v":"2","ps":"VMess","add":"vm.example","port":"443","id":"uuid","net":"tcp"}"#;
        let vmess = base64::engine::general_purpose::STANDARD.encode(vmess_json);
        let body = format!(
            "vless://a@vl.example:443#VLESS\nvmess://{vmess}\ntrojan://p@tr.example:443#Trojan\nss://{ss}@ss.example:8388#SS\nhy2://auth@hy.example:443/#HY\nwireguard://private@wg.example:51820?publickey=public&address=10.0.0.2%2F32#WG\nhttp://u:p@http.example:3128#HTTP\nsocks5://u:p@socks.example:1080#SOCKS"
        );
        let servers = parse_subscription(&body);
        assert_eq!(servers.len(), 8);
        for server in &servers {
            crate::xray::validate_server(server).unwrap_or_else(|error| {
                panic!("{} share-link was rejected: {error}", server.protocol)
            });
            let config = crate::xray::build_xray_config(
                server,
                &crate::split::SplitInput::default(),
                false,
                "warn",
            );
            assert_eq!(config["outbounds"][0]["protocol"], server.protocol);
        }
        assert_eq!(
            servers
                .iter()
                .map(|server| server.protocol.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "http",
                "hysteria",
                "shadowsocks",
                "socks",
                "trojan",
                "vless",
                "vmess",
                "wireguard",
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn parses_meta_headers() {
        let m = parse_headers(|name| match name {
            "profile-title" => Some("Varmlen".into()),
            "profile-update-interval" => Some("12".into()),
            "subscription-userinfo" => {
                Some("upload=10; download=200; total=1099511627776; expire=1781461695".into())
            }
            "support-url" => Some("https://t.me/x_bot".into()),
            _ => None,
        });
        assert_eq!(m.title.as_deref(), Some("Varmlen"));
        assert_eq!(m.update_interval_hours, Some(12));
        assert_eq!(m.upload_bytes, Some(10));
        assert_eq!(m.download_bytes, Some(200));
        assert_eq!(m.total_bytes, Some(1_099_511_627_776));
        assert_eq!(m.expires_at_unix, Some(1_781_461_695));
        assert_eq!(m.support_url.as_deref(), Some("https://t.me/x_bot"));
        assert!(m.has_userinfo);
    }

    #[test]
    fn meta_missing_headers_yields_defaults() {
        let m = parse_headers(|_| None);
        assert!(m.title.is_none());
        assert!(m.total_bytes.is_none());
        // No userinfo header at all: the client must KEEP its stored values.
        assert!(!m.has_userinfo);
    }

    #[test]
    fn userinfo_zero_or_absent_expiry_means_never() {
        // expire=0 -> never expires; the UI must not show 01.01.1970.
        let m = parse_headers(|name| match name {
            "subscription-userinfo" => Some("upload=1; download=2; total=0; expire=0".into()),
            _ => None,
        });
        assert!(m.has_userinfo);
        assert_eq!(m.expires_at_unix, None);
        assert_eq!(m.total_bytes, None); // 0 quota = unlimited
                                         // An "infinite" panel plan often just OMITS expire — the header is
                                         // still authoritative, so stored expiry must be cleared by the client.
        let m2 = parse_headers(|name| match name {
            "subscription-userinfo" => Some("upload=1; download=2".into()),
            _ => None,
        });
        assert!(m2.has_userinfo);
        assert_eq!(m2.expires_at_unix, None);
    }

    #[test]
    fn decodes_base64_prefixed_title() {
        let b64 = base64::engine::general_purpose::STANDARD.encode("Borealis VPS".as_bytes());
        let m = parse_headers(|name| match name {
            "profile-title" => Some(format!("base64:{b64}")),
            _ => None,
        });
        assert_eq!(m.title.as_deref(), Some("Borealis VPS"));
    }

    #[test]
    fn plain_title_is_left_untouched() {
        let m = parse_headers(|name| match name {
            "profile-title" => Some("Varmlen".into()),
            _ => None,
        });
        assert_eq!(m.title.as_deref(), Some("Varmlen"));
    }
}
