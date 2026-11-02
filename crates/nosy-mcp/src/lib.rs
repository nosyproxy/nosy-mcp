//! Model Context Protocol server for Nosy.
//!
//! Runs as `nosy-mcp` over stdio and talks to a running Nosy instance
//! through its local HTTP API, so everything an agent does is visible in the UI:
//! its requests land in the "MCP" Repeater tab and its annotations show up in
//! the proxy history immediately.

mod client;
mod edit;
mod format;

use std::{collections::BTreeMap, sync::Arc};

use nosy_codec::{Op, apply as apply_op, smart_chain};
use nosy_model::{FlowPatch, NewRepeaterTab, SendRequest, Target};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;

pub use client::Api;

#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Base URL of the Nosy UI/API, e.g. `http://127.0.0.1:1337`.
    pub api: String,
    /// Allow `send_request` to any host, not only hosts already in the history.
    pub allow_any_host: bool,
}

const MCP_TAB: &str = "MCP";
const DEFAULT_BODY_CHARS: usize = 20_000;

const INSTRUCTIONS: &str = "Nosy is an intercepting HTTP(S) proxy. These tools read the traffic \
it captured and send requests through its Repeater.\n\
Typical workflow: list_hosts → list_flows (filter by host/status/method) → get_flow for full \
request/response → search_flows to find tokens, parameters or secrets across bodies → \
replay_flow / send_request to test variations → annotate_flow to mark findings (the user sees \
highlights and notes in the UI). decode handles Base64/URL/HTML/hex/JWT/gzip and hashes.\n\
Bodies are returned decompressed; large bodies are truncated (see max_body_chars).";

pub async fn serve_stdio(cfg: McpConfig) -> anyhow::Result<()> {
    let server = NosyMcp::new(cfg);
    let service = server.serve(rmcp::transport::stdio_pipes()).await?;
    service.waiting().await?;
    Ok(())
}

#[derive(Clone)]
pub struct NosyMcp {
    api: Api,
    allow_any_host: bool,
    /// Cached id of the "MCP" repeater tab (serializes its creation).
    tab: Arc<Mutex<Option<i64>>>,
    tool_router: ToolRouter<Self>,
}

// ---------------------------------------------------------------- tool arguments

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFlowsArgs {
    /// Case-insensitive substring matched against host + path.
    pub query: Option<String>,
    /// Host filter; supports globs such as `*.example.com`.
    pub host: Option<String>,
    /// HTTP methods to include, e.g. ["POST", "PUT"].
    pub methods: Option<Vec<String>>,
    /// Status classes to include: 2 = 2xx, 3, 4, 5; 0 = no response (failed or pending).
    pub status_classes: Option<Vec<u8>>,
    /// Hide static assets (js, css, images, fonts, media).
    pub hide_static: Option<bool>,
    /// Max flows to return (default 50, max 500).
    pub limit: Option<u32>,
    /// Pagination: only flows with id lower than this (use the value printed at the end).
    pub before_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFlowArgs {
    /// Flow id (the number after `#`).
    pub id: i64,
    /// Which part to return: "request", "response" or "both" (default).
    pub part: Option<String>,
    /// Truncate each body to this many characters (default 20000).
    pub max_body_chars: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchArgs {
    /// Case-insensitive text to find in request/response heads and decompressed bodies.
    pub query: String,
    /// "all" (default), "request" or "response".
    pub scope: Option<String>,
    /// Max hits (default 20, max 200).
    pub limit: Option<u32>,
    /// Continue an earlier search: only flows with id lower than this.
    pub before_id: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendArgs {
    /// Full raw HTTP/1.x request: request line, headers, blank line, body. `\n` line endings are fine.
    /// Example: "GET /api/me HTTP/1.1\nHost: example.com\nCookie: s=1\n\n"
    pub raw_request: String,
    /// Target host; defaults to the Host header.
    pub host: Option<String>,
    /// Target port; defaults to the Host header's port, else 443 (TLS) or 80.
    pub port: Option<u16>,
    /// Use TLS (default true).
    pub tls: Option<bool>,
    /// Send over HTTP/2 instead of HTTP/1.1 (default false).
    pub http2: Option<bool>,
    /// Recompute Content-Length from the body (default true).
    pub update_content_length: Option<bool>,
    /// Timeout in milliseconds (default 30000).
    pub timeout_ms: Option<u64>,
    /// Truncate the response body to this many characters (default 20000).
    pub max_body_chars: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReplayArgs {
    /// Id of the captured flow to re-send.
    pub id: i64,
    /// Replace the HTTP method.
    pub method: Option<String>,
    /// Replace the path + query string, e.g. "/api/users/2?debug=1".
    pub path: Option<String>,
    /// Headers to set or replace, e.g. {"Authorization": "Bearer x"}.
    pub set_headers: Option<BTreeMap<String, String>>,
    /// Header names to remove, e.g. ["Cookie"].
    pub remove_headers: Option<Vec<String>>,
    /// Replace the body.
    pub body: Option<String>,
    /// Force HTTP/2 on or off (default: as captured).
    pub http2: Option<bool>,
    /// Timeout in milliseconds (default 30000).
    pub timeout_ms: Option<u64>,
    /// Truncate the response body to this many characters (default 20000).
    pub max_body_chars: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecodeArgs {
    /// The data to transform.
    pub input: String,
    /// Operations applied in order. Omit for automatic detection of nested encodings.
    /// Decode: b64-dec, url-dec, html-dec, hex-dec, uni-dec, jwt, gunzip, inflate, brotli, zstd.
    /// Encode: b64-enc, b64url-enc, url-enc, url-enc-all, html-enc, hex-enc, uni-enc, gzip.
    /// Hash: md5, sha1, sha256, sha384, sha512.
    pub operations: Option<Vec<String>>,
    /// Treat `input` as hex-encoded bytes (for binary data).
    pub input_is_hex: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnnotateArgs {
    /// Flow id.
    pub id: i64,
    /// One of red, orange, yellow, green, cyan, blue, purple, or "none" to clear.
    pub highlight: Option<String>,
    /// Free-text note shown next to the flow in the UI; "" clears it.
    pub note: Option<String>,
}

const HIGHLIGHTS: &[&str] = &["red", "orange", "yellow", "green", "cyan", "blue", "purple"];

// ---------------------------------------------------------------- tools

#[tool_router]
impl NosyMcp {
    pub fn new(cfg: McpConfig) -> Self {
        Self {
            api: Api::new(&cfg.api),
            allow_any_host: cfg.allow_any_host,
            tab: Arc::new(Mutex::new(None)),
            tool_router: Self::tool_router(),
        }
    }

    /// List hosts seen in the proxy history with their request counts (most active first).
    #[tool(annotations(title = "List hosts", read_only_hint = true, open_world_hint = false))]
    async fn list_hosts(&self) -> Result<String, String> {
        let hosts = self.api.hosts().await?;
        if hosts.is_empty() {
            return Ok("No traffic captured yet.".into());
        }
        Ok(hosts
            .iter()
            .map(|h| format!("{} ({})", h.host, h.count))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    /// List captured HTTP flows, newest first, with optional filters. Each line:
    /// `#id METHOD status url · response size · type · duration`.
    #[tool(annotations(title = "List flows", read_only_hint = true, open_world_hint = false))]
    async fn list_flows(&self, Parameters(a): Parameters<ListFlowsArgs>) -> Result<String, String> {
        let limit = a.limit.unwrap_or(50).clamp(1, 500);
        let mut q: Vec<(&str, String)> = vec![("limit", limit.to_string())];
        if let Some(v) = a.query.filter(|v| !v.is_empty()) {
            q.push(("q", v));
        }
        if let Some(v) = a.host.filter(|v| !v.is_empty()) {
            q.push(("host", v));
        }
        if let Some(v) = a.methods.filter(|v| !v.is_empty()) {
            q.push(("methods", v.join(",")));
        }
        if let Some(v) = a.status_classes.filter(|v| !v.is_empty()) {
            q.push((
                "status",
                v.iter().map(u8::to_string).collect::<Vec<_>>().join(","),
            ));
        }
        if a.hide_static == Some(true) {
            q.push(("hide_static", "true".into()));
        }
        if let Some(b) = a.before_id {
            q.push(("before_id", b.to_string()));
        }
        let flows = self.api.flows(&q).await?;
        if flows.is_empty() {
            return Ok("No flows match.".into());
        }
        let mut out = flows
            .iter()
            .map(format::flow_line)
            .collect::<Vec<_>>()
            .join("\n");
        if flows.len() as u32 == limit
            && let Some(last) = flows.last()
        {
            out.push_str(&format!(
                "\n\nMore results: call again with before_id={}",
                last.id
            ));
        }
        Ok(out)
    }

    /// Get one flow: summary plus the raw request and/or response (bodies decompressed).
    #[tool(annotations(title = "Get flow", read_only_hint = true, open_world_hint = false))]
    async fn get_flow(&self, Parameters(a): Parameters<GetFlowArgs>) -> Result<String, String> {
        let max = a.max_body_chars.unwrap_or(DEFAULT_BODY_CHARS);
        let part = a.part.as_deref().unwrap_or("both");
        let detail = self.api.flow(a.id).await?;
        let mut out = format::flow_line(&detail.summary);
        if part != "response" {
            let raw = self.api.flow_message(a.id, false).await?;
            out.push_str("\n\n=== REQUEST ===\n");
            out.push_str(&format::message(&raw, max));
        }
        if part != "request" {
            out.push_str("\n\n=== RESPONSE ===\n");
            if detail.summary.status.is_some() {
                let raw = self.api.flow_message(a.id, true).await?;
                out.push_str(&format::message(&raw, max));
            } else {
                out.push_str(
                    detail
                        .summary
                        .error
                        .as_deref()
                        .unwrap_or("(no response yet)"),
                );
            }
        }
        if detail.summary.truncated {
            out.push_str("\n\n[note: a body exceeded the proxy's capture limit and is incomplete]");
        }
        Ok(out)
    }

    /// Full-text search (case-insensitive) across request/response heads and decompressed
    /// bodies, newest flows first. Good for finding tokens, API keys, parameters, error messages.
    #[tool(annotations(title = "Search flows", read_only_hint = true, open_world_hint = false))]
    async fn search_flows(&self, Parameters(a): Parameters<SearchArgs>) -> Result<String, String> {
        if a.query.trim().is_empty() {
            return Err("query must not be empty".into());
        }
        let mut q: Vec<(&str, String)> = vec![
            ("q", a.query.clone()),
            ("limit", a.limit.unwrap_or(20).to_string()),
        ];
        if let Some(s) = a.scope {
            q.push(("scope", s));
        }
        if let Some(b) = a.before_id {
            q.push(("before_id", b.to_string()));
        }
        let res = self.api.search(&q).await?;
        let mut out = if res.hits.is_empty() {
            format!("No matches for {:?} in {} flows.", a.query, res.scanned)
        } else {
            res.hits
                .iter()
                .map(|h| {
                    format!(
                        "{}\n    {}: {}",
                        format::flow_line(&h.flow),
                        h.location,
                        h.snippet
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        if let Some(next) = res.next_before_id {
            out.push_str(&format!(
                "\n\nScanned {} flows; older flows remain: call again with before_id={next}",
                res.scanned
            ));
        }
        Ok(out)
    }

    /// Send a raw HTTP request through Nosy's Repeater (HTTP/1.x is sent byte-for-byte) and
    /// return the response. Requests are recorded in the "MCP" Repeater tab. By default only
    /// hosts already present in the proxy history may be targeted.
    #[tool(annotations(
        title = "Send request",
        read_only_hint = false,
        destructive_hint = false,
        open_world_hint = true
    ))]
    async fn send_request(&self, Parameters(a): Parameters<SendArgs>) -> Result<String, String> {
        let from_header = edit::host_header(&a.raw_request);
        let host = a
            .host
            .clone()
            .or_else(|| from_header.as_ref().map(|(h, _)| h.clone()))
            .ok_or("no target host: pass `host` or include a Host header")?;
        let tls = a.tls.unwrap_or(true);
        let port = a
            .port
            .or_else(|| {
                from_header
                    .as_ref()
                    .and_then(|(h, p)| (h.eq_ignore_ascii_case(&host)).then_some(*p).flatten())
            })
            .unwrap_or(if tls { 443 } else { 80 });
        self.check_host(&host).await?;
        let target = Target {
            host,
            port,
            tls,
            http2: a.http2.unwrap_or(false),
        };
        self.dispatch(
            target,
            a.raw_request,
            a.update_content_length.unwrap_or(true),
            a.timeout_ms,
            a.max_body_chars,
        )
        .await
    }

    /// Re-send a captured flow, optionally changing method, path, headers or body (Content-Length
    /// is recomputed). Ideal for testing authorization (remove/replace cookies or tokens), IDOR
    /// (change ids in the path) and injection (alter parameters).
    #[tool(annotations(
        title = "Replay flow",
        read_only_hint = false,
        destructive_hint = false,
        open_world_hint = true
    ))]
    async fn replay_flow(&self, Parameters(a): Parameters<ReplayArgs>) -> Result<String, String> {
        let tpl = self.api.replay_template(a.id).await?;
        let raw = edit::apply(
            &tpl.raw_request,
            &edit::Edits {
                method: a.method.as_deref(),
                path: a.path.as_deref(),
                set_headers: a.set_headers.as_ref(),
                remove_headers: a.remove_headers.as_deref(),
                body: a.body.as_deref(),
            },
        );
        let mut target = tpl.target;
        if let Some(h2) = a.http2 {
            target.http2 = h2;
        }
        self.dispatch(target, raw, true, a.timeout_ms, a.max_body_chars)
            .await
    }

    /// Transform data locally: decode/encode Base64, URL, HTML entities, hex, unicode escapes,
    /// decode JWTs, (de)compress gzip/deflate/brotli/zstd, or hash (MD5/SHA). Without
    /// `operations`, nested encodings are detected and peeled automatically
    /// (e.g. URL → Base64 → gzip → JSON).
    #[tool(annotations(
        title = "Decode / encode",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn decode(&self, Parameters(a): Parameters<DecodeArgs>) -> Result<String, String> {
        let input = if a.input_is_hex == Some(true) {
            apply_op(Op::HexDec, a.input.as_bytes()).map_err(|e| e.to_string())?
        } else {
            a.input.into_bytes()
        };
        let steps: Vec<(Op, Vec<u8>)> = match a.operations.filter(|o| !o.is_empty()) {
            None => {
                let chain = smart_chain(&input, 8);
                if chain.is_empty() {
                    return Ok("No known encoding detected.".into());
                }
                chain
            }
            Some(ops) => {
                let mut cur = input;
                let mut out = Vec::new();
                for name in ops {
                    let op: Op = name
                        .parse()
                        .map_err(|e: nosy_codec::TransformError| e.to_string())?;
                    cur = apply_op(op, &cur)
                        .map_err(|e| format!("step {} ({}) failed: {e}", out.len() + 1, op.id()))?;
                    out.push((op, cur.clone()));
                }
                out
            }
        };
        let mut text = String::new();
        let last = steps.len() - 1;
        for (i, (op, bytes)) in steps.iter().enumerate() {
            if i == last {
                text.push_str(&format!(
                    "{}. {} → result ({} bytes):\n{}",
                    i + 1,
                    op.id(),
                    bytes.len(),
                    format::body_text(bytes, DEFAULT_BODY_CHARS)
                ));
            } else {
                text.push_str(&format!("{}. {} → {} bytes\n", i + 1, op.id(), bytes.len()));
            }
        }
        Ok(text)
    }

    /// Highlight a flow and/or attach a note. The user sees it immediately in the proxy history,
    /// so use it to flag findings (e.g. red = vulnerability, yellow = worth a look).
    #[tool(annotations(
        title = "Annotate flow",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = false
    ))]
    async fn annotate_flow(
        &self,
        Parameters(a): Parameters<AnnotateArgs>,
    ) -> Result<String, String> {
        let highlight = match a.highlight.as_deref().map(str::to_ascii_lowercase) {
            None => None,
            Some(h) if h == "none" || h.is_empty() => Some(String::new()),
            Some(h) if HIGHLIGHTS.contains(&h.as_str()) => Some(h),
            Some(h) => {
                return Err(format!(
                    "unknown highlight {h:?}; use one of {} or none",
                    HIGHLIGHTS.join(", ")
                ));
            }
        };
        if highlight.is_none() && a.note.is_none() {
            return Err("nothing to change: pass highlight and/or note".into());
        }
        let f = self
            .api
            .patch_flow(
                a.id,
                &FlowPatch {
                    highlight,
                    note: a.note,
                },
            )
            .await?;
        Ok(format!("Updated: {}", format::flow_line(&f)))
    }
}

impl NosyMcp {
    async fn check_host(&self, host: &str) -> Result<(), String> {
        if self.allow_any_host {
            return Ok(());
        }
        let hosts = self.api.hosts().await?;
        if hosts.iter().any(|h| h.host.eq_ignore_ascii_case(host)) {
            Ok(())
        } else {
            Err(format!(
                "host {host:?} is not in the proxy history, so send_request refuses to contact it. \
                 Browse it through the proxy first, or restart the MCP server with `nosy-mcp --allow-any-host`."
            ))
        }
    }

    async fn mcp_tab(&self, target: &Target, raw: &str, refresh: bool) -> Result<i64, String> {
        let mut cached = self.tab.lock().await;
        if let (Some(id), false) = (*cached, refresh) {
            return Ok(id);
        }
        let tabs = self.api.tabs().await?;
        let id = match tabs.iter().find(|t| t.name == MCP_TAB) {
            Some(t) => t.id,
            None => {
                self.api
                    .create_tab(&NewRepeaterTab {
                        name: Some(MCP_TAB.into()),
                        target: target.clone(),
                        raw_request: raw.into(),
                    })
                    .await?
                    .id
            }
        };
        *cached = Some(id);
        Ok(id)
    }

    async fn dispatch(
        &self,
        target: Target,
        raw: String,
        update_content_length: bool,
        timeout_ms: Option<u64>,
        max_body_chars: Option<usize>,
    ) -> Result<String, String> {
        let req = SendRequest {
            target: target.clone(),
            raw_request: raw.clone(),
            update_content_length,
            timeout_ms,
        };
        let mut tab = self.mcp_tab(&target, &raw, false).await?;
        let entry = match self.api.send(tab, &req).await {
            // The user may have closed the tab: recreate it once.
            Err(e) if e.starts_with("not found") => {
                tab = self.mcp_tab(&target, &raw, true).await?;
                self.api.send(tab, &req).await?
            }
            r => r?,
        };
        let where_ = format!(
            "{}://{}:{} · Repeater tab \"{MCP_TAB}\" entry #{}",
            if target.tls { "https" } else { "http" },
            target.host,
            target.port,
            entry.id
        );
        if let Some(e) = entry.error {
            return Err(format!(
                "request failed after {}: {e}\n({where_})",
                format::duration(entry.duration_us)
            ));
        }
        let raw_resp = self.api.entry_response(entry.id).await?;
        Ok(format!(
            "{} {} · {} · TTFB {} · total {}\n({where_})\n\n{}",
            entry.http_version.as_deref().unwrap_or("HTTP"),
            entry.status.map_or("-".into(), |s| s.to_string()),
            format::size(Some(entry.resp_size)),
            format::duration(entry.ttfb_us),
            format::duration(entry.duration_us),
            format::message(&raw_resp, max_body_chars.unwrap_or(DEFAULT_BODY_CHARS)),
        ))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for NosyMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("nosy", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}
