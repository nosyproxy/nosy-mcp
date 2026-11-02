//! Thin typed client for the running Nosy instance's HTTP API.

use std::time::Duration;

use nosy_model::{
    FlowDetail, FlowPatch, FlowSummary, HostCount, NewRepeaterTab, RepeaterEntry, RepeaterTab,
    ReplayTemplate, SearchResult, SendRequest,
};
use reqwest::{Method, RequestBuilder};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: String,
}

pub type ApiResult<T> = Result<T, String>;

impl Api {
    pub fn new(base: &str) -> Self {
        let http = reqwest::Client::builder()
            .no_proxy() // never route our own API calls through a proxy
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(180))
            .build()
            .expect("reqwest client");
        Self {
            http,
            base: format!("{}/api", base.trim_end_matches('/')),
        }
    }

    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        self.http.request(method, format!("{}{path}", self.base))
    }

    async fn exec(&self, rb: RequestBuilder) -> ApiResult<reqwest::Response> {
        let resp = rb.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                format!(
                    "Nosy is not reachable at {} — start it with `nosy` (or point `nosy-mcp --api` at it). ({e})",
                    self.base.trim_end_matches("/api")
                )
            } else {
                format!("request to Nosy failed: {e}")
            }
        })?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status();
        let msg = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
            .unwrap_or_else(|| status.to_string());
        Err(if status == reqwest::StatusCode::NOT_FOUND {
            format!("not found: {msg}")
        } else {
            msg
        })
    }

    async fn json<T: DeserializeOwned>(&self, rb: RequestBuilder) -> ApiResult<T> {
        self.exec(rb)
            .await?
            .json()
            .await
            .map_err(|e| format!("bad response from Nosy: {e}"))
    }

    async fn bytes(&self, rb: RequestBuilder) -> ApiResult<Vec<u8>> {
        Ok(self
            .exec(rb)
            .await?
            .bytes()
            .await
            .map_err(|e| e.to_string())?
            .to_vec())
    }

    pub async fn flows<Q: Serialize + ?Sized>(&self, query: &Q) -> ApiResult<Vec<FlowSummary>> {
        self.json(self.req(Method::GET, "/flows").query(query))
            .await
    }

    pub async fn flow(&self, id: i64) -> ApiResult<FlowDetail> {
        self.json(self.req(Method::GET, &format!("/flows/{id}")))
            .await
    }

    /// Full raw message with decoded body.
    pub async fn flow_message(&self, id: i64, response: bool) -> ApiResult<Vec<u8>> {
        let part = if response { "response" } else { "request" };
        self.bytes(
            self.req(Method::GET, &format!("/flows/{id}/{part}"))
                .query(&[("decode", "true")]),
        )
        .await
    }

    pub async fn replay_template(&self, id: i64) -> ApiResult<ReplayTemplate> {
        self.json(self.req(Method::GET, &format!("/flows/{id}/replay")))
            .await
    }

    pub async fn patch_flow(&self, id: i64, patch: &FlowPatch) -> ApiResult<FlowSummary> {
        self.json(self.req(Method::PATCH, &format!("/flows/{id}")).json(patch))
            .await
    }

    pub async fn hosts(&self) -> ApiResult<Vec<HostCount>> {
        self.json(self.req(Method::GET, "/hosts")).await
    }

    pub async fn search<Q: Serialize + ?Sized>(&self, query: &Q) -> ApiResult<SearchResult> {
        self.json(self.req(Method::GET, "/search").query(query))
            .await
    }

    pub async fn tabs(&self) -> ApiResult<Vec<RepeaterTab>> {
        self.json(self.req(Method::GET, "/repeater/tabs")).await
    }

    pub async fn create_tab(&self, tab: &NewRepeaterTab) -> ApiResult<RepeaterTab> {
        self.json(self.req(Method::POST, "/repeater/tabs").json(tab))
            .await
    }

    pub async fn send(&self, tab_id: i64, req: &SendRequest) -> ApiResult<RepeaterEntry> {
        self.json(
            self.req(Method::POST, &format!("/repeater/tabs/{tab_id}/send"))
                .json(req),
        )
        .await
    }

    pub async fn entry_response(&self, entry_id: i64) -> ApiResult<Vec<u8>> {
        self.bytes(
            self.req(
                Method::GET,
                &format!("/repeater/history/{entry_id}/response"),
            )
            .query(&[("decode", "true")]),
        )
        .await
    }
}
