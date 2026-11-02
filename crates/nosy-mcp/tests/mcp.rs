//! End-to-end: the real `nosy-mcp` binary over stdio, driven like an MCP client would.

use std::{process::Stdio, time::Duration};

use nosy_server::{App, Cli};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::{Child, ChildStdin, ChildStdout, Command},
};
use tokio_util::sync::CancellationToken;

/// Upstream that reflects the request line and Authorization header in a JSON body.
async fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let line = head.lines().next().unwrap_or_default().to_owned();
                let auth = head
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("authorization: ")
                            .or_else(|| l.strip_prefix("Authorization: "))
                    })
                    .unwrap_or("-")
                    .to_owned();
                let body =
                    json!({ "line": line, "auth": auth, "secret": "tok_live_123" }).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

struct Mcp {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    async fn spawn(api: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nosy-mcp"))
            .args(["--api", api])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            _child: child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    async fn notify(&mut self, method: &str) {
        let msg = json!({ "jsonrpc": "2.0", "method": method });
        self.stdin
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.stdin
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(Duration::from_secs(20), self.stdout.read_line(&mut line))
                .await
                .expect("MCP response timed out")
                .unwrap();
            assert!(n > 0, "MCP server closed stdout");
            // Every stdout line must be a JSON-RPC message (no stray logging).
            let v: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("non-JSON on stdout: {line:?} ({e})"));
            if v["id"] == json!(id) {
                assert!(v.get("error").is_none(), "{method} failed: {v}");
                return v["result"].clone();
            }
        }
    }

    /// Returns (text, is_error).
    async fn call(&mut self, tool: &str, args: Value) -> (String, bool) {
        let r = self
            .request("tools/call", json!({ "name": tool, "arguments": args }))
            .await;
        let text = r["content"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["text"].as_str())
            .collect::<String>();
        (text, r["isError"].as_bool().unwrap_or(false))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_tools_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let app = App::new(&Cli {
        proxy: "127.0.0.1:0".parse().unwrap(),
        ui: "127.0.0.1:0".parse().unwrap(),
        project: None,
        data_dir: Some(dir.path().to_path_buf()),
        verify_upstream: false,
        max_capture_mb: 16,
        open: false,
    })
    .await
    .unwrap();
    let ui = format!("http://{}", app.state.info.ui_addr);
    let proxy = format!("http://{}", app.state.info.proxy_addr);
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    tokio::spawn(app.run(token));

    // Capture one flow through the proxy.
    let port = upstream().await;
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&proxy).unwrap())
        .build()
        .unwrap();
    client
        .get(format!("http://localhost:{port}/api/users/1"))
        .header("Authorization", "Bearer alice")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let api = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut flow_id = 0;
    for _ in 0..100 {
        let flows: Vec<Value> = api
            .get(format!("{ui}/api/flows"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(f) = flows
            .first()
            .filter(|f| !f["status"].is_null() && f["method"] == "GET")
        {
            flow_id = f["id"].as_i64().unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(flow_id > 0, "flow captured");

    // Handshake.
    let mut mcp = Mcp::spawn(&ui).await;
    let init = mcp
        .request(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } }),
        )
        .await;
    assert_eq!(init["serverInfo"]["name"], "nosy");
    assert!(
        init["instructions"]
            .as_str()
            .unwrap()
            .contains("list_flows")
    );
    mcp.notify("notifications/initialized").await;

    // Tool catalogue with annotations.
    let tools = mcp.request("tools/list", json!({})).await;
    let tools = tools["tools"].as_array().unwrap();
    let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "annotate_flow",
            "decode",
            "get_flow",
            "list_flows",
            "list_hosts",
            "replay_flow",
            "search_flows",
            "send_request"
        ]
    );
    let send = tools.iter().find(|t| t["name"] == "send_request").unwrap();
    assert_eq!(send["annotations"]["openWorldHint"], true);
    assert_eq!(send["inputSchema"]["required"], json!(["raw_request"]));
    let get = tools.iter().find(|t| t["name"] == "get_flow").unwrap();
    assert_eq!(get["annotations"]["readOnlyHint"], true);

    // Reading.
    let (hosts, _) = mcp.call("list_hosts", json!({})).await;
    assert_eq!(hosts, "localhost (1)");
    let (list, _) = mcp
        .call(
            "list_flows",
            json!({ "host": "localhost", "status_classes": [2] }),
        )
        .await;
    assert!(
        list.starts_with(&format!(
            "#{flow_id} GET 200 http://localhost:{port}/api/users/1"
        )),
        "{list}"
    );
    let (flow, _) = mcp.call("get_flow", json!({ "id": flow_id })).await;
    assert!(
        flow.contains("=== REQUEST ===\nGET /api/users/1 HTTP/1.1"),
        "{flow}"
    );
    assert!(flow.contains("Authorization: Bearer alice"), "{flow}");
    assert!(flow.contains("\"secret\":\"tok_live_123\""), "{flow}");
    let (hits, _) = mcp
        .call("search_flows", json!({ "query": "TOK_LIVE" }))
        .await;
    assert!(
        hits.contains("response.body: ") && hits.contains("tok_live_123"),
        "{hits}"
    );

    // Replay with edits (IDOR-style): the upstream reflects what it received.
    let (replayed, err) = mcp
        .call(
            "replay_flow",
            json!({ "id": flow_id, "path": "/api/users/2", "set_headers": { "Authorization": "Bearer mallory" } }),
        )
        .await;
    assert!(!err, "{replayed}");
    assert!(replayed.starts_with("HTTP/1.1 200"), "{replayed}");
    assert!(
        replayed.contains("GET /api/users/2 HTTP/1.1") && replayed.contains("Bearer mallory"),
        "{replayed}"
    );
    assert!(replayed.contains("Repeater tab \"MCP\""), "{replayed}");

    // Raw send to a known host works; unknown hosts are refused by default.
    let raw =
        format!("POST /echo HTTP/1.1\nHost: localhost:{port}\nContent-Type: text/plain\n\nhello");
    let (sent, err) = mcp
        .call("send_request", json!({ "raw_request": raw, "tls": false }))
        .await;
    assert!(!err && sent.contains("POST /echo HTTP/1.1"), "{sent}");
    let (refused, err) = mcp
        .call(
            "send_request",
            json!({ "raw_request": "GET / HTTP/1.1\nHost: evil.example\n\n" }),
        )
        .await;
    assert!(
        err && refused.contains("not in the proxy history"),
        "{refused}"
    );

    // The agent's requests are visible to the user in a single Repeater tab.
    let tabs: Vec<Value> = api
        .get(format!("{ui}/api/repeater/tabs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mcp_tabs: Vec<_> = tabs.iter().filter(|t| t["name"] == "MCP").collect();
    assert_eq!(mcp_tabs.len(), 1);
    let history: Vec<Value> = api
        .get(format!(
            "{ui}/api/repeater/tabs/{}/history",
            mcp_tabs[0]["id"]
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(history.len(), 2);

    // Local transforms.
    let (dec, _) = mcp
        .call("decode", json!({ "input": "YWRtaW46c2VjcmV0" }))
        .await;
    assert!(
        dec.contains("b64-dec") && dec.ends_with("admin:secret"),
        "{dec}"
    );
    let (hash, _) = mcp
        .call(
            "decode",
            json!({ "input": "abc", "operations": ["sha256"] }),
        )
        .await;
    assert!(
        hash.ends_with("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "{hash}"
    );
    let (bad, err) = mcp
        .call("decode", json!({ "input": "x", "operations": ["rot13"] }))
        .await;
    assert!(err && bad.contains("unknown operation"), "{bad}");

    // Annotations show up in the UI's data.
    let (ann, err) = mcp
        .call(
            "annotate_flow",
            json!({ "id": flow_id, "highlight": "red", "note": "IDOR: users/2" }),
        )
        .await;
    assert!(
        !err && ann.contains("[highlight:red]") && ann.contains("[note: IDOR: users/2]"),
        "{ann}"
    );
    let f: Value = api
        .get(format!("{ui}/api/flows/{flow_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (
            f["summary"]["highlight"].as_str(),
            f["summary"]["note"].as_str()
        ),
        (Some("red"), Some("IDOR: users/2"))
    );
}

#[tokio::test]
async fn mcp_reports_unreachable_backend() {
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut mcp = Mcp::spawn(&format!("http://127.0.0.1:{port}")).await;
    mcp.request(
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }),
    )
    .await;
    mcp.notify("notifications/initialized").await;
    let (text, err) = mcp.call("list_hosts", json!({})).await;
    assert!(err && text.contains("not reachable"), "{text}");
}
