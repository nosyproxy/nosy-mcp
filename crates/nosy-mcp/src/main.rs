use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Model Context Protocol server on stdio for AI agents (Claude Code, Claude Desktop, Cursor…).
/// It talks to an already running `nosy` through its local API.
///
/// Example: claude mcp add nosy -- nosy-mcp
#[derive(Debug, Parser)]
#[command(name = "nosy-mcp", version)]
struct Args {
    /// URL of the running Nosy web UI / API.
    #[arg(long, default_value = "http://127.0.0.1:1337", env = "NOSY_API")]
    api: String,
    /// Let `send_request` contact any host (by default only hosts already in the history).
    #[arg(long)]
    allow_any_host: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Logs go to stderr: stdout carries the protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();
    nosy_mcp::serve_stdio(nosy_mcp::McpConfig {
        api: args.api,
        allow_any_host: args.allow_any_host,
    })
    .await
}
