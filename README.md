# nosy-mcp

[Model Context Protocol](https://modelcontextprotocol.io) server for [Nosy](https://github.com/nosyproxy/nosy),
the intercepting HTTP(S) proxy. It runs on stdio and talks to a running `nosy` through its local
API, so the agent's activity is visible in the UI: requests land in the **MCP** Repeater tab,
highlights and notes appear in the history instantly.

## Usage

```sh
nosy                                   # start the proxy + UI first
claude mcp add nosy -- nosy-mcp        # Claude Code (use the full path if not on PATH)
```

Other clients (Claude Desktop, Cursor, …): command `nosy-mcp`, no args.
Options: `--api http://127.0.0.1:1337` (env `NOSY_API`), `--allow-any-host`.

| tool | what it does |
|---|---|
| `list_hosts` | hosts in the history with request counts |
| `list_flows` | history with filters (substring, host glob, methods, status classes, hide static), paginated |
| `get_flow` | full request/response with decompressed bodies (truncated to `max_body_chars`) |
| `search_flows` | case-insensitive search across heads and decompressed bodies |
| `send_request` | raw HTTP request via the Repeater (h1 byte-exact or h2) |
| `replay_flow` | re-send a captured flow with method/path/header/body edits |
| `decode` | Base64/URL/HTML/hex/unicode/JWT, gzip/deflate/brotli/zstd, MD5/SHA; auto-detects nested encodings |
| `annotate_flow` | highlight and/or note a flow |

Read-only tools are annotated `readOnlyHint`; `send_request`/`replay_flow` are `openWorldHint` so
clients ask before running them. `send_request` only targets hosts already in the history unless
`--allow-any-host` is given.

## Building

Depends on `nosy-model` / `nosy-codec` from the [core](https://github.com/nosyproxy/nosy) (and
`nosy-server` for the e2e test) as git dependencies pinned in `Cargo.lock`.

```sh
make build      # target/release/nosy-mcp
make check      # fmt, clippy -D warnings, tests (incl. end-to-end against an in-process nosy)
cargo update -p nosy-model -p nosy-codec -p nosy-server   # pick up the core's latest main
```

To work on the core and the MCP server together, check the core out next to this repo and run
`make link`: it writes a git-ignored `.cargo/config.toml` that patches the git dependency with
`../nosy` (`CORE=/path/to/nosy` to override). `make unlink` switches back.
