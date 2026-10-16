# AGENTS.md

Single-file MCP server (`mcp_shell.py`) plus an end-to-end test suite
(`test_mcp_shell.py`). One tool (`run_command`): a streamable-HTTP daemon on
127.0.0.1 that runs commands without a shell (argv arrays), each approved by
the human at the daemon's terminal (`/dev/tty`), fail-closed. The daemon is
the only run mode — `mcp_shell.py stdio` is a usage error by design.

## Commands

- Setup: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
- Full verification: `.venv/bin/python test_mcp_shell.py` (~10-15s, exit 1 on
  any failure). This is the only gate — no pytest, no lint, no CI. Run it
  after every change.
- Manual daemon for poking (pick a non-default port so you don't collide
  with a real instance): `MCP_SHELL_DEBUG=1 MCP_SHELL_PORT=7901 .venv/bin/python mcp_shell.py`

## Test-suite quirks (read before touching tests)

- The suite is end-to-end: every check spawns the real daemon over a PTY
  (`os.login_tty`) and drives it over real streamable-HTTP MCP. No mocks,
  no unit tests.
- The `daemon/no-tty*` checks require the test runner to have **no
  controlling terminal**. Agent shells (pipes) work; from an interactive
  terminal the spawned daemon inherits that TTY, its prompt blocks, and the
  suite hangs at `daemon/no-tty`. If it hangs there, run it from a non-TTY
  context — don't "fix" the suite.
- Timeouts are deliberately tight (`PROMPT_TIMEOUT=5`, `TOOL_TIMEOUT=10`): a
  healthy step takes seconds. Never raise them to make a hang pass.
- PTY harness invariant: one reader thread buffers all PTY output and
  `wait_for(marker, start=pos)` scans that buffer by offset. Never read the
  PTY fd in waiters — concurrent fd reads steal prompt bytes (this bug
  already happened once). Feed answers only after the prompt appeared.
- `daemon_call_tool(...)` opens a NEW MCP session per call, so every call
  sees a session-auth prompt followed by the command prompt. Use its
  `answer=` / `session_answer=` parameters; don't hand-roll the sequence.
- Tests pick free ports; a daemon already listening on 7801 does not
  collide with the suite.

## MCP SDK gotchas (mcp 2.x; pinned `>=2.3,<3`, verified on 2.3.0)

- The high-level server is `MCPServer` (`mcp.server.mcpserver`), not `FastMCP`.
- Session identity inside a tool: `ctx.headers["mcp-session-id"]`. Plain
  `ctx.session_id` / `ctx.connection` do NOT exist on the mcpserver
  `Context` (AttributeError — it is a different class than the low-level one).
- `open_process()` is an async factory: `async with await open_process(...)`.
- `/dev/tty` needs raw fd I/O (`os.open` + byte-wise `os.read`);
  `open("/dev/tty", "r+")` raises `io.UnsupportedOperation` (ttys are not
  seekable).
- HTTP middleware must NEVER read request bodies — the transport downstream
  starves and the POST hangs forever (symptom: "request received, nothing
  happens"). The teardown middleware stays header-only.
- Terminal prompts must run off the event loop (`asyncio.to_thread`) and be
  serialized (`_prompt_lock`), or a blocked `os.read` freezes the server.

## Conventions

- Commit messages carry the pseudo-header `AI-assisted: yes, <agent> + <model>`.
- Docs, comments, and test names describe the current design only —
  no historical narratives ("previously we had X", "formerly", "no longer").
- POSIX-only (Linux tested): `/dev/tty`, `os.login_tty`, `TIOCGWINSZ`,
  process-group signals.
