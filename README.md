# mcp-shell

A minimal MCP server that runs commands **in the user's environment** (on the
host, outside any sandbox). Every command must be approved by **the human at
the server's terminal** — the one channel a compromised MCP client cannot
touch.

> **Why a daemon, not a stdio server.** A stdio MCP server is a *child
> process* of the client: it inherits the client's environment, privileges,
> and **sandbox** — and it gets no controlling terminal, so terminal
> confirmation could never be shown. mcp-shell is therefore an HTTP daemon
> only: you run it yourself, outside the sandbox, and point OpenCode at it
> as a *remote* MCP server. Commands execute with the daemon's authority,
> and every confirmation appears on the terminal you launched it from.

## Confirmation: one mode, the terminal

Every `run_command` call prompts on the server's controlling terminal
(`/dev/tty`) and blocks until you answer. An explicit `y` runs the command;
anything else — `n`, Enter, EOF, a missing terminal — refuses it
(fail-closed). The prompt and your answer never pass through the MCP client,
so a compromised client cannot approve on your behalf, and cannot forge,
hide, or auto-answer the confirmation.

There is one confirmation channel by design: the terminal. Alternatives
were ruled out on security and reliability grounds — an in-client form
(elicitation) depends on the client to display it faithfully and can hang
the call when it doesn't, and client-side permission rules are only as
trustworthy as the client itself. The terminal is out-of-band: it works
regardless of who the client is.

> When a call appears to hang in OpenCode, it is waiting for you at the
> daemon's terminal. The tool's description tells the model this too.

## Per-session authorization (default on)

Confirming every single command is the WHAT gate. Session authorization adds
a WHO gate: the **first `tools/call` of each MCP session** triggers one
terminal prompt — `session <id>, first request <cmd>… Authorize?` Approving
authorizes that session for the daemon's lifetime; refusing it means every
command from that session is refused. The authorization is dropped when the
client disconnects (session DELETE). Disable with `MCP_SHELL_SESSION_AUTH=0`.

## Quick start

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python test_mcp_shell.py   # 16 checks, ~10s, all must pass
```

## Daemon usage (the sandbox-evasion setup)

Start the daemon **outside the sandbox**, in your own terminal:

```sh
cd /path/to/mcp-shell
MCP_SHELL_DEBUG=1 .venv/bin/python mcp_shell.py
```

(The `daemon` argument is optional — the daemon is the only mode.)

It prints its endpoint and auth setup once:

```text
mcp-shell daemon listening on http://127.0.0.1:7801/mcp
  auth: session auth at this terminal
  confirmation: every command prompts at this terminal
  debug off (MCP_SHELL_DEBUG=1 to enable)
  Set MCP_SHELL_SESSION_AUTH=0 to disable session auth; MCP_SHELL_PORT for the port.
```

HTTP logging (access lines, session chatter) stays quiet by default so the
approval prompts are readable; `MCP_SHELL_DEBUG=1` enables both the debug
lines and the HTTP logs. A prompt looks like this on your terminal:

```text
────────────────────────────────────────────────────────────────────────
⚠ mcp-shell — command approval requested

    $ git status

Approve? [y/N]
```

with the command bolded, long commands wrapped (never truncated), and an
immediate `✓ approved — running` / `✗ refused` verdict after your keystroke,
plus a dim `↳ finished: exit 0` line when the command completes. Colors are
used when the terminal supports them and disabled with `NO_COLOR` or
`TERM=dumb`.

Register it in OpenCode as a **remote** server. With the CLI:

```sh
opencode mcp add mcp-shell --url http://127.0.0.1:7801/mcp
```

Or by hand in `opencode.jsonc` (global: `~/.config/opencode/opencode.jsonc`);
**disabled by default** so OpenCode only connects when you explicitly opt in
(flip to `false`, remove the field, or toggle interactively with `/mcps`):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "mcp-shell": {
        "type": "remote",
        "url": "http://127.0.0.1:7801/mcp",
        "oauth": false,
        "disabled": true
      }
    }
  }
}
```

Check with `opencode mcp list` (should show `connected` once enabled). When
the model calls `run_command`: the first call per session prompts
`Authorize this session?` at the daemon terminal; every call then prompts
`Approve?` with the exact command. Answer `y` at the terminal to proceed.

## Tool: `run_command`

| Parameter | Type | Description |
|-----------|------|-------------|
| `argv` | `list[str]` | Command as an argv array, e.g. `["git", "status"]`. No shell involved. |
| `cwd` | `str?` | Optional working directory (absolute path). Defaults to the server's cwd. |

Returns `command` (shell-quoted display), `exit_code`, `stdout`, `stderr`,
`timed_out`, `truncated`.

## Security model

- **Terminal confirmation, fail-closed.** The command runs only on an
  explicit `y` at the server's terminal. Every other outcome — decline,
  EOF, missing `/dev/tty`, client disconnect — refuses.
- **Out-of-band by construction.** Prompt and answer live on the terminal,
  not in MCP. A compromised client sees the call but cannot approve it,
  hide the prompt, or answer it.
- **Session authorization.** Each session must be
  authorized once at the terminal before any of its commands even reach
  per-command confirmation. WHO and WHAT are separate gates.
- **No shell by construction.** Commands are argv arrays; no string
  interpolation, so `;`, `&&`, backticks, and `$()` are literal text.
  Test: `["echo", "a;rm -rf /"]` prints `a;rm -rf /`.
- **Deny list is defense-in-depth, not the boundary.** `argv[0]`'s basename
  is checked against a short list (`sudo`, `su`, `doas`, `pkexec`,
  `sudoedit`, `nmap`, `masscan`, `hydra`, `john`, `hashcat`). The
  confirmation gate is the actual boundary. Edit `_DENIED_EXECUTABLES` to
  taste.
- **Timeout with process-group kill.** Over-timeout commands are SIGKILLed
  as a group (`start_new_session=True`), so children cannot outlive the
  call. `exit_code` is `-9`, `timed_out` is `true`.
- **Output cap.** Each of stdout and stderr is capped (default 1 MiB per
  stream) with head+tail truncation, so long runs don't blow up model
  context.
- **Your environment by default.** Commands inherit the server's full
  environment — your user account's exports, since you start the server from
  your shell. Server-internal `MCP_SHELL_*` configuration is always stripped
  so it never leaks into commands. Set
  `MCP_SHELL_ENV=NAME,NAME,...` to restrict commands to an allowlist
  instead.
- **Loopback + rebinding protection.** The daemon binds to `127.0.0.1`
  only and validates Host/Origin against DNS-rebinding attacks.
- **Debug logging.** `MCP_SHELL_DEBUG=1` prints each decision (calls
  received, session prompts and outcomes, approvals, executions) and
  enables HTTP access logs; by default both stay quiet so prompts are
  readable — enough to diagnose any "nothing happened".

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SHELL_SESSION_AUTH` | on | Require one terminal authorization per MCP session. `0` disables it. |
| `MCP_SHELL_PORT` | `7801` | Daemon HTTP port. |
| `MCP_SHELL_TIMEOUT` | `120` | Seconds before a command is killed (group SIGKILL). |
| `MCP_SHELL_OUTPUT_CAP` | `1048576` | Max bytes per stream (stdout / stderr separately) before truncation. |
| `MCP_SHELL_ENV` | unset (full inheritance) | Comma-separated env var names: restrict commands to this allowlist. Unset = inherit your full environment (with `MCP_SHELL_*` stripped). |
| `MCP_SHELL_DEBUG` | `0` | `1` enables per-decision debug lines **and** HTTP logs; default keeps the terminal quiet for prompts. |

## Tests

`test_mcp_shell.py` (16 checks, ~10s) drives the daemon over real
streamable-HTTP MCP connections against a real PTY (via `login_tty`, so the
daemon genuinely owns a controlling terminal):

- usage error for an unknown run mode
- daemon: session authorize/approve, fresh-session re-authorization,
  command refusal, session refusal, credential-less HTTP reachability,
  no-tty fail-closed (session auth on and off), deny-list, no-shell literal
  metacharacters, missing executable, bad cwd, cwd, environment inheritance
  + `MCP_SHELL_*` stripping, `MCP_SHELL_ENV` restriction, timeout kill

```sh
.venv/bin/python test_mcp_shell.py
```

## Notes

- Official Python SDK (`mcp` 2.x): the high-level server class is
  `MCPServer`. This server uses no elicitation — the terminal is the only
  confirmation channel.
- POSIX only: `/dev/tty`, `os.login_tty`, `TIOCGWINSZ`, and process-group
  signals are Unix APIs; there is no Windows or macOS support and the test
  suite runs on Linux.
- For manual debugging of any MCP server, use the official
  **MCP Inspector**: `npx @modelcontextprotocol/inspector`.
- OpenCode's normalized tool name is `mcp-shell_run_command` for permission
  rules; `codemode: false` on the server entry exposes the tool directly.
- Running host commands is inherently risky; this server exists to make
  that *auditable and gated*, not safe. Read every prompt carefully —
  especially what a compromised client could do with your `y`.
