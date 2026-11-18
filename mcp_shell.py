#!/usr/bin/env python3
"""mcp-shell: run commands on the host, confirmed at the terminal.

A streamable HTTP MCP daemon on 127.0.0.1. Start it OUTSIDE any sandbox, in
your own terminal; the sandboxed client (e.g. OpenCode) connects over HTTP
as a remote MCP server and commands execute with the daemon's (unsandboxed)
authority — this is the sandbox-evasion point.

There is exactly one run mode (this daemon) and one confirmation mode: the
terminal.

  Every command must be approved by the human at this server's controlling
  terminal (/dev/tty) with an explicit y. Fail-closed: EOF, a missing
  terminal, or any other answer refuses the command. The confirmation never
  passes through the MCP client, so a compromised client cannot approve.

  Each MCP session is additionally authorized ONCE at the terminal, at its
  first tools/call (MCP_SHELL_SESSION_AUTH=0 disables it).

Commands are argv lists run without a shell: no string interpolation, no
pipes, no shell syntax, so metacharacters in arguments are literal text.

Security notes:

  - Per-session authorization (default on): a session's FIRST tools/call
    triggers ONE prompt at the daemon's terminal; approving authorizes that
    session for the daemon's lifetime (cleaned up when the session ends).
    Session auth decides WHO may ask; per-command confirmation decides WHAT
    runs. This terminal gate is the only auth layer: a process that finds
    the endpoint still cannot run anything without your 'y'.
  - The server binds to 127.0.0.1 only, with DNS-rebinding protection.
  - Debug logging (MCP_SHELL_DEBUG=1) prints each decision to the terminal:
    calls received, session prompts, approvals, executions.
  - A daemon started by a sandboxed client is just as sandboxed as the
    client: the point is that YOU start it outside the sandbox.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from typing import Annotated

import anyio
from anyio import open_process

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import ToolAnnotations
from pydantic import Field

__version__ = "0.2.0"

# ---------------------------------------------------------------------------
# Configuration (operator-controlled environment variables only)
# ---------------------------------------------------------------------------


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


EXEC_TIMEOUT_S: float = _env_float("MCP_SHELL_TIMEOUT", 120.0)
OUTPUT_CAP_BYTES: int = _env_int("MCP_SHELL_OUTPUT_CAP", 1024 * 1024)
DAEMON_PORT: int = _env_int("MCP_SHELL_PORT", 7801)
# Per-session authorization at the daemon's terminal: each MCP session must
# be authorized once with a 'y' before its commands reach per-command
# confirmation. Default ON; MCP_SHELL_SESSION_AUTH=0 disables it.
_SESSION_AUTH_ENV: str = os.environ.get("MCP_SHELL_SESSION_AUTH", "").strip().lower()
SESSION_AUTH: bool = _SESSION_AUTH_ENV not in ("0", "false", "no", "off")
# Debug logging to stderr (the daemon terminal). Enabled with MCP_SHELL_DEBUG=1.
DEBUG: bool = (os.environ.get("MCP_SHELL_DEBUG", "0").strip().lower() in ("1", "true", "yes", "on"))


def _debug(msg: str) -> None:
    """Timestamped debug line to stderr; helps diagnose 'nothing happened'."""
    if DEBUG:
        print(f"[mcp-shell {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# Environment passed to commands:
#  - MCP_SHELL_ENV unset (default): inherit this server's full environment —
#    the user account's exports, since you start the server from your shell.
#    Server-internal MCP_SHELL_* configuration is never passed to commands.
#  - MCP_SHELL_ENV=NAME,NAME,...: pass ONLY the named variables (minimal env).
_raw_env_list = os.environ.get("MCP_SHELL_ENV", "").strip()
ENV_RESTRICT: frozenset[str] | None = (
    frozenset(name.strip() for name in re.split(r"[,\s]+", _raw_env_list) if name.strip())
    if _raw_env_list
    else None
)

def _argv_to_string(argv: list[str]) -> str:
    """Render argv as a shell-quoted string for display in confirmations."""
    return " ".join(shlex.quote(a) for a in argv)


def _build_env() -> dict[str, str]:
    """The environment commands run with.

    Default: this server's full inherited environment (the user account's
    exports). MCP_SHELL_ENV restricts it to an allowlist. Server-internal
    MCP_SHELL_* configuration is always stripped so settings never leak
    into commands.
    """
    if ENV_RESTRICT is not None:
        env = {
            name: value
            for name in ENV_RESTRICT
            if (value := os.environ.get(name)) is not None
        }
    else:
        env = dict(os.environ)
    for name in list(env):
        if name.startswith("MCP_SHELL_"):
            del env[name]
    return env


# ---------------------------------------------------------------------------
# Terminal confirmation (the only confirmation channel)
# ---------------------------------------------------------------------------

# ANSI styles for the prompts. _styled disables them automatically when the
# terminal doesn't support color or NO_COLOR is set (https://no-color.org).
_DIM = "2"
_BOLD = "1"
_YELLOW = "33"
_RED = "31"
_GREEN = "32"
_RESET = "\033[0m"


def _styled(fd: int, style: str, text: str) -> str:
    """`text` wrapped in an ANSI style when the terminal supports it."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM", "") == "dumb":
        return text
    if not os.isatty(fd):
        return text
    return f"\033[{style}m{text}{_RESET}"


def _term_width(fd: int) -> int:
    """Terminal column count; 80 when it cannot be determined."""
    try:
        import fcntl
        import struct
        import termios

        packed = fcntl.ioctl(fd, termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0))
        cols = struct.unpack("HHHH", packed)[1]
        if cols >= 20:
            return cols
    except OSError:
        pass
    return 80


def _wrap(text: str, indent: str, width: int) -> str:
    """Wrap long text (a command to approve) so it stays fully visible.

    Never truncates: everything you are about to approve must be on screen,
    even if it takes many lines.
    """
    import textwrap

    return "\n".join(
        textwrap.wrap(
            text,
            width=max(20, width - len(indent)),
            initial_indent=indent,
            subsequent_indent=indent,
            break_long_words=True,
            break_on_hyphens=False,
        )
    )


def _tty_note(msg: str) -> None:
    """Print a short dim status line to the terminal. Best effort, never fatal."""
    try:
        fd = os.open("/dev/tty", os.O_WRONLY)
    except OSError:
        return
    try:
        os.write(fd, (_styled(fd, _DIM, msg) + "\n").encode("utf-8"))
    except OSError:
        pass
    finally:
        os.close(fd)


def _tty_confirm(
    header: str,
    body: list[tuple[str, str]],
    question: str,
    approved_note: str,
    refused_note: str,
) -> str:
    """Render a clear approval prompt at the terminal and read the answer.

    Fail-closed: any error, EOF, or a missing terminal raises OSError, which
    callers translate into a refusal. Reads from /dev/tty (the terminal the
    daemon was started in), never from stdin/stdout.
    """
    # Raw fd I/O: buffered text wrappers ("r+"/"rb+") on a tty can raise
    # UnsupportedOperation (not seekable) — and /dev/tty always pairs reads
    # and writes on the same fd, so one O_RDWR fd is all we need.
    tty_fd = os.open("/dev/tty", os.O_RDWR)
    try:
        width = _term_width(tty_fd)
        sep = _styled(tty_fd, _DIM, "─" * min(width, 72))
        head = _styled(tty_fd, f"{_BOLD};{_YELLOW}", f"⚠ mcp-shell — {header}")
        out = ["", sep, head, ""]
        for kind, text in body:
            if kind == "code":
                # The thing you are approving: wrapped, indented, bold.
                for line in _wrap(text, "    ", width).split("\n"):
                    out.append(_styled(tty_fd, _BOLD, line))
            elif kind == "dim":
                out.append(_styled(tty_fd, _DIM, text))
            else:
                out.append(text)
        out.append("")
        out.append(_styled(tty_fd, _BOLD, question) + " [y/N] ")
        os.write(tty_fd, "\n".join(out).encode("utf-8"))
        # Read one line, byte by byte, until \n or EOF.
        answer = b""
        while True:
            b = os.read(tty_fd, 1)
            if not b or b == b"\n":
                break
            answer += b
        verdict = answer.strip().lower().decode("utf-8", errors="replace")
        if verdict in ("y", "yes"):
            note = _styled(tty_fd, f"{_BOLD};{_GREEN}", f"✓ {approved_note}")
        else:
            note = _styled(tty_fd, f"{_BOLD};{_RED}", f"✗ {refused_note}")
        os.write(tty_fd, (note + "\n").encode("utf-8"))
    finally:
        os.close(tty_fd)
    return verdict


# Serializes terminal prompts AND moves the blocking read off the event
# loop: two concurrent calls must not interleave prompts on one terminal,
# and a blocked os.read must not freeze the whole server.
_prompt_lock = asyncio.Lock()


async def _prompt_at_terminal(
    header: str,
    body: list[tuple[str, str]],
    question: str,
    approved_note: str,
    refused_note: str,
) -> str:
    """Ask a yes/no question at the terminal without blocking the event loop."""
    async with _prompt_lock:
        return await asyncio.to_thread(_tty_confirm, header, body, question, approved_note, refused_note)


# Sessions the human has authorized at the terminal (daemon lifetime).
_authorized_sessions: set[str] = set()
# Sessions currently waiting at an authorization prompt. Prevents the
# check-then-act race where two concurrent first calls from the same session
# both prompt — the user's single 'y' would approve one prompt and the other
# would steal the next keystroke (e.g. the per-command approval's).
_authorizing_locks: dict[str, asyncio.Lock] = {}


def _session_gate_lock(session_id: str) -> asyncio.Lock:
    """The per-session authorization gate lock (created on first use)."""
    lock = _authorizing_locks.get(session_id)
    if lock is None:
        lock = _authorizing_locks.setdefault(session_id, asyncio.Lock())
    return lock


def _forget_session(session_id: str) -> None:
    """Drop a session's authorization and gate lock (on session teardown)."""
    _authorized_sessions.discard(session_id)
    _authorizing_locks.pop(session_id, None)


async def _authorize_session(session_id: str, first_request: str) -> bool:
    """Ask the human at the terminal to authorize a new MCP session.

    Returns True only on an explicit y. Everything else — including a missing
    terminal (OSError) — refuses. This is a separate gate from per-command
    confirmation: it decides WHO may ask; per-command confirmation still
    decides WHAT runs.

    The caller must hold the session's gate lock while calling, so only ONE
    authorization prompt per session can ever be pending.
    """
    try:
        answer = await _prompt_at_terminal(
            header="session authorization requested",
            body=[
                ("plain", f"    session:  {session_id[:8]}"),
                ("code", first_request),
                ("dim", "Each command still requires separate approval."),
            ],
            question="Authorize this session?",
            approved_note="session authorized",
            refused_note="session refused",
        )
    except OSError as e:
        _debug(f"session auth prompt failed: {e}")
        return False
    if answer not in ("y", "yes"):
        _debug(f"session {session_id[:8]}… refused at terminal")
        return False
    _debug(f"session {session_id[:8]}… authorized at terminal")
    _authorized_sessions.add(session_id)
    return True


async def _confirm_tty(argv: list[str]) -> list[str]:
    """Prompt the human at the terminal to approve the command. Fail-closed.

    Everything other than an explicit y/Y refuses the command.
    """
    display = _argv_to_string(argv)
    _debug(f"tty confirmation requested for: {display}")
    try:
        answer = await _prompt_at_terminal(
            header="command approval requested",
            body=[("code", "$ " + display)],
            question="Approve?",
            approved_note="approved — running",
            refused_note="refused — command not run",
        )
    except OSError as e:
        raise ToolError(
            f"Command not run: cannot open the terminal for confirmation ({e.errno}: {e.strerror}). "
            "The server must be started from an interactive terminal."
        ) from e
    _debug(f"tty answer for {display!r}: {answer!r}")
    if answer not in ("y", "yes"):
        raise ToolError("Command not run: user did not approve at the terminal.")
    return argv


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


async def _run(argv: list[str], cwd: str | None = None) -> dict[str, object]:
    """Execute argv without a shell, with timeout and output capping."""
    display = _argv_to_string(argv)
    env = _build_env()

    # Validate cwd BEFORE spawning: a bad cwd otherwise surfaces as a
    # misleading "executable not found" (the exec fails after the chdir).
    if cwd is not None and not os.path.isdir(cwd):
        raise ToolError(f"Command not started: cwd {cwd!r} is not a directory.")

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    truncated = False
    timed_out = False

    # New session (process group) so a timeout can kill the whole tree.
    # anyio's open_process() is an async factory: await it to get the Process.
    try:
        proc = await open_process(
            argv,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            cwd=cwd,
        )
    except FileNotFoundError:
        raise ToolError(f"Command not started: executable {argv[0]!r} not found.")
    async with proc:
        try:
            with anyio.move_on_after(EXEC_TIMEOUT_S):
                # Drain stdout and stderr concurrently so a full pipe can't deadlock.
                async with anyio.create_task_group() as tg:
                    tg.start_soon(_drain, proc.stdout, stdout_chunks)
                    tg.start_soon(_drain, proc.stderr, stderr_chunks)
                    await proc.wait()
        finally:
            if proc.returncode is None:
                # Timeout (or cancellation): kill the whole process group.
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                with anyio.CancelScope(shield=True):
                    await proc.wait()

    stdout = b"".join(stdout_chunks)
    stderr = b"".join(stderr_chunks)

    def cap(data: bytes, label: str) -> tuple[bytes, bool]:
        nonlocal truncated
        if len(data) <= OUTPUT_CAP_BYTES:
            return data, False
        truncated = True
        half = OUTPUT_CAP_BYTES // 2
        marker = f"\n... [{label} truncated at {OUTPUT_CAP_BYTES} bytes] ...\n".encode()
        return data[:half] + marker + data[-half:], True

    stdout, _ = cap(stdout, "stdout")
    stderr, _ = cap(stderr, "stderr")

    return {
        "command": display,
        "exit_code": proc.returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "timed_out": timed_out,
        "truncated": truncated,
    }


async def _drain(stream: anyio.abc.ByteReceiveStream | None, chunks: list[bytes]) -> None:
    """Read a process stream to EOF, collecting chunks (raw bytes)."""
    if stream is None:
        return
    try:
        while True:
            chunk = await stream.receive()
            chunks.append(chunk)
    except anyio.EndOfStream:
        pass
    except anyio.ClosedResourceError:
        pass


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

server = MCPServer(
    name="mcp-shell",
    title="Shell (terminal-confirmed)",
    version=__version__,
    description="Runs commands in the user's environment. Every command requires explicit user confirmation.",
    instructions=(
        "This server runs commands on the user's host, outside any sandbox. "
        "Commands are argv arrays run without a shell. "
        "Every invocation must be confirmed by the human at this server's terminal; "
        "the confirmation happens outside the MCP client and cannot be answered by it. "
        "A call that appears to hang is waiting for the human to approve at the terminal."
    ),
)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@server.tool(
    name="run_command",
    title="Run a shell command (requires terminal confirmation)",
    description=(
        "Run a command in the user's environment (on the host, outside any sandbox). "
        "The command is an argv array executed without a shell: no pipes, redirection, "
        "or shell syntax are possible; use argv[0] as the executable and each argument "
        "as its own list element. Every call must be approved by the user at the "
        "server's terminal before it runs; a rejection, or a failure to obtain "
        "confirmation, means the command is not executed — the call blocks until the "
        "human answers. The working directory starts at the server process's directory. "
        "Output is capped; long-running commands are killed after a timeout."
    ),
    annotations=ToolAnnotations(
        title="Run a shell command (requires terminal confirmation)",
        destructive_hint=True,
        idempotent_hint=False,
        open_world_hint=True,
        read_only_hint=False,
    ),
)
async def run_command(
    argv: Annotated[
        list[str],
        Field(
            description=(
                "The command to run as an argv array, e.g. ['git', 'status'] or "
                "['bash', '-c', 'echo hi']. argv[0] is resolved against PATH."
            ),
            min_length=1,
        ),
    ],
    cwd: Annotated[
        str | None,
        Field(description="Optional working directory (absolute path). Defaults to the server's cwd.", default=None),
    ],
    ctx: Context,
) -> dict[str, object]:
    _debug(f"run_command called: argv={argv!r} cwd={cwd!r}")

    if not argv or not all(isinstance(a, str) and a for a in argv):
        raise ToolError("argv must be a non-empty list of non-empty strings.")

    # Per-session authorization (daemon mode): the session's first tools/call
    # triggers ONE terminal prompt. Decided here, inside the tool, because the
    # SDK exposes the request headers via ctx.headers — HTTP middleware never
    # needs to parse request bodies (which starves the transport and hangs).
    if SESSION_AUTH:
        headers = ctx.headers or {}
        session_id = (headers.get("mcp-session-id") or "").strip() or None
        if session_id is None:
            # A transport without session ids (or a stripped header): there is
            # no per-session identity to authorize. Fail closed.
            raise ToolError(
                "Command not run: this connection has no session identity, so it "
                "cannot be authorized. Connect over the daemon's HTTP transport."
            )
        if session_id not in _authorized_sessions:
            _debug(f"session {session_id[:8]}… not yet authorized; prompting at terminal")
            # Hold the session's gate across check + prompt: a concurrent
            # first call from the same session waits here instead of issuing
            # a duplicate prompt, and re-checks after the lock is released.
            gate = _session_gate_lock(session_id)
            async with gate:
                if session_id in _authorized_sessions:
                    approved = True
                else:
                    approved = await _authorize_session(session_id, _argv_to_string(argv))
            if not approved:
                raise ToolError("Command not run: session not authorized at the terminal.")

    argv_to_run = await _confirm_tty(argv)

    _debug(f"executing: {_argv_to_string(argv_to_run)}")
    result = await _run(argv_to_run, cwd)
    _debug(f"execution finished: exit_code={result['exit_code']} timed_out={result['timed_out']}")
    if result["timed_out"]:
        note = f"↳ finished: exit {result['exit_code']} (timed out after {EXEC_TIMEOUT_S:g}s)"
    else:
        note = f"↳ finished: exit {result['exit_code']}"
    _tty_note(str(note))
    return result


# ---------------------------------------------------------------------------
# Entrypoints
# ---------------------------------------------------------------------------


def main() -> None:
    # The daemon is the only run mode; an optional `daemon` argument is
    # accepted for explicitness. Anything else is a usage error.
    run_mode = sys.argv[1] if len(sys.argv) > 1 else "daemon"
    if run_mode != "daemon":
        print(f"usage: {sys.argv[0]} [daemon]", file=sys.stderr)
        sys.exit(2)

    import logging

    import uvicorn

    # Quiet by default so approval prompts stay readable: the SDK and
    # uvicorn both log HTTP session chatter and tool-failure notices at
    # INFO on the root logger. WARNING keeps real errors (and exception
    # tracebacks) visible. MCP_SHELL_DEBUG=1 restores the chatter.
    if not DEBUG:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    else:
        logging.basicConfig(level=logging.DEBUG)

    # Session teardown middleware: forget a session's authorization when the
    # client disconnects (DELETE), so the authorized set cannot grow forever.
    # Header-only — this middleware never reads request bodies (consuming the
    # body in middleware starves the MCP transport downstream and hangs).
    # Per-session authorization itself lives in the tool, via the request
    # headers (see run_command); the terminal is the only auth gate.
    from starlette.middleware.base import BaseHTTPMiddleware

    class SessionTeardownMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if SESSION_AUTH and request.method == "DELETE":
                session_id = request.headers.get("mcp-session-id")
                if session_id:
                    _forget_session(session_id)
            return await call_next(request)

    app = server.streamable_http_app(
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        ),
    )
    app.add_middleware(SessionTeardownMiddleware)

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=DAEMON_PORT,
        # Access logs are debug-only: they sandwich the approval prompts
        # and make them hard to read.
        log_level="debug" if DEBUG else "error",
    )
    uvicorn_server = uvicorn.Server(config)
    auth_desc = "session auth at this terminal" if SESSION_AUTH else "SESSION AUTH DISABLED"
    debug_desc = "debug ON" if DEBUG else "debug off (MCP_SHELL_DEBUG=1 to enable)"
    print(
        f"mcp-shell daemon listening on http://127.0.0.1:{DAEMON_PORT}/mcp\n"
        f"  auth: {auth_desc}\n"
        f"  confirmation: every command prompts at this terminal\n"
        f"  {debug_desc}\n"
        f"  Set MCP_SHELL_SESSION_AUTH=0 to disable session auth; MCP_SHELL_PORT for the port.",
        file=sys.stderr,
    )
    uvicorn_server.run()


if __name__ == "__main__":
    main()
