#!/usr/bin/env python3
"""End-to-end smoke test for mcp-shell.

Spawns the daemon over a real PTY (login_tty gives it a genuine controlling
terminal, like a human launch) and drives it over real streamable-HTTP MCP
connections:

  session authorization, per-command approval, command refusal, session
  refusal, credential-less HTTP reachability, no-tty fail-closed (with
  session auth on and off), no-shell literal metacharacters,
  missing executable, bad cwd, cwd, environment inheritance and stripping,
  MCP_SHELL_ENV restriction, timeout kill, usage error on an unknown run
  mode.

Run:  .venv/bin/python test_mcp_shell.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVER = ROOT / "mcp_shell.py"
TOOL_TIMEOUT = 10  # client read timeout per tool call
PROMPT_TIMEOUT = 5  # how long a terminal prompt may take to appear


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


passed: list[str] = []
failed: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (passed if ok else failed).append(name)
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail[:160]}" if detail else ""), flush=True)


async def call_tool_daemon_raw(
    port: int,
    argv: list[str],
    *,
    cwd: str | None = None,
) -> tuple[bool, str]:
    """Call run_command over HTTP against a daemon with no controlling terminal.

    A plain-pipe daemon has no /dev/tty, so confirmations must fail closed
    with a clear error instead of hanging.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    url = f"http://127.0.0.1:{port}/mcp"

    async def call() -> tuple[bool, str]:
        import httpx2 as httpx

        http_client = httpx.AsyncClient(timeout=TOOL_TIMEOUT)
        async with streamable_http_client(url, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "run_command",
                    {"argv": argv, **({"cwd": cwd} if cwd else {})},
                    read_timeout_seconds=TOOL_TIMEOUT,
                )
                text = "\n".join(
                    c.model_dump().get("text", "") for c in result.content if c.model_dump().get("type") == "text"
                )
                return not result.is_error, text

    return await asyncio.wait_for(call(), timeout=TOOL_TIMEOUT)


# ---------------------------------------------------------------------------
# daemon harness (PTY + HTTP)
# ---------------------------------------------------------------------------


class Daemon:
    """The daemon under test: process on a PTY, HTTP endpoint.

    ONE reader thread buffers all PTY output into a shared buffer; wait_for
    scans the buffer instead of reading the fd, so cancelled waiters can
    never steal another test's prompt bytes (fd reads race; buffer scans
    don't).
    """

    def __init__(self, port: int, env_extra: dict[str, str] | None = None):
        import pty

        self.port = port
        self.env_extra = dict(env_extra or {})
        self.master, self.slave = pty.openpty()
        self.proc: asyncio.subprocess.Process | None = None
        self.log: list[str] = []
        self._buf: bytes = b""
        self._stop = threading.Event()
        self._reader: threading.Thread | None = None

    def _read_pty(self) -> None:
        while not self._stop.is_set():
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            if not chunk:
                return
            self._buf += chunk
            self.log.append(chunk.decode("utf-8", errors="replace"))

    async def start(self) -> None:
        # Inherit the test runner's environment (like a user launching from
        # their shell), then apply server config and per-test overrides.
        env = {
            **os.environ,
            "MCP_SHELL_PORT": str(self.port),
            **self.env_extra,
        }
        # login_tty wrapper: gives the daemon its own session with the PTY as
        # controlling terminal, so /dev/tty works (like a real interactive launch).
        # The slave must arrive as fd 0 (stdin) — close_fds closes everything else.
        wrapper = (
            "import os,sys;"
            "os.login_tty(0);"
            f"os.execve(sys.executable, [sys.executable, {str(SERVER)!r}, 'daemon'], dict(os.environ))"
        )
        self.proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            wrapper,
            stdin=self.slave,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
        self._reader = threading.Thread(target=self._read_pty, daemon=True)
        self._reader.start()

    def buffer_len(self) -> int:
        """Current length of the PTY output buffer; a scan start offset."""
        return len(self._buf)

    def wait_for(self, marker: str, timeout: float = PROMPT_TIMEOUT, start: int = 0) -> bool:
        """Block until `marker` appears in PTY output appended after `start`."""
        marker_b = marker.encode()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if marker_b in self._buf[start:]:
                return True
            time.sleep(0.05)
        return marker_b in self._buf[start:]

    def feed_answer(self, answer: str) -> None:
        """Write a confirmation answer into the PTY master."""
        os.write(self.master, (answer + "\n").encode())

    async def stop(self) -> None:
        self._stop.set()
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        if self._reader and self._reader.is_alive():
            self._reader.join(timeout=1)
        os.close(self.master)
        os.close(self.slave)


async def daemon_start_and_wait(daemon: Daemon, timeout: float = 10.0) -> None:
    """Start the daemon and wait until its port accepts TCP connections."""
    await daemon.start()
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", daemon.port)
        except OSError:
            await asyncio.sleep(0.15)
            continue
        writer.close()
        await writer.wait_closed()
        return
    raise TimeoutError(f"daemon did not accept connections; log:\n{''.join(daemon.log)}")


def _task_result(task: "asyncio.Task[tuple[bool, str]]", label: str) -> tuple[bool, str]:
    """Extract a completed task's result; failures become test messages."""
    try:
        return task.result()
    except Exception as e:  # noqa: BLE001 — harness must not crash the suite
        return False, f"{label}: {type(e).__name__}: {str(e)[:120]}"


async def daemon_call_tool(
    daemon: Daemon,
    argv: list[str],
    *,
    cwd: str | None = None,
    answer: str | None = "y",
    session_answer: str | None = "y",
    label: str = "",
) -> tuple[bool, str]:
    """Call run_command over HTTP against a running daemon.

    Handles the prompt sequence: session-auth prompt first (once per
    session), then the per-command prompt. Feeds each answer only after its
    prompt appeared — like a human reading then typing. Prompt detection
    scans the daemon's PTY buffer from this call's start offset, so prompts
    from earlier tests are never re-matched.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    url = f"http://127.0.0.1:{daemon.port}/mcp"

    async def call() -> tuple[bool, str]:
        import httpx2 as httpx

        http_client = httpx.AsyncClient(timeout=TOOL_TIMEOUT)
        async with streamable_http_client(url, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "run_command",
                    {"argv": argv, **({"cwd": cwd} if cwd else {})},
                    read_timeout_seconds=TOOL_TIMEOUT,
                )
                text = "\n".join(
                    c.model_dump().get("text", "") for c in result.content if c.model_dump().get("type") == "text"
                )
                return not result.is_error, text

    task = asyncio.create_task(call())
    pos = daemon.buffer_len()

    async def wait_prompt_or_call(marker: str) -> str:
        """Race the prompt wait against the call: 'prompt', 'call', or 'none'."""
        prompt_wait = asyncio.create_task(asyncio.to_thread(daemon.wait_for, marker, PROMPT_TIMEOUT, pos))
        done, _ = await asyncio.wait({prompt_wait, task}, return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            prompt_wait.cancel()
            return "call"
        return "prompt" if prompt_wait.result() else "none"

    # Session-auth prompt (first tools/call of this session only).
    outcome = await wait_prompt_or_call("Authorize this session")
    if outcome == "call":
        # Call finished before any session prompt: session auth off, or a
        # fast failure (missing terminal).
        return _task_result(task, label)
    if outcome == "none":
        task.cancel()
        return False, f"{label}: session prompt never appeared"
    if session_answer is None:
        task.cancel()
        return False, f"{label}: session prompt appeared but no answer configured"
    daemon.feed_answer(session_answer)

    if answer is not None:
        outcome = await wait_prompt_or_call("Approve?")
        if outcome == "call":
            return _task_result(task, label)
        if outcome == "none":
            task.cancel()
            return False, f"{label}: command prompt never appeared"
        daemon.feed_answer(answer)
    try:
        return await task
    except Exception as e:  # noqa: BLE001 — harness must not crash the suite
        return False, f"{label}: {type(e).__name__}: {str(e)[:120]}"


async def daemon_raw_http(daemon: Daemon) -> tuple[int, str]:
    """Probe the endpoint without the MCP client (transport-level check)."""
    import httpx2 as httpx

    async with httpx.AsyncClient(timeout=TOOL_TIMEOUT) as client:
        resp = await client.post(
            f"http://127.0.0.1:{daemon.port}/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        return resp.status_code, resp.text


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


async def main() -> None:
    # --- usage error on a bad run mode --------------------------------------
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(SERVER),
        "stdio",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "MCP_SHELL_PORT": str(_free_port())},
    )
    out = (await proc.stdout.read()).decode("utf-8", errors="replace")
    await proc.wait()
    check(
        "bad-run-mode: usage error for an unknown run mode",
        proc.returncode == 2 and "usage:" in out,
        out.strip()[:160],
    )

    # --- daemon over HTTP with tty confirmation -----------------------------
    port = _free_port()
    daemon = Daemon(port)
    await daemon_start_and_wait(daemon)
    try:
        ok, text = await daemon_call_tool(daemon, ["echo", "via-http"], label="first")
        check(
            "daemon/tty-approve: session authorized, command runs",
            ok and "via-http" in text,
            text[:200],
        )

        ok, text = await daemon_call_tool(daemon, ["echo", "second"], label="second")
        check(
            "daemon/tty-second: fresh session re-authorized, command runs",
            ok and "second" in text,
            text[:200],
        )

        ok, text = await daemon_call_tool(daemon, ["echo", "should-not-run"], answer="n", label="refuse")
        check(
            "daemon/tty-refuse: command refused at terminal",
            (not ok) and "not run" in text.lower(),
            text[:200],
        )

        ok, text = await daemon_call_tool(
            daemon, ["echo", "no-session"], session_answer="n", answer=None, label="session-refuse"
        )
        check(
            "daemon/session-refuse: refused session means no command",
            (not ok) and "not authorized" in text.lower(),
            text[:200],
        )
    finally:
        await daemon.stop()

    # --- daemon: a plain HTTP probe still reaches the endpoint ---------------
    # (The terminal is the only auth gate; transport-level reachability is
    # expected — the session gate inside the tool refuses unauthorized use.)
    port = _free_port()
    daemon = Daemon(port)
    await daemon_start_and_wait(daemon)
    try:
        status, _ = await daemon_raw_http(daemon)
        check(
            "daemon/raw-http: endpoint reachable without credentials",
            status in (200, 406),
            f"status={status}",
        )
    finally:
        await daemon.stop()

    # --- daemon without a controlling terminal: fail closed ------------------
    port = _free_port()
    env = {
        "MCP_SHELL_PORT": str(port),
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
    }
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(SERVER),
        "daemon",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )
    try:
        deadline = asyncio.get_event_loop().time() + 10
        while asyncio.get_event_loop().time() < deadline:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
            except OSError:
                await asyncio.sleep(0.15)
                continue
            writer.close()
            await writer.wait_closed()
            break
        else:
            raise TimeoutError("no-tty daemon never listened")

        # With session auth ON (default): the session prompt itself cannot be
        # shown, so the call must fail closed fast.
        ok, text = await call_tool_daemon_raw(port, ["echo", "no-tty"])
        check(
            "daemon/no-tty: session-auth prompt fails closed with clear error",
            (not ok) and "not authorized" in text.lower(),
            text[:200],
        )
    finally:
        proc.terminate()
        await proc.wait()

    # --- daemon without a tty, session auth OFF: per-command prompt fails ----
    port = _free_port()
    env = {
        "MCP_SHELL_PORT": str(port),
        "MCP_SHELL_SESSION_AUTH": "0",
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
    }
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(SERVER),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )
    try:
        deadline = asyncio.get_event_loop().time() + 10
        while asyncio.get_event_loop().time() < deadline:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
            except OSError:
                await asyncio.sleep(0.15)
                continue
            writer.close()
            await writer.wait_closed()
            break
        else:
            raise TimeoutError("no-tty daemon (auth off) never listened")

        ok, text = await call_tool_daemon_raw(port, ["echo", "no-tty"])
        check(
            "daemon/no-tty-auth-off: per-command confirmation fails closed with clear error",
            (not ok) and "terminal" in text.lower(),
            text[:200],
        )
    finally:
        proc.terminate()
        await proc.wait()

    # --- daemon: execution checks -------------------------------------------
    port = _free_port()
    daemon = Daemon(port)
    await daemon_start_and_wait(daemon)
    try:
        ok, text = await daemon_call_tool(daemon, ["echo", "a;rm -rf /"], label="no-shell")
        check(
            "daemon/no-shell: metacharacters are literal",
            ok and "a;rm -rf /" in text,
            text[:200],
        )

        ok, text = await daemon_call_tool(daemon, ["this-executable-does-not-exist-xyz"], label="missing")
        check(
            "daemon/missing-executable: clear error after approval",
            (not ok) and "not found" in text,
            text[:200],
        )

        ok, text = await daemon_call_tool(daemon, ["pwd"], cwd="/definitely/not/a/dir", label="bad-cwd")
        check(
            "daemon/bad-cwd: clear cwd error, not a misleading executable error",
            (not ok) and "cwd" in text.lower() and "not found" not in text,
            text[:200],
        )

        ok, text = await daemon_call_tool(daemon, ["pwd"], cwd="/tmp", label="cwd")
        check(
            "daemon/cwd: working directory is honored",
            ok and "/tmp" in text,
            text[:200],
        )
    finally:
        await daemon.stop()

    # --- daemon: environment inheritance -----------------------------------
    port = _free_port()
    marker = f"marker-{os.getpid()}-{_free_port()}"
    daemon = Daemon(port, env_extra={"MCS_TEST_MARKER": marker})
    await daemon_start_and_wait(daemon)
    try:
        # Default: full inherited env, but MCP_SHELL_* stripped.
        ok, text = await daemon_call_tool(
            daemon,
            ["bash", "-c", "echo $MCS_TEST_MARKER; echo PORT=[$MCP_SHELL_PORT]"],
            label="env",
        )
        check(
            "daemon/env: inherits user env, strips MCP_SHELL_*",
            ok and marker in text and "PORT=[]" in text,
            text[:200],
        )

        # Restriction: MCP_SHELL_ENV allowlist passes only the named vars.
        daemon2 = Daemon(
            _free_port(),
            env_extra={"MCP_SHELL_ENV": "PATH,MCS_TEST_MARKER", "MCS_TEST_MARKER": marker},
        )
        await daemon_start_and_wait(daemon2)
        try:
            ok, text = await daemon_call_tool(
                daemon2,
                ["bash", "-c", "echo HOME=[$HOME]; echo MARKER=$MCS_TEST_MARKER"],
                label="env-restrict",
            )
            check(
                "daemon/env-restrict: MCP_SHELL_ENV allowlist passes only named vars",
                ok and "HOME=[]" in text and marker in text,
                text[:200],
            )
        finally:
            await daemon2.stop()
    finally:
        await daemon.stop()

    # --- daemon: timeout kill with a short MCP_SHELL_TIMEOUT ----------------
    port = _free_port()
    daemon = Daemon(port, env_extra={"MCP_SHELL_TIMEOUT": "2"})
    await daemon_start_and_wait(daemon)
    try:
        ok, text = await daemon_call_tool(daemon, ["sleep", "10"], label="timeout")
        check(
            "daemon/timeout: exceeded MCP_SHELL_TIMEOUT, killed with -9",
            ok and '"timed_out": true' in text and '"exit_code": -9' in text,
            text[:200],
        )
    finally:
        await daemon.stop()

    print()
    print(f"passed: {len(passed)}  failed: {len(failed)}")
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
