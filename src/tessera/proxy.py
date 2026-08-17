"""The transparent MCP interception proxy — the chokepoint.

The agent thinks it is talking to its tools; it is actually talking to Tessera,
which forwards to the real upstream MCP server(s) and, in between, attaches
labels, enforces the flow rule, sanitizes outputs, and writes the ledger.
Shipping as a proxy is the deliberate adoption choice: it slots in front of an
existing MCP server without rewriting the agent.

This module splits the logic in two:

  * :class:`MCPInterceptor` — pure, transport-agnostic message handling. Given
    a parsed JSON-RPC request and a callable to reach upstream, it returns the
    response to hand back to the client. This is what the tests drive.
  * :class:`StdioProxy` — wires the interceptor between a client (stdin/stdout)
    and an upstream MCP server launched as a subprocess, using MCP's
    newline-delimited JSON-RPC stdio framing.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from tessera.ledger import open_ledger
from tessera.policy import Decision, PolicyEngine, PolicyResult, Strictness
from tessera.session import Session

#: An upstream transport: take a JSON-RPC request dict, return the response dict.
UpstreamCall = Callable[[dict], dict]
#: A human-in-the-loop approver: shown the decision + explanation, returns
#: True to approve the escalated action.
HitlCallback = Callable[[PolicyResult, str], bool]


def _error_result(id_: Any, message: str) -> dict:
    """A tools/call result marked as an error the agent can read in-band.

    Refusing is not secret, so we surface *why* — but never the blocked data.
    """
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "result": {
            "content": [{"type": "text", "text": f"[Tessera blocked this action] {message}"}],
            "isError": True,
        },
    }


@dataclass
class MCPInterceptor:
    """Transport-agnostic MCP request handler enforcing Tessera's policy."""

    session: Session
    upstream: UpstreamCall
    hitl: Optional[HitlCallback] = None

    def handle_request(self, message: dict) -> Optional[dict]:
        """Handle one client→server JSON-RPC message.

        Returns the response dict to send back to the client, or None for a
        notification that expects no response.
        """
        method = message.get("method")

        if method == "tools/call":
            return self._handle_tools_call(message)

        # Everything else passes through unchanged...
        if message.get("id") is None:
            # A notification (no id): forward and expect nothing back.
            self.upstream(message)
            return None

        response = self.upstream(message)

        # ...but we snoop tools/list to auto-classify the tools' blast radius.
        if method == "tools/list":
            self._register_from_list(response)
        return response

    def _register_from_list(self, response: dict) -> None:
        result = response.get("result")
        if isinstance(result, Mapping):
            tools = result.get("tools")
            if isinstance(tools, list):
                self.session.register_tools_from_schema(tools)

    def _handle_tools_call(self, message: dict) -> dict:
        params = message.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments", {})
        id_ = message.get("id")

        result = self.session.authorize_call(tool, args)

        if result.decision is Decision.BLOCK:
            return _error_result(id_, result.reason)

        if result.decision is Decision.ESCALATE:
            approved = self._escalate(result)
            if not approved:
                return _error_result(
                    id_, "human approval was denied or unavailable; " + result.reason
                )

        # If a declassifier canonicalized any arguments, forward the cleaned
        # values, not the raw (possibly-smuggled) originals -- defense in depth.
        if result.cleaned_arguments:
            merged = {**args, **result.cleaned_arguments}
            message = {**message, "params": {**params, "arguments": merged}}

        # Allowed (or human-approved): forward to upstream, then label and
        # sanitize the result on the way back.
        response = self.upstream(message)
        self._ingest_response(tool, response)
        return response

    def _escalate(self, result: PolicyResult) -> bool:
        if self.hitl is None:
            return False
        return bool(self.hitl(result, self.session.explain(result)))

    def _ingest_response(self, tool: str, response: dict) -> None:
        """Label, taint and sanitize **everything** the server sent back.

        This ingests the whole payload object rather than picking
        ``content[].text`` out of it. Extracting a single block type meant every
        other shape the MCP spec allows — ``structuredContent``, the ``text`` of
        an embedded ``resource``, a ``resource_link``'s ``description``, a
        bare-string ``content`` — reached the agent with **no label, no taint and
        no ledger entry**. That is an *ingestion* gap rather than a propagation
        one, so no strictness setting compensates for it: ``paranoid`` cannot
        taint on data it was never shown, and an incident review sees a
        ``decision`` with no ``label`` before it.

        Passing the whole object is also what keeps this closed as the spec
        grows — a field we have never heard of is walked by default instead of
        being silently dropped. ``sanitize_value`` preserves shape, so the
        sanitized copy is still a valid MCP result, and *every* text leaf in it
        is defanged rather than just the first block (the old write-back
        concatenated all text blocks and stored the result in block 0, leaving
        any later block carrying its original URL).

        The JSON-RPC ``error`` object is ingested on the same footing: a
        protocol error routinely echoes its input (``"Unknown tool: <name>"``),
        which is attacker-reachable text arriving in the agent's context.
        """
        for key in ("result", "error"):
            payload = response.get(key)
            if not isinstance(payload, Mapping):
                continue
            labeled = self.session.ingest_result(tool, payload)
            # Hand the agent the sanitized copy, never the original.
            if isinstance(labeled.content, Mapping):
                response[key] = dict(labeled.content)


# --------------------------------------------------------------------------
# Stdio transport
# --------------------------------------------------------------------------


class _SubprocessUpstream:
    """Speaks MCP newline-delimited JSON-RPC to an upstream server subprocess.

    Synchronous request/response: write the request line, then read upstream
    lines until the matching response id arrives, forwarding any interleaved
    server notifications to ``on_notification``.
    """

    def __init__(self, proc: subprocess.Popen, on_notification: Callable[[dict], None]):
        self._proc = proc
        self._on_notification = on_notification
        self._lock = threading.Lock()

    def __call__(self, message: dict) -> dict:
        assert self._proc.stdin and self._proc.stdout
        with self._lock:
            self._proc.stdin.write(json.dumps(message) + "\n")
            self._proc.stdin.flush()
            if message.get("id") is None:
                return {}  # notification: nothing to read back
            target = message.get("id")
            while True:
                line = self._proc.stdout.readline()
                if not line:
                    raise RuntimeError("upstream MCP server closed the connection")
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if msg.get("id") == target:
                    return msg
                # A server-initiated request/notification: pass it through.
                self._on_notification(msg)


@dataclass
class StdioProxy:
    """Run Tessera as a stdio MCP proxy in front of an upstream server.

    Example
    -------
    Launch the proxy in front of an upstream server command::

        StdioProxy(
            upstream_cmd=["python", "-m", "my_mcp_server"],
            strictness=Strictness.BALANCED,
        ).run()
    """

    upstream_cmd: list[str]
    strictness: Strictness = Strictness.BALANCED
    ledger_path: Optional[str] = None
    allowlist: frozenset[str] = frozenset()
    hitl: Optional[HitlCallback] = None
    session_id: str = "stdio"
    #: Optional key to HMAC-chain the ledger with, making tampering detectable
    #: by a verifier that holds the key (see :func:`tessera.verify_ledger`).
    ledger_key: Optional[bytes] = None

    def _build_session(self) -> Session:
        ledger = open_ledger(
            self.ledger_path, session_id=self.session_id, hmac_key=self.ledger_key
        )
        return Session(
            session_id=self.session_id,
            policy=PolicyEngine(strictness=self.strictness),
            ledger=ledger,
            allowlist=self.allowlist,
        )

    def run(self) -> None:  # pragma: no cover - exercised via integration only
        proc = subprocess.Popen(
            self.upstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        out = sys.stdout

        def emit(msg: dict) -> None:
            out.write(json.dumps(msg) + "\n")
            out.flush()

        upstream = _SubprocessUpstream(proc, on_notification=emit)
        interceptor = MCPInterceptor(self._build_session(), upstream, hitl=self.hitl)

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                try:
                    response = interceptor.handle_request(message)
                except Exception as exc:  # noqa: BLE001 - see below
                    # An unhandled error in the guard used to escape this loop
                    # and take the whole session (and the upstream server) down
                    # with it. Refuse the single call instead: the agent gets a
                    # readable in-band error and the proxy keeps serving.
                    #
                    # This stays fail-closed. The exception means we cannot
                    # vouch for the call, so we do not return a result the
                    # agent can act on — and if it was raised on the way *back*
                    # (a ledger write that could not complete, say), refusing
                    # also means the unaudited result never reaches the agent.
                    sys.stderr.write(f"[tessera] {type(exc).__name__}: {exc}\n")
                    sys.stderr.flush()
                    # A notification carries no id, and JSON-RPC has no reply to
                    # send for one — dropping it is the only correct answer.
                    response = (
                        None
                        if message.get("id") is None
                        else _error_result(
                            message.get("id"),
                            f"internal error in the guard ({type(exc).__name__}); "
                            "the call was refused",
                        )
                    )
                if response is not None:
                    emit(response)
        finally:
            proc.terminate()
