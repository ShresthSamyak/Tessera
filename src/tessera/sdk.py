"""The easy front door — wrap any agent's tools in one line.

The full machinery (Session, PolicyEngine, classification, ledger) is powerful
but verbose. Most users want: *take my tools, make every call go through
Tessera's flow rule, with sane defaults.* This module is that.

    from tessera import protect

    safe = protect([send_email, read_doc, fetch_url], policy="balanced")
    # `safe` are the same callables, but every call is now gated: untrusted data
    # can't drive an exfiltration-capable or irreversible tool. Drop them into
    # your agent (LangChain, the OpenAI SDK, a hand-rolled loop) unchanged.

Or decorate the tools you define:

    from tessera import tool

    @tool(reversibility="irreversible", exfiltration_capable=True)
    def send_email(to: str, body: str) -> str: ...

This is the programmatic twin of the transparent MCP proxy (`tessera run`): same
flow rule, same labels, same ledger — applied in-process instead of on the wire.
Nothing here weakens the guarantees; it's a thin, friendly layer over
:class:`~tessera.session.Session`.
"""

from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from tessera.capabilities import Capability, CapabilityEngine
from tessera.classification import Reversibility, operator_profile
from tessera.declassify import Declassifier
from tessera.labels import Origin, TrustLevel
from tessera.ledger import Ledger
from tessera.policy import Decision, PolicyEngine, PolicyResult, Strictness
from tessera.session import Session

#: Friendly policy names -> strictness (the dynamism<->containment knob).
POLICIES = {
    "paranoid": Strictness.PARANOID,
    "balanced": Strictness.BALANCED,
    "permissive": Strictness.PERMISSIVE,
}

_REVERSIBILITY = {
    "read_only": Reversibility.READ_ONLY,
    "reversible": Reversibility.REVERSIBLE,
    "irreversible": Reversibility.IRREVERSIBLE,
}


class Blocked(Exception):
    """Raised when Tessera blocks a tool call (with ``on_block="raise"``)."""

    def __init__(self, result: PolicyResult):
        self.result = result
        super().__init__(result.reason)


class BlockedResult(str):
    """What a blocked call returns under ``on_block="error"`` — a real ``str``.

    Returning a string is the right default for a tool loop: the message goes
    back to the model, which can read it and adapt, exactly as it would read any
    other tool output. But a plain string makes a refusal and a success
    indistinguishable except by prefix, so a caller that logs the value, ignores
    it, or passes it onward gets no signal that the action did not happen.

    This subclasses ``str`` so every one of those loops keeps working unchanged,
    while ``isinstance(value, BlockedResult)`` gives code that *does* care an
    exact test — without forcing exception handling on code that doesn't.
    :attr:`decision` carries the full :class:`~tessera.policy.PolicyResult`, so
    a caller can inspect the blast radius and provenance rather than parse prose.

    The refusal is real either way: the wrapped function never runs.
    """

    __slots__ = ("decision",)

    def __new__(cls, decision: PolicyResult) -> "BlockedResult":
        self = super().__new__(cls, f"[blocked by Tessera] {decision.reason}")
        self.decision = decision
        return self


def tool(
    fn: Callable | None = None,
    *,
    name: str | None = None,
    reversibility: str | None = None,
    exfiltration_capable: bool | None = None,
    origin: Origin | None = None,
    declassifiers: dict[str, Declassifier] | None = None,
):
    """Annotate a tool with blast-radius / origin hints Tessera should trust.

    Usable bare (``@tool``) or with hints (``@tool(reversibility="irreversible",
    exfiltration_capable=True)``). Hints are *operator declarations* — they
    override the name-based auto-classification when the function is wrapped by
    :func:`protect` / :class:`Guard`.
    """

    def deco(f: Callable) -> Callable:
        f._tessera = {  # type: ignore[attr-defined]
            "name": name or f.__name__,
            "reversibility": reversibility,
            "exfiltration_capable": exfiltration_capable,
            "origin": origin,
            "declassifiers": declassifiers or {},
        }
        return f

    return deco(fn) if fn is not None else deco


@dataclass
class Guard:
    """Wraps tool callables so every call passes Tessera's gates.

    Holds one :class:`Session` (one agent run = one Guard). Use :func:`protect`
    for the common case; construct a Guard directly for finer control.
    """

    session: Session
    on_block: str = "error"  # "error" -> return a message; "raise" -> raise Blocked

    @classmethod
    def create(
        cls,
        policy: str = "balanced",
        *,
        allow_hosts: Iterable[str] = (),
        capabilities: bool = False,
        on_block: str = "error",
        session_id: str = "guard",
    ) -> "Guard":
        if policy not in POLICIES:
            raise ValueError(f"unknown policy {policy!r}; choose from {sorted(POLICIES)}")
        engine = CapabilityEngine() if capabilities else None
        session = Session(
            session_id=session_id,
            policy=PolicyEngine(strictness=POLICIES[policy]),
            allowlist=frozenset(h.lower() for h in allow_hosts),
            capability_engine=engine,
            require_capabilities=capabilities,
        )
        return cls(session=session, on_block=on_block)

    # -- wrapping tools -----------------------------------------------------

    def wrap(self, fn: Callable, *, name: str | None = None) -> Callable:
        """Return a gated version of ``fn`` (same signature; calls are checked)."""
        meta = getattr(fn, "_tessera", {})
        tool_name = name or meta.get("name") or getattr(fn, "__name__", "tool")
        self._register(tool_name, meta)
        sig = _signature(fn)

        @functools.wraps(fn)
        def gated(*args: Any, **kwargs: Any) -> Any:
            argmap = _argmap(sig, args, kwargs)
            decision = self.session.authorize_call(tool_name, argmap)
            if decision.decision is not Decision.ALLOW:
                if self.on_block == "raise":
                    raise Blocked(decision)
                return BlockedResult(decision)
            try:
                if decision.cleaned_arguments:
                    argmap.update(decision.cleaned_arguments)
                    result = fn(**argmap)
                else:
                    result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - labelled, then re-raised
                # A tool's *failure* text reaches the agent just as its success
                # value does, and it is free-form by construction: errors
                # routinely echo their input ("no such user: <argument>"). The
                # success path was labelled and the failure path was not, which
                # is backwards — the free-form one is the one worth tracking.
                #
                # The original exception is re-raised unchanged: replacing it
                # would change the type callers catch and lose the traceback.
                # So this taints from the message without rewriting it, and the
                # residual is that an exfil channel inside an exception's text
                # is not defanged the way a returned value's would be.
                self.session.ingest_result(tool_name, str(exc))
                raise
            labeled = self.session.ingest_result(tool_name, result)
            # Return the *sanitized* value whatever its shape. This used to be
            # strings only, back when sanitization could not reach inside a
            # dict/object — handing the caller the original now would throw
            # away the defanging and reopen the rendered-exfil channel for
            # every structured return.
            return labeled.content

        gated._tessera_name = tool_name  # type: ignore[attr-defined]
        return gated

    def wrap_tools(self, tools: Iterable[Callable]) -> list[Callable]:
        return [self.wrap(t) for t in tools]

    def _register(self, name: str, meta: dict) -> None:
        rev = meta.get("reversibility")
        exf = meta.get("exfiltration_capable")
        if rev is not None or exf is not None:
            self.session.register_tool(operator_profile(
                name,
                reversibility=_REVERSIBILITY.get(rev or "reversible", Reversibility.REVERSIBLE),
                exfiltration_capable=bool(exf),
            ))
        if meta.get("origin") is not None:
            self.session.set_tool_origin(name, meta["origin"])
        for arg, d in (meta.get("declassifiers") or {}).items():
            self.session.register_declassifier(name, arg, d)

    # -- configuration pass-throughs (fluent) -------------------------------

    def trust(self, tool: str, level: TrustLevel = TrustLevel.INTERNAL) -> "Guard":
        """Mark a tool's output as coming from a vetted source (won't taint)."""
        self.session.trust_tool(tool, level)
        return self

    def set_origin(self, tool: str, origin: Origin) -> "Guard":
        self.session.set_tool_origin(tool, origin)
        return self

    def declassify(self, tool: str, arg: str, declassifier: Declassifier) -> "Guard":
        self.session.register_declassifier(tool, arg, declassifier)
        return self

    def grant(self, capability: Capability) -> "Guard":
        self.session.grant(capability)
        return self

    @property
    def ledger(self) -> Ledger | None:
        return self.session.ledger


def protect(
    tools: Callable | Iterable[Callable] | None = None,
    *,
    policy: str = "balanced",
    allow_hosts: Iterable[str] = (),
    capabilities: bool = False,
    on_block: str = "error",
) -> Any:
    """Wrap tools with Tessera's flow rule, with sane defaults. The easy path.

    - ``protect([f, g])`` -> list of gated callables.
    - ``protect(f)`` -> one gated callable.
    - ``protect()`` -> a :class:`Guard` (wrap things yourself, configure trust).

    ``policy`` is ``"paranoid"`` / ``"balanced"`` (default) / ``"permissive"``.
    ``on_block`` is ``"error"`` (return a message the agent can read — drop-in
    for tool loops) or ``"raise"`` (raise :class:`Blocked`).
    """
    guard = Guard.create(
        policy=policy, allow_hosts=allow_hosts,
        capabilities=capabilities, on_block=on_block,
    )
    if tools is None:
        return guard
    if callable(tools):
        return guard.wrap(tools)
    return guard.wrap_tools(tools)


# -- helpers ----------------------------------------------------------------


def _signature(fn: Callable) -> inspect.Signature | None:
    try:
        return inspect.signature(fn)
    except (ValueError, TypeError):
        return None


def _argmap(sig: inspect.Signature | None, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Best-effort map of a call's arguments to {name: value} for gating."""
    if sig is not None:
        try:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)
        except TypeError:
            pass
    # Fall back to kwargs plus positional-by-index.
    argmap = dict(kwargs)
    for i, a in enumerate(args):
        argmap[f"arg{i}"] = a
    return argmap
