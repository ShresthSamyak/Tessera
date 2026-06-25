"""The capability engine — kill ambient authority.

A classic agent holds a credential that works for *any* call to a tool: read
the inbox, send mail to anyone, delete any file. That ambient authority is what
makes a hijacked agent dangerous. Tessera replaces it with **capabilities**:
unforgeable, just-in-time, narrowly-scoped grants derived from the plan —
"send_email to bob@ with this payload", never "send_email to anyone". They
expire fast, and they **attenuate down delegation chains**: when one capability
is narrowed for a sub-agent or a downstream tool, permissions only ever shrink.

The construction is macaroon-style. A capability carries a list of **caveats**
(constraints) and an HMAC signature chained over them:

    sig0 = HMAC(root_key, capability_id)
    sig_i = HMAC(sig_{i-1}, serialize(caveat_i))

From this one trick the security properties fall out:

  * **Unforgeable** — only a holder of ``root_key`` can mint a valid root
    signature, so an agent cannot fabricate a capability from nothing.
  * **Attenuation needs no secret, and can only narrow** — appending a caveat
    and extending the chain (``HMAC(current_sig, new_caveat)``) requires no key,
    but every caveat is an *additional* restriction; you can never drop or
    reorder one without breaking the signature.
  * **Verifiable** — the engine, holding ``root_key``, recomputes the whole
    chain and checks every caveat against the proposed call.

``max_uses`` is inherently stateful, so the engine keeps a server-side use
counter keyed by capability id. Attenuated children keep their parent's id
(required so the HMAC chain still verifies from the root), which means a
capability lineage shares one use budget.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Mapping


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


# --------------------------------------------------------------------------
# Caveats
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Caveat:
    """A single restriction on what a capability authorizes.

    ``kind`` selects the predicate; ``params`` carries its arguments. The
    ``serialize`` form is what gets folded into the HMAC chain, so it must be
    canonical and stable.
    """

    kind: str
    params: tuple[tuple[str, Any], ...]

    @classmethod
    def make(cls, kind: str, **params: Any) -> "Caveat":
        return cls(kind=kind, params=tuple(sorted(params.items())))

    def get(self, key: str) -> Any:
        for k, v in self.params:
            if k == key:
                return v
        return None

    def serialize(self) -> str:
        body = ",".join(f"{k}={v!r}" for k, v in self.params)
        return f"{self.kind}({body})"

    def check(self, tool: str, args: Mapping[str, Any], ctx: "_VerifyContext") -> tuple[bool, str]:
        checker = _CAVEAT_CHECKS.get(self.kind)
        if checker is None:
            return False, f"unknown caveat kind {self.kind!r}"
        return checker(self, tool, args, ctx)

    def describe(self) -> str:
        return self.serialize()


def tool_is(name: str) -> Caveat:
    """The call must target tool ``name``."""
    return Caveat.make("tool_is", name=name)


def arg_equals(arg: str, value: Any) -> Caveat:
    """``args[arg]`` must equal ``value`` (compared as strings)."""
    return Caveat.make("arg_equals", arg=arg, value=str(value))


def arg_matches(arg: str, pattern: str) -> Caveat:
    """``args[arg]`` must fully match the regex ``pattern``."""
    return Caveat.make("arg_matches", arg=arg, pattern=pattern)


def arg_in(arg: str, values: list[str]) -> Caveat:
    """``args[arg]`` must be one of ``values``."""
    return Caveat.make("arg_in", arg=arg, values="|".join(sorted(str(v) for v in values)))


def expires_at(epoch_seconds: float) -> Caveat:
    """The capability is invalid after ``epoch_seconds``."""
    return Caveat.make("expires_at", ts=float(epoch_seconds))


def max_uses(n: int) -> Caveat:
    """The capability (lineage) may authorize at most ``n`` calls."""
    return Caveat.make("max_uses", n=int(n))


def _check_tool_is(c, tool, args, ctx):
    want = c.get("name")
    return (tool == want, f"tool must be {want!r}, got {tool!r}")


def _check_arg_equals(c, tool, args, ctx):
    arg, want = c.get("arg"), c.get("value")
    got = str(args.get(arg))
    return (got == want, f"{arg} must equal {want!r}, got {got!r}")


def _check_arg_matches(c, tool, args, ctx):
    arg, pattern = c.get("arg"), c.get("pattern")
    got = str(args.get(arg, ""))
    ok = re.fullmatch(pattern, got) is not None
    return (ok, f"{arg}={got!r} must match /{pattern}/")


def _check_arg_in(c, tool, args, ctx):
    arg = c.get("arg")
    allowed = set(c.get("values").split("|")) if c.get("values") else set()
    got = str(args.get(arg))
    return (got in allowed, f"{arg}={got!r} must be one of {sorted(allowed)}")


def _check_expires_at(c, tool, args, ctx):
    ts = c.get("ts")
    return (ctx.now <= ts, f"capability expired at {ts} (now {ctx.now:.0f})")


def _check_max_uses(c, tool, args, ctx):
    n = c.get("n")
    return (ctx.uses < n, f"capability used {ctx.uses}/{n} times")


_CAVEAT_CHECKS = {
    "tool_is": _check_tool_is,
    "arg_equals": _check_arg_equals,
    "arg_matches": _check_arg_matches,
    "arg_in": _check_arg_in,
    "expires_at": _check_expires_at,
    "max_uses": _check_max_uses,
}

# Aliases so the convenience minter can build caveats without its keyword
# parameters shadowing the constructor functions of the same name.
_cav_arg_equals = arg_equals
_cav_arg_in = arg_in
_cav_arg_matches = arg_matches


# --------------------------------------------------------------------------
# Capability
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Capability:
    """An unforgeable, attenuable grant. Identified by ``id``; the ``signature``
    is the HMAC chain over ``caveats`` rooted at ``id``."""

    id: str
    caveats: tuple[Caveat, ...]
    signature: bytes

    def attenuate(self, *caveats: Caveat) -> "Capability":
        """Return a strictly narrower capability with extra caveats appended.

        Requires no secret: the chain is extended from the current signature.
        The result can only be *more* restricted than ``self``.
        """
        sig = self.signature
        for cav in caveats:
            sig = _hmac(sig, cav.serialize())
        return Capability(id=self.id, caveats=self.caveats + tuple(caveats), signature=sig)

    def describe(self) -> str:
        caveat_str = "; ".join(c.describe() for c in self.caveats) or "(no caveats)"
        return f"cap {self.id[:8]} [{caveat_str}]"


@dataclass
class CapabilityResult:
    """The outcome of checking a capability against a proposed call."""

    authorized: bool
    reason: str
    capability_id: str | None = None

    @property
    def denied(self) -> bool:
        return not self.authorized


@dataclass
class _VerifyContext:
    now: float
    uses: int


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


@dataclass
class CapabilityEngine:
    """Mints, attenuates, and verifies capabilities against a root key."""

    root_key: bytes = field(default_factory=lambda: os.urandom(32))
    _uses: dict[str, int] = field(default_factory=dict)

    def mint(self, *caveats: Caveat, capability_id: str | None = None) -> Capability:
        """Mint a fresh root capability with the given caveats (the secret path)."""
        cap_id = capability_id or os.urandom(12).hex()
        sig = _hmac(self.root_key, cap_id)
        for cav in caveats:
            sig = _hmac(sig, cav.serialize())
        return Capability(id=cap_id, caveats=tuple(caveats), signature=sig)

    def mint_for(
        self,
        tool: str,
        *,
        arg_equals: Mapping[str, Any] | None = None,
        arg_in: Mapping[str, list[str]] | None = None,
        arg_matches: Mapping[str, str] | None = None,
        expires_in: float | None = None,
        uses: int | None = None,
    ) -> Capability:
        """Convenience minter for the common 'one tool, scoped args' grant."""
        caveats: list[Caveat] = [tool_is(tool)]
        for k, v in (arg_equals or {}).items():
            caveats.append(_cav_arg_equals(k, v))
        for k, vals in (arg_in or {}).items():
            caveats.append(_cav_arg_in(k, vals))
        for k, pat in (arg_matches or {}).items():
            caveats.append(_cav_arg_matches(k, pat))
        if expires_in is not None:
            caveats.append(expires_at(time.time() + expires_in))
        if uses is not None:
            caveats.append(max_uses(uses))
        return self.mint(*caveats)

    def _signature_valid(self, cap: Capability) -> bool:
        expected = _hmac(self.root_key, cap.id)
        for cav in cap.caveats:
            expected = _hmac(expected, cav.serialize())
        return hmac.compare_digest(expected, cap.signature)

    def verify(
        self,
        cap: Capability,
        tool: str,
        args: Mapping[str, Any],
        *,
        now: float | None = None,
        consume: bool = False,
    ) -> CapabilityResult:
        """Check that ``cap`` authorizes calling ``tool`` with ``args``.

        Verifies the HMAC chain (unforgeability), then every caveat. With
        ``consume=True``, increments the use counter on success — call it only
        for the capability you actually use.
        """
        if not self._signature_valid(cap):
            return CapabilityResult(False, "invalid signature (forged or tampered)", cap.id)
        ctx = _VerifyContext(now=now if now is not None else time.time(), uses=self._uses.get(cap.id, 0))
        for cav in cap.caveats:
            ok, reason = cav.check(tool, args, ctx)
            if not ok:
                return CapabilityResult(False, reason, cap.id)
        if consume:
            self._uses[cap.id] = ctx.uses + 1
        return CapabilityResult(True, "authorized by capability", cap.id)

    def consume(self, cap: Capability) -> None:
        """Record one use of a capability lineage."""
        self._uses[cap.id] = self._uses.get(cap.id, 0) + 1

    def uses_of(self, cap: Capability) -> int:
        return self._uses.get(cap.id, 0)
