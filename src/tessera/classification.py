"""Classify tools by *blast radius*, not by caller.

Classic gateways ask "is this caller allowed to call this tool?" — and the
answer is always yes, it's your agent. That check cannot see the real danger,
which is what a tool can *do*. Tessera instead profiles every tool along the
axes that determine how much damage a hijacked call can cause:

  * **reversibility** — can the effect be undone? (read a row vs. delete it vs.
    wire money)
  * **exfiltration capacity** — can the call carry data to an
    attacker-chosen destination? (anything that reaches an arbitrary outbound
    endpoint is an exfiltration primitive)
  * **idempotency** — does repeating the call cause additional effect?

The flow rule fires on the *dangerous* combination: a tool that is either
exfiltration-capable or irreversible. Everything else can stay fully dynamic.

These profiles can be set explicitly by the operator, but the make-or-break
adoption property is that :func:`classify_tool` produces a sane default
*automatically* from an MCP tool's schema, so the secure path works out of the
box. Auto-classification is a heuristic and intentionally errs toward caution
(unknown write-ish tools are treated as dangerous); operators override per tool
where they know better. This is the per-tool dynamism<->containment knob.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping


class Reversibility(IntEnum):
    """How hard the effect of a tool is to undo."""

    READ_ONLY = 0  # no side effect at all
    REVERSIBLE = 1  # writes, but trivially undoable (set a draft, add a label)
    IRREVERSIBLE = 2  # delete, send, pay, publish — cannot be taken back


@dataclass(frozen=True)
class BlastRadius:
    """The danger profile of a single tool."""

    reversibility: Reversibility
    exfiltration_capable: bool
    #: Does repeating the call cause *additional* effect? This axis does **not**
    #: feed the flow rule — that keys only on :attr:`is_dangerous`, and whether a
    #: first call is safe has nothing to do with whether a second one is. It
    #: governs *how much authority a call needs*: the plan interpreter caps a
    #: non-idempotent dangerous step's derived capability at one use
    #: (``PlanInterpreter._derive_capabilities``), so a replay needs fresh
    #: authority. Outside plan mode nothing derives capabilities automatically,
    #: so there it is recorded in the ledger and available to operators minting
    #: their own grants — see the note in :mod:`tessera.policy`.
    idempotent: bool
    #: Does calling this tool hand work to *another* agent? Such a tool makes
    #: its own tool calls, and those never pass through this session — so plan
    #: mode's structural guarantee ("the executed set is exactly the plan's
    #: steps") holds of the plan and not of the process.
    #:
    #: Unlike ``idempotent`` this **does** make a tool dangerous: whatever the
    #: sub-agent can do, the delegating call can cause, so its blast radius is
    #: whatever the sub-agent's tools allow — unbounded from here. That makes
    #: the flow rule gate untrusted *instructions* flowing into a delegation,
    #: which is right and is not sufficient: a delegation whose arguments are
    #: plan constants carries no untrusted data, so the rule is silent while the
    #: sub-agent is still free to act. Containing that is plan mode's job (see
    #: :class:`~tessera.plan.PlanInterpreter`), not the flow rule's.
    spawns_agents: bool = False

    @property
    def is_dangerous(self) -> bool:
        """A tool the flow rule must escort untrusted data away from.

        Dangerous == can leak data outward OR can cause an unrecoverable
        effect. Read-only, non-exfiltrating tools are safe to drive with
        untrusted data and stay fully dynamic.

        Note that ``idempotent`` is deliberately absent here: a repeatable tool
        is not thereby safe, and a one-shot tool is not thereby dangerous.
        ``spawns_agents`` *is* present: a tool that runs another agent can cause
        anything that agent can, so it is dangerous by construction whatever its
        own name suggests.
        """
        return (
            self.exfiltration_capable
            or self.spawns_agents
            or self.reversibility is Reversibility.IRREVERSIBLE
        )


@dataclass(frozen=True)
class ToolProfile:
    """A named tool plus its blast radius and how we decided it."""

    name: str
    blast_radius: BlastRadius
    #: "auto" when inferred from schema, "operator" when explicitly configured.
    source: str = "auto"
    rationale: str = ""

    @property
    def is_dangerous(self) -> bool:
        return self.blast_radius.is_dangerous


# --- Heuristic vocabularies -------------------------------------------------
#
# Deliberately conservative: false "dangerous" labels cost some dynamism;
# false "safe" labels cost containment. We bias toward the former.

_EXFIL_VERBS = (
    "send",
    "post",
    "publish",
    "upload",
    "email",
    "fetch",
    "request",
    "http",
    "webhook",
    "notify",
    "share",
    "tweet",
    "message",
    "submit",
    "export",
    # Granting a new principal access exposes data outward — exfil-flavored.
    "invite",
    "grant",
)
#: Names that say "this tool runs another agent". Delegation is the one
#: construct plan mode cannot contain structurally, so it is worth naming
#: explicitly rather than lumping in with ordinary writes.
_DELEGATION_VERBS = (
    "delegate",
    "dispatch",
    "spawn",
    "subagent",
    "sub_agent",
    "handoff",
    "handover",
    "orchestrate",
    "supervise",
)
# NB: a bare "agent" token is deliberately *not* here. It matches
# ``get_agent_status`` and ``list_agents``, which read about agents rather than
# run one — and the consequence of a false positive is a hard plan-mode refusal,
# not merely extra gating. The motivating case (``delegate_to_runbook_agent``)
# is caught by "delegate" anyway. An operator whose delegating tool is named
# without any of these verbs says so with ``operator_profile(...)``.
_IRREVERSIBLE_VERBS = (
    "delete",
    "remove",
    "drop",
    "destroy",
    "purge",
    "wipe",
    "transfer",
    "pay",
    "wire",
    "charge",
    "refund",
    "send",
    "execute",
    "deploy",
    "merge",
    "revoke",
)
_WRITE_VERBS = (
    "create",
    "write",
    "update",
    "set",
    "add",
    "insert",
    "edit",
    "modify",
    "append",
    "label",
    "tag",
    "draft",
    "move",
    "rename",
)
_READ_VERBS = (
    "get",
    "read",
    "list",
    "search",
    "find",
    "fetch",  # note: fetch is also exfil-capable; handled below
    "query",
    "lookup",
    "view",
    "show",
    "describe",
    "count",
)

# An *outbound* parameter lets the tool reach an arbitrary endpoint of its
# own — a free-text URL/host/webhook is an exfiltration primitive regardless of
# the verb (even ``get_webpage(url)`` leaks via the URL it fetches).
_OUTBOUND_PARAM_RE = re.compile(
    r"(url|uri|endpoint|host|callback|webhook)s?$", re.IGNORECASE
)
# A *recipient* parameter names who/where, but says nothing on its own about
# direction: ``send_message(channel)`` sends *to* a channel (exfil) while
# ``read_messages(channel)`` reads *from* one (not exfil). So a recipient
# parameter only implies exfiltration when the tool also carries an exfil verb
# — which the verb check already captures. We track it for the rationale only.
_RECIPIENT_PARAM_RE = re.compile(
    r"(recipient|to|address|email|destination|channel)s?$", re.IGNORECASE
)


def _stem(token: str) -> str:
    """Crudely normalize a verb's surface form (sends/sending/sent -> send)."""
    for suffix in ("ing", "ed", "es", "s"):
        if token.endswith(suffix) and len(token) - len(suffix) >= 3:
            return token[: -len(suffix)]
    return token


def _tokenize(name: str) -> set[str]:
    """Split a tool name like 'sendEmail' / 'send_email' / 'send-email'.

    Returns both the raw tokens and their stems, so verb matching catches
    plurals and tenses ("sends", "fetching") without a real stemmer.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    raw = [t for t in re.split(r"[\s_\-./]+", spaced.lower()) if t]
    return set(raw) | {_stem(t) for t in raw}


def _schema_param_names(schema: Mapping[str, Any] | None) -> list[str]:
    if not schema:
        return []
    props = schema.get("properties")
    if isinstance(props, Mapping):
        return [str(k) for k in props.keys()]
    return []


def classify_tool(
    name: str,
    input_schema: Mapping[str, Any] | None = None,
    *,
    description: str = "",
) -> ToolProfile:
    """Infer a tool's blast radius from its MCP name/schema/description.

    The result is a default; operators should override for tools where they
    know the true effect. The heuristic:

      * a free-text *outbound* parameter (``url``, ``endpoint``, ``webhook`` …)
        or an exfil verb in the name ⇒ exfiltration-capable. A *recipient*
        parameter (``to``, ``channel`` …) alone is not enough — it could be a
        read selector (``read_channel(channel)``) rather than a send target;
        it only counts when paired with an exfil verb;
      * an irreversible verb (``delete``, ``transfer``, ``send`` …) ⇒
        irreversible;
      * otherwise a write verb ⇒ reversible write; a pure read verb ⇒
        read-only;
      * an *unrecognized* tool is treated as a reversible write (cautious
        middle), never as read-only.
    """
    # Description tokens widen the signal: a read-named tool whose description
    # says "sends ..." should still be caught.
    token_set = _tokenize(f"{name} {description}")
    params = _schema_param_names(input_schema)

    has_outbound_param = any(_OUTBOUND_PARAM_RE.search(p) for p in params)
    has_recipient_param = any(_RECIPIENT_PARAM_RE.search(p) for p in params)
    has_exfil_verb = any(v in token_set for v in _EXFIL_VERBS)
    # Exfiltration-capable iff it can reach an arbitrary endpoint (outbound
    # param) OR it actually sends (exfil verb). A recipient parameter alone is
    # NOT enough — it could just as well be a read selector.
    exfiltration_capable = has_outbound_param or has_exfil_verb

    has_irreversible_verb = any(v in token_set for v in _IRREVERSIBLE_VERBS)
    has_write_verb = any(v in token_set for v in _WRITE_VERBS)
    # Treat as read-only only if it has a read verb AND no write/irreversible
    # signal at all.
    has_read_verb = any(v in token_set for v in _READ_VERBS)

    reasons: list[str] = []
    if has_irreversible_verb:
        reversibility = Reversibility.IRREVERSIBLE
        reasons.append("name contains an irreversible verb")
    elif has_write_verb:
        reversibility = Reversibility.REVERSIBLE
        reasons.append("name contains a write verb")
    elif has_read_verb and not exfiltration_capable:
        reversibility = Reversibility.READ_ONLY
        reasons.append("name looks read-only")
    else:
        # Unknown / ambiguous: assume it writes something undoable. Cautious.
        reversibility = Reversibility.REVERSIBLE
        reasons.append("unrecognized verb; defaulting to reversible write")

    if has_outbound_param:
        reasons.append("has a free-text outbound endpoint parameter")
    if has_exfil_verb:
        reasons.append("name contains an exfiltration verb")
    if has_recipient_param and not exfiltration_capable:
        reasons.append("has a recipient parameter but no send verb (read selector)")

    # Idempotency: pure reads and explicit set/label-style writes are
    # idempotent; creates/sends/deletes generally are not.
    idempotent = reversibility is Reversibility.READ_ONLY or (
        "set" in token_set or "label" in token_set or "tag" in token_set
    )

    spawns_agents = any(v in token_set for v in _DELEGATION_VERBS)
    if spawns_agents:
        reasons.append("name suggests it delegates to another agent")

    blast = BlastRadius(
        reversibility=reversibility,
        exfiltration_capable=exfiltration_capable,
        idempotent=idempotent,
        spawns_agents=spawns_agents,
    )
    rationale = "; ".join(reasons) or "no signal"
    return ToolProfile(name=name, blast_radius=blast, source="auto", rationale=rationale)


def operator_profile(
    name: str,
    *,
    reversibility: Reversibility,
    exfiltration_capable: bool,
    idempotent: bool = False,
    rationale: str = "operator override",
) -> ToolProfile:
    """Build an explicit, operator-declared profile (overrides auto-classify)."""
    return ToolProfile(
        name=name,
        blast_radius=BlastRadius(
            reversibility=reversibility,
            exfiltration_capable=exfiltration_capable,
            idempotent=idempotent,
        ),
        source="operator",
        rationale=rationale,
    )
