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
    idempotent: bool

    @property
    def is_dangerous(self) -> bool:
        """A tool the flow rule must escort untrusted data away from.

        Dangerous == can leak data outward OR can cause an unrecoverable
        effect. Read-only, non-exfiltrating tools are safe to drive with
        untrusted data and stay fully dynamic.
        """
        return self.exfiltration_capable or (
            self.reversibility is Reversibility.IRREVERSIBLE
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
)
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

# A free-text destination argument means the tool can reach an arbitrary
# outbound endpoint — the hallmark of an exfiltration primitive.
_DESTINATION_PARAM_RE = re.compile(
    r"(url|uri|endpoint|host|recipient|to|address|email|destination|"
    r"callback|webhook|channel)s?$",
    re.IGNORECASE,
)


def _tokenize(name: str) -> list[str]:
    """Split a tool name like 'sendEmail' / 'send_email' / 'send-email'."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return [t for t in re.split(r"[\s_\-./]+", spaced.lower()) if t]


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

      * a free-text destination parameter (``url``, ``to``, ``recipient`` …) or
        an exfil verb in the name ⇒ exfiltration-capable;
      * an irreversible verb (``delete``, ``transfer``, ``send`` …) ⇒
        irreversible;
      * otherwise a write verb ⇒ reversible write; a pure read verb ⇒
        read-only;
      * an *unrecognized* tool is treated as a reversible write (cautious
        middle), never as read-only.
    """
    # Description tokens widen the signal: a read-named tool whose description
    # says "sends ..." should still be caught.
    tokens = _tokenize(f"{name} {description}")
    token_set = set(tokens)
    params = _schema_param_names(input_schema)

    has_destination_param = any(_DESTINATION_PARAM_RE.search(p) for p in params)
    has_exfil_verb = any(v in token_set for v in _EXFIL_VERBS)
    exfiltration_capable = has_destination_param or has_exfil_verb

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

    if has_destination_param:
        reasons.append("has a free-text destination parameter")
    if has_exfil_verb:
        reasons.append("name contains an exfiltration verb")

    # Idempotency: pure reads and explicit set/label-style writes are
    # idempotent; creates/sends/deletes generally are not.
    idempotent = reversibility is Reversibility.READ_ONLY or (
        "set" in token_set or "label" in token_set or "tag" in token_set
    )

    blast = BlastRadius(
        reversibility=reversibility,
        exfiltration_capable=exfiltration_capable,
        idempotent=idempotent,
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
