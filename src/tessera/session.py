"""Per-session taint state and orchestration.

The proxy sees a stream of tool calls and tool results for one agent session.
The :class:`Session` ties the engines together and holds the state the flow
rule needs: which untrusted data has entered the agent's context, and at what
trust level.

The honest hard part: the LLM sits between a tool result and the next tool
call, and it is an *untracked mixing function* — untrusted text goes in, a
clean-looking argument comes out, and we cannot trace through it. So Tessera
propagates **conservatively** and offers a knob:

  * ``PARANOID`` uses *context taint*: once any untrusted value has entered the
    session, every subsequent dangerous tool call is treated as untrusted-
    driven until a declassifier clears it. This is sound (it cannot be evaded
    by laundering the payload through the model) but has a high utility tax.

  * ``BALANCED`` / ``PERMISSIVE`` use *value-flow matching*: a call's arguments
    are treated as untrusted only if untrusted material actually appears in
    them. This catches the literal exfiltration that dominates real attacks
    (a secret or attacker URL copied into an argument) at a far lower tax, but
    a determined attacker can launder the payload past it — which is precisely
    what declassifiers and ``PARANOID`` are for. This trade is the point on the
    frontier the operator is choosing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from tessera.classification import ToolProfile, classify_tool
from tessera.labels import Origin, TrustLevel, combine
from tessera.ledger import Ledger, open_ledger
from tessera.policy import Decision, PolicyEngine, PolicyResult, Strictness
from tessera.provenance import LabeledValue, ProvenanceGraph
from tessera.sanitize import sanitize_markdown

# Minimum length of a token we consider "significant" enough to track for
# value-flow matching. Short common words would cause false positives.
_MIN_TOKEN_LEN = 6
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-./:@+=?&%]+")
_TRIM = ".,;:!?\"'`()[]{}<>"


def _significant_tokens(text: str) -> set[str]:
    """Extract normalized tokens long enough to be a meaningful data fragment.

    Used symmetrically on untrusted results and on proposed-call arguments:
    a non-empty intersection means untrusted material is literally flowing into
    the call. Tokens are trimmed of surrounding punctuation so that
    ``SECRET998877.`` (sentence-final) matches ``SECRET998877`` in an argument.
    """
    out: set[str] = set()
    for match in _TOKEN_RE.findall(text):
        tok = match.strip(_TRIM)
        if len(tok) >= _MIN_TOKEN_LEN:
            out.add(tok)
    return out


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


@dataclass
class Session:
    """Tracks taint for one agent session and authorizes its tool calls."""

    session_id: str = "default"
    policy: PolicyEngine = field(default_factory=PolicyEngine)
    ledger: Ledger | None = None
    allowlist: frozenset[str] = frozenset()

    # --- internal state ---
    profiles: dict[str, ToolProfile] = field(default_factory=dict)
    graph: ProvenanceGraph = field(default_factory=ProvenanceGraph)
    #: Floor trust level of everything ingested into context so far.
    context_level: TrustLevel = TrustLevel.TRUSTED
    #: Significant tokens seen in untrusted results, for value-flow matching.
    _tainted_tokens: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.ledger is None:
            self.ledger = open_ledger(session_id=self.session_id)

    # -- tool registration --------------------------------------------------

    def register_tool(self, profile: ToolProfile) -> None:
        """Register a tool's blast-radius profile (auto or operator-set)."""
        self.profiles[profile.name] = profile

    def register_tools_from_schema(self, tools: list[Mapping[str, Any]]) -> None:
        """Auto-classify a list of MCP tool descriptors (from tools/list)."""
        for tool in tools:
            name = str(tool.get("name", ""))
            if not name:
                continue
            if name in self.profiles:
                continue  # don't clobber an operator override
            profile = classify_tool(
                name,
                tool.get("inputSchema") or tool.get("input_schema"),
                description=str(tool.get("description", "")),
            )
            self.register_tool(profile)

    def _profile_for(self, tool: str) -> ToolProfile:
        if tool not in self.profiles:
            # Unknown tool seen at call time: classify it now, cautiously.
            self.register_tool(classify_tool(tool))
        return self.profiles[tool]

    # -- ingesting results (taint in) --------------------------------------

    def ingest_result(
        self,
        tool: str,
        content: Any,
        *,
        origin: Origin | None = None,
        level: TrustLevel | None = None,
    ) -> LabeledValue:
        """Label a tool result, propagate its taint into context, and sanitize.

        The trust level is inferred from the tool's blast radius unless given:
        a result from an exfiltration-capable / web-facing tool is attacker-
        reachable and therefore ``UNTRUSTED``. Returns the labeled value whose
        ``content`` has been sanitized for rendered-markdown exfil.
        """
        profile = self._profile_for(tool)
        resolved_origin = origin or self._infer_origin(profile)
        resolved_level = level if level is not None else resolved_origin.default_level

        # Sanitize the rendered content (closes the markdown-image channel).
        text = _stringify(content)
        san = sanitize_markdown(text, allowlist=self.allowlist)
        if san.changed and self.ledger:
            self.ledger.sanitize(tool, san.removed)

        value = LabeledValue.from_origin(
            san.text,
            resolved_origin,
            label=f"{tool}()",
            level=resolved_level,
        )
        self.graph.add(value)

        # Propagate taint into the session.
        if resolved_level.is_untrusted:
            self.context_level = combine(self.context_level, resolved_level)
            self._tainted_tokens.update(_significant_tokens(text))

        if self.ledger:
            self.ledger.label(
                tool=tool,
                level=resolved_level.name,
                origin=resolved_origin.name,
                node_id=value.node.node_id,
            )
        return value

    @staticmethod
    def _infer_origin(profile: ToolProfile) -> Origin:
        # A tool that can reach arbitrary outbound endpoints is, symmetrically,
        # a surface that returns attacker-reachable content (a fetched page).
        if profile.blast_radius.exfiltration_capable:
            return Origin.WEB_CONTENT
        return Origin.TOOL_OUTPUT

    # -- authorizing calls (taint out) -------------------------------------

    def _arg_level(self, args: Mapping[str, Any] | Any) -> tuple[TrustLevel, list[str]]:
        """Determine the trust level of a proposed call's arguments.

        Returns the level and a short provenance description for the ledger.
        """
        if self.policy.strictness is Strictness.PARANOID:
            if self.context_level.is_untrusted:
                return self.context_level, [
                    "context taint: untrusted data has entered this session"
                ]
            return TrustLevel.TRUSTED, ["no untrusted data in session"]

        # Value-flow matching: do the args share any significant token with
        # untrusted material we've seen?
        arg_tokens = _significant_tokens(_stringify(args))
        hits = sorted(self._tainted_tokens & arg_tokens)
        if hits:
            shown = ", ".join(hits[:3]) + (" …" if len(hits) > 3 else "")
            return TrustLevel.UNTRUSTED, [
                f"argument carries untrusted material ({shown})"
            ]
        return TrustLevel.TRUSTED, ["arguments contain no tracked untrusted material"]

    def authorize_call(
        self,
        tool: str,
        args: Mapping[str, Any] | Any,
        *,
        declassified: bool = False,
    ) -> PolicyResult:
        """Evaluate a proposed tool call against the flow rule and record it."""
        profile = self._profile_for(tool)
        arg_level, provenance = self._arg_level(args)
        result = self.policy.evaluate(
            profile,
            arg_level,
            declassified=declassified,
            provenance=tuple(provenance),
        )
        if self.ledger:
            self.ledger.decision(result)
        return result

    # -- convenience --------------------------------------------------------

    @property
    def is_tainted(self) -> bool:
        return self.context_level.is_untrusted

    def explain(self, result: PolicyResult) -> str:
        """Render a human-facing summary of a decision (for HITL prompts)."""
        lines = [
            f"Tool:      {result.tool}",
            f"Decision:  {result.decision.value.upper()}",
            f"Arg trust: {result.arg_level.name}",
            f"Blast:     {self._blast_summary(result)}",
            f"Reason:    {result.reason}",
        ]
        if result.provenance:
            lines.append("Provenance:")
            lines.extend(f"  - {p}" for p in result.provenance)
        if result.decision is Decision.ESCALATE:
            lines.append("Action:    awaiting human approval")
        return "\n".join(lines)

    @staticmethod
    def _blast_summary(result: PolicyResult) -> str:
        br = result.profile.blast_radius
        bits = [br.reversibility.name.lower()]
        if br.exfiltration_capable:
            bits.append("exfiltration-capable")
        return ", ".join(bits)
