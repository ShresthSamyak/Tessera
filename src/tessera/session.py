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
from dataclasses import dataclass, field, replace
from typing import Any, Mapping

from tessera.capabilities import Capability, CapabilityEngine, CapabilityResult
from tessera.classification import ToolProfile, classify_tool
from tessera.declassify import Declassifier
from tessera.labels import Origin, TrustLevel, combine
from tessera.ledger import Ledger, open_ledger
from tessera.policy import Decision, PolicyEngine, PolicyResult, Strictness
from tessera.provenance import LabeledValue, ProvenanceGraph
from tessera.sanitize import sanitize_value

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

    #: Declassifiers keyed by (tool name, argument name). The trusted control
    #: plane decides which arguments may pass untrusted data through a membrane.
    declassifiers: dict[tuple[str, str], Declassifier] = field(default_factory=dict)

    #: Optional capability engine. When set with ``require_capabilities``, every
    #: gated tool call must be authorized by a granted capability (least
    #: authority), independently of the provenance flow rule.
    capability_engine: CapabilityEngine | None = None
    #: If True, calls to dangerous tools require a granted capability. If
    #: ``capabilities_cover_all`` is also True, *every* tool does.
    require_capabilities: bool = False
    capabilities_cover_all: bool = False

    # --- internal state ---
    profiles: dict[str, ToolProfile] = field(default_factory=dict)
    #: Operator-declared trust origin per tool (how much to trust its output).
    #: Blast radius is *what a tool can do*; origin is *how trustworthy what it
    #: returns is*. Absent an entry, origin is inferred (conservatively).
    tool_origins: dict[str, Origin] = field(default_factory=dict)
    #: Explicit per-tool trust-level overrides (set via :meth:`trust_tool`).
    tool_levels: dict[str, TrustLevel] = field(default_factory=dict)
    graph: ProvenanceGraph = field(default_factory=ProvenanceGraph)
    #: Floor trust level of everything ingested into context so far.
    context_level: TrustLevel = TrustLevel.TRUSTED
    #: Significant tokens seen in untrusted results, for value-flow matching.
    _tainted_tokens: set[str] = field(default_factory=set)
    #: Capabilities granted to this session (the held set the proxy enforces).
    _granted: list[Capability] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.ledger is None:
            self.ledger = open_ledger(session_id=self.session_id)

    # -- tool registration --------------------------------------------------

    def register_tool(self, profile: ToolProfile) -> None:
        """Register a tool's blast-radius profile (auto or operator-set)."""
        self.profiles[profile.name] = profile

    def register_declassifier(
        self, tool: str, arg: str, declassifier: Declassifier
    ) -> None:
        """Permit untrusted data into ``tool``'s ``arg`` iff it passes ``declassifier``.

        This is a trusted-control-plane decision: the operator declares a narrow
        bottleneck through which tainted data may reach a dangerous tool.
        """
        self.declassifiers[(tool, arg)] = declassifier

    def set_tool_origin(
        self, tool: str, origin: Origin, *, level: TrustLevel | None = None
    ) -> None:
        """Declare the trust origin of a tool's output (overrides inference).

        Use this to tell Tessera where a tool's data really comes from — e.g.
        ``read_inbox`` returns ``INBOUND_MESSAGE`` (untrusted), a first-party
        ``internal_db`` returns ``VETTED_SYSTEM`` (internal). ``level`` may pin
        an explicit trust level if the origin's default isn't right.
        """
        self.tool_origins[tool] = origin
        if level is not None:
            self.tool_levels[tool] = level

    def trust_tool(self, tool: str, level: TrustLevel = TrustLevel.INTERNAL) -> None:
        """Mark a tool's output as coming from a vetted source (default INTERNAL).

        Its results then carry a trusted level and do NOT taint the session, so
        legitimate work that reads from a vetted system isn't over-gated. Only
        do this for sources an attacker genuinely cannot influence.
        """
        self.tool_origins[tool] = Origin.VETTED_SYSTEM
        self.tool_levels[tool] = level

    def grant(self, capability: Capability) -> None:
        """Add a capability to the session's held set (least authority).

        Capabilities are minted by the trusted control plane and granted here;
        when ``require_capabilities`` is on, a gated call is authorized only if
        one held capability covers it.
        """
        self._granted.append(capability)

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
        reachable and therefore ``UNTRUSTED``. A string result has its rendered
        markdown sanitized (closing the image-exfil channel); a structured
        (non-string) result is preserved as-is so the plan interpreter can read
        fields from it — it is still tainted, but not deep-sanitized (a known
        limitation tracked for structured returns).
        """
        profile = self._profile_for(tool)
        # Resolution order: explicit arg -> operator config -> name/blast-radius
        # inference (conservative default).
        resolved_origin = (
            origin or self.tool_origins.get(tool) or self._infer_origin(tool, profile)
        )
        if level is not None:
            resolved_level = level
        elif tool in self.tool_levels:
            resolved_level = self.tool_levels[tool]
        else:
            resolved_level = resolved_origin.default_level

        # Token extraction for value-flow taint uses the *original* serialized
        # form (conservative — captures tokens even from URLs we strip).
        text = _stringify(content)
        # Deep-sanitize the rendered content, preserving structure so the plan
        # interpreter can still field-access it. Foreign objects (pydantic) pass
        # through structurally intact but remain tainted via ``text`` above.
        new_content, removed = sanitize_value(content, allowlist=self.allowlist)
        if removed and self.ledger:
            self.ledger.sanitize(tool, removed)

        value = LabeledValue.from_origin(
            new_content,
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
    def _infer_origin(tool: str, profile: ToolProfile) -> Origin:
        """Guess a tool result's origin from its name and blast radius.

        Only sharpens the *label* (for the audit trail / HITL prompt) — every
        case here is still untrusted-or-unverified, so it never relaxes the
        gate. To mark a source *trusted*, an operator must say so explicitly
        (:meth:`trust_tool` / :meth:`set_tool_origin`).
        """
        name = tool.lower()
        if any(k in name for k in ("inbox", "email", "mail", "message", "dm")):
            return Origin.INBOUND_MESSAGE
        if profile.blast_radius.exfiltration_capable or any(
            k in name for k in ("web", "url", "http", "fetch", "browse", "search", "page")
        ):
            return Origin.WEB_CONTENT
        if any(k in name for k in ("doc", "file", "pdf", "attachment", "upload", "download")):
            return Origin.DOCUMENT
        return Origin.TOOL_OUTPUT

    # -- authorizing calls (taint out) -------------------------------------

    def _tainted_args(self, args: Mapping[str, Any] | Any) -> dict[str, list[str]]:
        """Which arguments carry untrusted material, under the active mode.

        Returns a map of argument name -> the untrusted tokens found in it. In
        ``paranoid`` mode, once the session is tainted *every* argument is
        suspect (the model could have laundered the payload into any of them),
        so they are all listed. In value-flow modes, only arguments whose text
        actually contains a tracked untrusted token are listed.
        """
        if not isinstance(args, Mapping):
            # Non-mapping argument payload: treat as one opaque value.
            text = _stringify(args)
            if self.policy.strictness is Strictness.PARANOID:
                return {"": ["context taint"]} if self.context_level.is_untrusted else {}
            hits = sorted(tok for tok in self._tainted_tokens if tok in text)
            return {"": hits} if hits else {}

        tainted: dict[str, list[str]] = {}
        paranoid = self.policy.strictness is Strictness.PARANOID
        session_tainted = self.context_level.is_untrusted
        for name, value in args.items():
            text = _stringify(value)
            if paranoid and session_tainted:
                tainted[name] = ["context taint"]
            else:
                hits = sorted(tok for tok in self._tainted_tokens if tok in text)
                if hits:
                    tainted[name] = hits
        return tainted

    def _evaluate_arguments(
        self,
        tool: str,
        raw_args: Mapping[str, Any],
        tainted: dict[str, list[str]],
    ) -> tuple[TrustLevel, list[str], bool, dict | None]:
        """Resolve a call's argument trust level, applying any declassifiers.

        ``raw_args`` maps argument name -> raw value (used as declassifier input
        and for provenance). ``tainted`` is the precomputed set of arguments
        carrying untrusted material (from the token heuristic in
        :meth:`authorize_call`, or from precise labels in
        :meth:`authorize_call_labeled`). Returns
        ``(arg_level, provenance, declassified, cleaned_args)``.
        """
        if not tainted:
            return TrustLevel.TRUSTED, ["arguments contain no tracked untrusted material"], False, None

        provenance: list[str] = []
        cleaned: dict[str, Any] = {}
        remaining: list[str] = []

        for name, hits in tainted.items():
            declassifier = self.declassifiers.get((tool, name))
            shown = ", ".join(hits[:3]) + (" …" if len(hits) > 3 else "")
            arg_label = name or "<value>"
            if declassifier is None:
                remaining.append(name)
                provenance.append(f"{arg_label} carries untrusted material ({shown})")
                continue
            outcome = declassifier.apply(_stringify(raw_args.get(name)))
            if self.ledger:
                self.ledger.declassify(
                    tool, arg_label, declassifier.name, outcome.accepted,
                    outcome.reason, declassifier.constraint(),
                )
            if outcome.accepted:
                cleaned[name] = outcome.value
                provenance.append(
                    f"{arg_label} declassified via {declassifier.name} "
                    f"({declassifier.constraint()})"
                )
            else:
                remaining.append(name)
                provenance.append(
                    f"{arg_label} REJECTED by {declassifier.name}: {outcome.reason}"
                )

        if remaining:
            # At least one tainted argument could not be cleared.
            return TrustLevel.UNTRUSTED, provenance, False, None

        # Every tainted argument passed a declassifier. Only real (named)
        # substitutions can be forwarded downstream.
        cleaned_args = {k: v for k, v in cleaned.items() if k} or None
        return TrustLevel.UNTRUSTED, provenance, True, cleaned_args

    def _capability_required(self, profile: ToolProfile) -> bool:
        if not (self.require_capabilities and self.capability_engine is not None):
            return False
        return self.capabilities_cover_all or profile.is_dangerous

    def _check_capability(
        self, tool: str, args: Mapping[str, Any] | Any
    ) -> CapabilityResult:
        """Find a granted capability that authorizes this call (least authority)."""
        engine = self.capability_engine
        assert engine is not None
        call_args = args if isinstance(args, Mapping) else {}
        last_reason = "no capability has been granted for this session"
        for cap in self._granted:
            res = engine.verify(cap, tool, call_args)
            if res.authorized:
                engine.consume(cap)  # spend exactly the capability we used
                return res
            last_reason = res.reason
        return CapabilityResult(False, last_reason)

    def authorize_call(
        self,
        tool: str,
        args: Mapping[str, Any] | Any,
        *,
        declassified: bool = False,
    ) -> PolicyResult:
        """Evaluate a proposed tool call and record the decision.

        Two independent gates must both pass for a dangerous call:

          1. **least authority** — if capabilities are required, a granted
             capability must authorize this exact (tool, args); and
          2. **the flow rule** — untrusted data must not drive the tool unless
             declassified or human-approved.

        Untrusted arguments are routed through any registered declassifiers
        first; ``declassified`` may also be forced True by a caller that has
        already cleared the data out of band.
        """
        profile = self._profile_for(tool)
        raw_args = args if isinstance(args, Mapping) else {"": args}
        tainted = self._tainted_args(args)
        arg_level, provenance, auto_declassified, cleaned = self._evaluate_arguments(
            tool, raw_args, tainted
        )
        capability_args = args if isinstance(args, Mapping) else {}
        return self._finalize_decision(
            tool, profile, capability_args, arg_level, provenance,
            declassified or auto_declassified, cleaned,
        )

    def authorize_call_labeled(
        self,
        tool: str,
        labeled_args: Mapping[str, LabeledValue],
        *,
        declassified: bool = False,
    ) -> PolicyResult:
        """Authorize a call using *precise* per-argument provenance.

        Unlike :meth:`authorize_call` (which infers taint from a token
        heuristic, since it cannot see inside the model), this takes a
        :class:`LabeledValue` per argument — so an argument is untrusted iff its
        own label says so. This is what the plan interpreter
        (:mod:`tessera.plan`) uses: because the plan's control flow is fixed
        from trusted input, every value's provenance is known exactly, and the
        flow rule applies with no over-tainting.
        """
        profile = self._profile_for(tool)
        raw_args = {name: lv.content for name, lv in labeled_args.items()}
        tainted = {
            name: [f"value is {lv.level.name}"]
            for name, lv in labeled_args.items()
            if lv.is_untrusted
        }
        arg_level, provenance, auto_declassified, cleaned = self._evaluate_arguments(
            tool, raw_args, tainted
        )
        return self._finalize_decision(
            tool, profile, raw_args, arg_level, provenance,
            declassified or auto_declassified, cleaned,
        )

    def _finalize_decision(
        self,
        tool: str,
        profile: ToolProfile,
        capability_args: Mapping[str, Any],
        arg_level: TrustLevel,
        provenance: list[str],
        declassified: bool,
        cleaned: dict | None,
    ) -> PolicyResult:
        """Run both gates (least authority, then flow rule) and record."""
        # Gate 1: least authority. A missing/insufficient capability is a hard
        # block — ambient authority is exactly what we are removing.
        if self._capability_required(profile):
            cap_res = self._check_capability(tool, capability_args)
            if self.ledger:
                self.ledger.capability(
                    tool, cap_res.authorized, cap_res.reason, cap_res.capability_id
                )
            if not cap_res.authorized:
                result = PolicyResult(
                    decision=Decision.BLOCK,
                    tool=tool,
                    arg_level=arg_level,
                    profile=profile,
                    reason=f"no capability authorizes this call: {cap_res.reason}",
                    provenance=tuple(provenance),
                )
                if self.ledger:
                    self.ledger.decision(result)
                return result

        # Gate 2: the provenance flow rule.
        result = self.policy.evaluate(
            profile, arg_level, declassified=declassified, provenance=tuple(provenance)
        )
        if cleaned and result.decision is Decision.ALLOW:
            result = replace(result, cleaned_arguments=cleaned)
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
