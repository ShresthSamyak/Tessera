"""The policy engine — the product's heart.

It enforces exactly one rule:

    Data that originated untrusted may not become an argument to an
    exfiltration-capable or irreversible tool without passing a declassifier or
    human approval.

Everything else in Tessera exists to feed this decision soundly and without
paralyzing the agent. The engine is given, for a proposed tool call:

  * the tool's blast radius (:mod:`tessera.classification`), and
  * the trust level of the data flowing into its arguments,

and returns a :class:`PolicyResult` of ALLOW, BLOCK, or ESCALATE.

The :class:`Strictness` setting is the per-deployment point on the
dynamism<->containment frontier — the knob whose curve is the whole pitch. It
does not change the rule; it changes how the trust level of a call's arguments
is *determined* upstream (see :mod:`tessera.session`) and whether an
ambiguous-but-irreversible action blocks outright or routes to a human.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from tessera.classification import Reversibility, ToolProfile
from tessera.labels import TrustLevel


class Decision(str, Enum):
    """The verdict on a proposed tool call."""

    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"  # route to an informed human


class Strictness(str, Enum):
    """Where this deployment sits on the dynamism<->containment frontier.

    The mode governs what happens to a *dangerous* tool call carrying untrusted
    data when no declassifier cleared it:

      * ``PARANOID`` — block it. Maximum containment, maximum utility tax.
      * ``BALANCED`` — block exfiltration outright (a leak is unrecoverable and
        silent), but route irreversible non-exfiltrating actions to a human
        who is shown the provenance. The sane default.
      * ``PERMISSIVE`` — escalate everything to a human; block nothing
        automatically. Lowest tax, leans on HITL. Use when a human is reliably
        in the loop.
    """

    PARANOID = "paranoid"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


@dataclass(frozen=True)
class PolicyResult:
    """The outcome of evaluating one tool call against the flow rule."""

    decision: Decision
    tool: str
    #: The trust level of the data flowing into the call's arguments.
    arg_level: TrustLevel
    profile: ToolProfile
    reason: str
    #: Human-readable provenance summary, for the ledger and HITL prompt.
    provenance: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK


@dataclass
class PolicyEngine:
    """Evaluates proposed tool calls against the single flow rule."""

    strictness: Strictness = Strictness.BALANCED

    def evaluate(
        self,
        profile: ToolProfile,
        arg_level: TrustLevel,
        *,
        declassified: bool = False,
        provenance: tuple[str, ...] = (),
    ) -> PolicyResult:
        """Decide whether a tool call may proceed.

        Parameters
        ----------
        profile:
            The blast-radius profile of the tool being called.
        arg_level:
            The combined trust level of the data flowing into the arguments,
            as determined by the session's taint tracking.
        declassified:
            True if the untrusted inputs were passed through a declassifier (a
            constrained extractor) that vouches for the emitted value. A
            declassified value is treated as clean for this decision.
        provenance:
            Human-readable origin descriptions, attached to the result for the
            ledger / HITL prompt.
        """
        result = lambda decision, reason: PolicyResult(  # noqa: E731
            decision=decision,
            tool=profile.name,
            arg_level=arg_level,
            profile=profile,
            reason=reason,
            provenance=provenance,
        )

        # Safe tools are never gated: a read-only, non-exfiltrating tool can be
        # driven by untrusted data all day. This is what keeps the utility tax
        # low — only dangerous tools pay.
        if not profile.is_dangerous:
            return result(
                Decision.ALLOW,
                "tool has no exfiltration or irreversible capacity; "
                "flow rule does not apply",
            )

        # Clean (trusted/internal) data may drive any tool. This is the normal,
        # legitimate path — the user's own instruction telling the agent to
        # send an email it composed from user-provided content.
        if not arg_level.is_untrusted:
            return result(
                Decision.ALLOW,
                f"arguments are {arg_level.name}; data is trusted to drive a "
                "dangerous tool",
            )

        # Untrusted data that was squeezed through a declassifier is cleared.
        if declassified:
            return result(
                Decision.ALLOW,
                "untrusted inputs passed a declassifier; emitted value is "
                "constrained and vouched-for",
            )

        # The dangerous case: untrusted data is about to drive a dangerous
        # tool with nothing vouching for it. How we respond depends on the
        # frontier setting and on *why* the tool is dangerous.
        return self._gate(profile, result)

    def _gate(self, profile: ToolProfile, result) -> PolicyResult:
        exfil = profile.blast_radius.exfiltration_capable
        irreversible = profile.blast_radius.reversibility is Reversibility.IRREVERSIBLE
        why = []
        if exfil:
            why.append("exfiltration-capable")
        if irreversible:
            why.append("irreversible")
        danger = " and ".join(why)
        base = (
            f"untrusted data would flow into a {danger} tool without a "
            "declassifier or approval"
        )

        if self.strictness is Strictness.PARANOID:
            return result(Decision.BLOCK, base + "; blocked (paranoid mode)")

        if self.strictness is Strictness.PERMISSIVE:
            return result(
                Decision.ESCALATE,
                base + "; routing to human (permissive mode)",
            )

        # BALANCED: a leak is silent and unrecoverable, so block exfiltration
        # outright; an irreversible-but-local action gets a human who can see
        # the provenance.
        if exfil:
            return result(
                Decision.BLOCK,
                base + "; exfiltration blocked outright (balanced mode)",
            )
        return result(
            Decision.ESCALATE,
            base + "; routing to human for the irreversible action "
            "(balanced mode)",
        )
