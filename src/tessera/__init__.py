"""Tessera — a provenance control plane for tool-using agents.

Tessera contains the *blast radius* of a successful prompt injection. It does
not try to stop the model from being fooled (conceded as unsolvable in-band);
it ensures that when the model is fooled, the damage is bounded to actions that
are reversible, non-exfiltrating, or human-approved.

The v0.2 wedge — what this package implements — is a provenance-tracking MCP
proxy that:

  1. labels every tool result by its trust origin (:mod:`tessera.labels`),
  2. propagates those labels through an agent session (:mod:`tessera.session`),
  3. classifies tools by blast radius (:mod:`tessera.classification`), and
  4. enforces the single killer flow rule (:mod:`tessera.policy`):

        Data that originated untrusted may not become an argument to an
        exfiltration-capable or irreversible tool without passing a
        declassifier or human approval.

Every label, decision, and escalation is written to an append-only audit
ledger (:mod:`tessera.ledger`).
"""

from tessera.capabilities import (
    Capability,
    CapabilityEngine,
    CapabilityResult,
    Caveat,
    arg_equals,
    arg_in,
    arg_matches,
    expires_at,
    max_uses,
    tool_is,
)
from tessera.classification import (
    BlastRadius,
    Reversibility,
    ToolProfile,
    classify_tool,
)
from tessera.declassify import (
    AllowlistDeclassifier,
    BooleanDeclassifier,
    Declassifier,
    DeclassifyOutcome,
    EnumDeclassifier,
    IntegerDeclassifier,
    IsoDateDeclassifier,
    NumberDeclassifier,
    PatternDeclassifier,
)
from tessera.labels import Origin, TrustLevel
from tessera.ledger import (
    GENESIS_HASH,
    Ledger,
    LedgerEntry,
    LedgerVerification,
    open_ledger,
    verify_chain,
    verify_ledger,
)
from tessera.plan import (
    Call,
    Const,
    Field,
    Plan,
    PlanInterpreter,
    PlanRun,
    Step,
    Var,
    call,
    const,
    plan,
    step,
    var,
)
from tessera.planner import (
    ClaudePlanner,
    Planner,
    PlannerError,
    ScriptedPlanner,
    ToolSpec,
    parse_plan,
    plan_to_dict,
)
from tessera.policy import Decision, PolicyEngine, PolicyResult, Strictness
from tessera.provenance import LabeledValue, ProvenanceNode
from tessera.sdk import Blocked, BlockedResult, Guard, protect, tool
from tessera.session import Session

__version__ = "0.2.3"

__all__ = [
    "AllowlistDeclassifier",
    "BlastRadius",
    "Blocked",
    "BlockedResult",
    "BooleanDeclassifier",
    "Capability",
    "CapabilityEngine",
    "CapabilityResult",
    "Caveat",
    "Decision",
    "Declassifier",
    "DeclassifyOutcome",
    "EnumDeclassifier",
    "GENESIS_HASH",
    "Guard",
    "IntegerDeclassifier",
    "IsoDateDeclassifier",
    "LabeledValue",
    "Ledger",
    "LedgerEntry",
    "LedgerVerification",
    "NumberDeclassifier",
    "Call",
    "Const",
    "Field",
    "ClaudePlanner",
    "Origin",
    "PatternDeclassifier",
    "Plan",
    "PlanInterpreter",
    "PlanRun",
    "Planner",
    "PlannerError",
    "PolicyEngine",
    "PolicyResult",
    "ScriptedPlanner",
    "ToolSpec",
    "parse_plan",
    "plan_to_dict",
    "ProvenanceNode",
    "Reversibility",
    "Session",
    "Step",
    "Strictness",
    "ToolProfile",
    "TrustLevel",
    "Var",
    "arg_equals",
    "arg_in",
    "arg_matches",
    "call",
    "classify_tool",
    "const",
    "expires_at",
    "max_uses",
    "open_ledger",
    "plan",
    "protect",
    "step",
    "tool",
    "tool_is",
    "var",
    "verify_chain",
    "verify_ledger",
    "__version__",
]
