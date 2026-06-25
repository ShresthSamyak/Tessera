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
from tessera.policy import Decision, PolicyEngine, PolicyResult, Strictness
from tessera.provenance import LabeledValue, ProvenanceNode
from tessera.session import Session

__version__ = "0.2.0"

__all__ = [
    "AllowlistDeclassifier",
    "BlastRadius",
    "BooleanDeclassifier",
    "Decision",
    "Declassifier",
    "DeclassifyOutcome",
    "EnumDeclassifier",
    "IntegerDeclassifier",
    "IsoDateDeclassifier",
    "LabeledValue",
    "NumberDeclassifier",
    "Origin",
    "PatternDeclassifier",
    "PolicyEngine",
    "PolicyResult",
    "ProvenanceNode",
    "Reversibility",
    "Session",
    "Strictness",
    "ToolProfile",
    "TrustLevel",
    "classify_tool",
    "__version__",
]
