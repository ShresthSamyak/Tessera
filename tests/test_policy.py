import pytest

from tessera.classification import Reversibility, classify_tool, operator_profile
from tessera.labels import TrustLevel
from tessera.policy import Decision, PolicyEngine, Strictness

SAFE = classify_tool("search_docs", {"properties": {"query": {}}})
EXFIL = classify_tool("send_email", {"properties": {"to": {}, "body": {}}})
IRREVERSIBLE_LOCAL = operator_profile(
    "delete_file",
    reversibility=Reversibility.IRREVERSIBLE,
    exfiltration_capable=False,
)


def test_safe_tool_always_allowed_even_with_untrusted_data():
    engine = PolicyEngine(Strictness.PARANOID)
    r = engine.evaluate(SAFE, TrustLevel.UNTRUSTED)
    assert r.decision is Decision.ALLOW


def test_trusted_data_into_dangerous_tool_allowed():
    engine = PolicyEngine(Strictness.BALANCED)
    r = engine.evaluate(EXFIL, TrustLevel.TRUSTED)
    assert r.decision is Decision.ALLOW


def test_untrusted_into_exfil_blocked_in_balanced():
    engine = PolicyEngine(Strictness.BALANCED)
    r = engine.evaluate(EXFIL, TrustLevel.UNTRUSTED)
    assert r.decision is Decision.BLOCK


def test_untrusted_into_irreversible_local_escalates_in_balanced():
    engine = PolicyEngine(Strictness.BALANCED)
    r = engine.evaluate(IRREVERSIBLE_LOCAL, TrustLevel.UNTRUSTED)
    assert r.decision is Decision.ESCALATE


def test_declassified_untrusted_allowed():
    engine = PolicyEngine(Strictness.BALANCED)
    r = engine.evaluate(EXFIL, TrustLevel.UNTRUSTED, declassified=True)
    assert r.decision is Decision.ALLOW


def test_paranoid_blocks_everything_dangerous():
    engine = PolicyEngine(Strictness.PARANOID)
    assert engine.evaluate(EXFIL, TrustLevel.UNTRUSTED).decision is Decision.BLOCK
    assert engine.evaluate(IRREVERSIBLE_LOCAL, TrustLevel.UNTRUSTED).decision is Decision.BLOCK


def test_permissive_escalates_everything_dangerous():
    engine = PolicyEngine(Strictness.PERMISSIVE)
    assert engine.evaluate(EXFIL, TrustLevel.UNTRUSTED).decision is Decision.ESCALATE
    assert engine.evaluate(IRREVERSIBLE_LOCAL, TrustLevel.UNTRUSTED).decision is Decision.ESCALATE


def test_unverified_is_treated_as_untrusted():
    engine = PolicyEngine(Strictness.BALANCED)
    r = engine.evaluate(EXFIL, TrustLevel.UNVERIFIED)
    assert r.decision is Decision.BLOCK


@pytest.mark.parametrize("strictness", list(Strictness))
def test_result_carries_provenance(strictness):
    engine = PolicyEngine(strictness)
    prov = ("came from web page x",)
    r = engine.evaluate(EXFIL, TrustLevel.UNTRUSTED, provenance=prov)
    assert r.provenance == prov
    assert r.tool == "send_email"
