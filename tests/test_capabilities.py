import dataclasses
import time

import pytest

from tessera.capabilities import (
    CapabilityEngine,
    arg_equals,
    arg_in,
    arg_matches,
    expires_at,
    max_uses,
    tool_is,
)


@pytest.fixture
def engine():
    # Fixed key so tests are deterministic; the key is the trust root.
    return CapabilityEngine(root_key=b"test-root-key-32-bytes-long!!!!!")


# --- Scoping ---------------------------------------------------------------

def test_capability_authorizes_exact_call(engine):
    cap = engine.mint(tool_is("send_email"), arg_equals("to", "bob@co.test"))
    assert engine.verify(cap, "send_email", {"to": "bob@co.test", "body": "hi"}).authorized


def test_capability_denies_wrong_tool(engine):
    cap = engine.mint(tool_is("send_email"))
    res = engine.verify(cap, "delete_file", {})
    assert res.denied and "tool must be" in res.reason


def test_capability_denies_wrong_arg(engine):
    cap = engine.mint(tool_is("send_email"), arg_equals("to", "bob@co.test"))
    assert engine.verify(cap, "send_email", {"to": "attacker@evil.test"}).denied


def test_arg_in_and_matches(engine):
    cap = engine.mint(tool_is("set_status"), arg_in("status", ["open", "closed"]))
    assert engine.verify(cap, "set_status", {"status": "open"}).authorized
    assert engine.verify(cap, "set_status", {"status": "deleted"}).denied

    cap2 = engine.mint(tool_is("refund"), arg_matches("order_id", r"ORD-\d{5}"))
    assert engine.verify(cap2, "refund", {"order_id": "ORD-12345"}).authorized
    assert engine.verify(cap2, "refund", {"order_id": "ORD-1; drop"}).denied


# --- Unforgeability --------------------------------------------------------

def test_forged_capability_rejected(engine):
    cap = engine.mint(tool_is("send_email"), arg_equals("to", "bob@co.test"))
    # Tamper: swap the recipient caveat but keep the original signature.
    forged = dataclasses.replace(
        cap, caveats=(tool_is("send_email"), arg_equals("to", "attacker@evil.test"))
    )
    res = engine.verify(forged, "send_email", {"to": "attacker@evil.test"})
    assert res.denied and "signature" in res.reason


def test_capability_from_other_key_rejected(engine):
    other = CapabilityEngine(root_key=b"a-totally-different-root-key-32b!")
    cap = other.mint(tool_is("send_email"))
    assert engine.verify(cap, "send_email", {}).denied  # wrong root key


def test_dropping_a_caveat_breaks_signature(engine):
    cap = engine.mint(tool_is("send_email"), arg_equals("to", "bob@co.test"))
    stripped = dataclasses.replace(cap, caveats=(tool_is("send_email"),))
    assert engine.verify(stripped, "send_email", {"to": "anyone@x.test"}).denied


# --- Attenuation (only narrows) -------------------------------------------

def test_attenuation_narrows_and_verifies(engine):
    cap = engine.mint(tool_is("send_email"), arg_equals("to", "bob@co.test"))
    child = cap.attenuate(arg_equals("subject", "Invoice"))
    # Child still verifies against the root key...
    assert engine.verify(child, "send_email", {"to": "bob@co.test", "subject": "Invoice"}).authorized
    # ...but is strictly narrower: the extra caveat must also hold.
    assert engine.verify(child, "send_email", {"to": "bob@co.test", "subject": "Other"}).denied


def test_attenuation_cannot_broaden(engine):
    # Start narrow, then "try to broaden" by attenuating with a contradictory
    # caveat. Attenuation only ever adds restrictions, so the result can only
    # get tighter -- there is no way to remove the original recipient lock.
    cap = engine.mint(tool_is("send_email"), arg_equals("to", "bob@co.test"))
    child = cap.attenuate(arg_equals("to", "carol@co.test"))
    # Now BOTH recipient caveats must hold, which is impossible -> always denied.
    assert engine.verify(child, "send_email", {"to": "bob@co.test"}).denied
    assert engine.verify(child, "send_email", {"to": "carol@co.test"}).denied


# --- Expiry & uses ---------------------------------------------------------

def test_expiry(engine):
    cap = engine.mint(tool_is("ping"), expires_at(1000.0))
    assert engine.verify(cap, "ping", {}, now=999.0).authorized
    assert engine.verify(cap, "ping", {}, now=1001.0).denied


def test_max_uses(engine):
    cap = engine.mint(tool_is("ping"), max_uses(2))
    assert engine.verify(cap, "ping", {}, consume=True).authorized
    assert engine.verify(cap, "ping", {}, consume=True).authorized
    assert engine.verify(cap, "ping", {}).denied  # third use over budget


def test_mint_for_convenience(engine):
    cap = engine.mint_for(
        "send_email", arg_equals={"to": "bob@co.test"}, expires_in=60, uses=1
    )
    assert engine.verify(cap, "send_email", {"to": "bob@co.test"}, now=time.time()).authorized
    assert engine.verify(cap, "send_email", {"to": "x@y.test"}).denied


# --- expiry and the clock (findings.md #22) --------------------------------
# Capabilities exist to strip ambient authority from a host assumed compromised.
# Judging expiry by *that host's* clock is the one caveat that undermines the
# assumption, so the time source has to be injectable where enforcement happens.

def test_a_wound_back_clock_revives_an_expired_capability():
    """Stated so the limit is a known property rather than a surprise."""
    import time

    from tessera.capabilities import CapabilityEngine

    engine = CapabilityEngine(root_key=b"k" * 32)
    cap = engine.mint_for("send_email", expires_in=-10)  # already expired

    assert not engine.verify(cap, "send_email", {}).authorized
    assert engine.verify(cap, "send_email", {}, now=time.time() - 3600).authorized


def test_an_injected_time_source_is_used_by_the_session_gate():
    """The escape hatch has to reach the *enforcement* path.

    ``verify(..., now=)`` is per-call, and ``Session`` verifies internally --
    so before ``time_source`` a proxy operator could not supply a trusted clock
    at all, which is where it matters most.
    """
    import time

    from tessera.capabilities import CapabilityEngine
    from tessera.classification import Reversibility, operator_profile
    from tessera.policy import Decision, PolicyEngine, Strictness
    from tessera.session import Session

    def build(clock=None):
        kwargs = {"time_source": clock} if clock else {}
        engine = CapabilityEngine(root_key=b"k" * 32, **kwargs)
        session = Session(
            policy=PolicyEngine(strictness=Strictness.BALANCED),
            capability_engine=engine,
            require_capabilities=True,
        )
        session.register_tool(operator_profile(
            "send_email", reversibility=Reversibility.IRREVERSIBLE,
            exfiltration_capable=True))
        session.grant(engine.mint_for("send_email", expires_in=-10))
        return session

    # A host whose clock has been wound back revives the expired grant...
    assert build(lambda: time.time() - 3600).authorize_call(
        "send_email", {"to": "a@b.test"}
    ).decision is Decision.ALLOW
    # ...and a trusted source restores the intended refusal, through the Session.
    assert build(lambda: time.time()).authorize_call(
        "send_email", {"to": "a@b.test"}
    ).decision is Decision.BLOCK
