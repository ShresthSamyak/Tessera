"""Declassifier soundness: a declassifier is only as safe as its constraint.

Run it:

    python examples/declassifier_soundness_demo.py

The plan is the honest hard case from the frontier: a "reply to the sender of my
latest message" workflow. The dangerous step (send_email) is genuinely in the
plan, and its recipient comes from an *untrusted* inbound message -- so a
declassifier is the only way to let the legitimate reply through.

The lesson: the declassifier's *output space* is what makes it safe, not whether
it looks strict. A regex that accepts "any well-formed email address" is tight
against injection sentences but **semantically loose** -- its output space
includes the attacker's address, so it launders the attack through. An allowlist
of known contacts has a bounded, attacker-uninfluenced output space, so it
contains the attack while still allowing real replies.
"""

from __future__ import annotations

from tessera.classification import Reversibility, classify_tool, operator_profile
from tessera.declassify import AllowlistDeclassifier, PatternDeclassifier
from tessera.plan import PlanInterpreter, call, const, plan, step, var
from tessera.policy import PolicyEngine, Strictness
from tessera.session import Session

ATTACKER = "exfil@evil.test"
CONTACT = "bob@co.test"

# A reply-to-sender plan. `sender` is bound from an untrusted inbox read.
REPLY_PLAN = plan(
    step(call("read_inbox", folder=const("inbox")), bind="sender"),
    step(call("send_email", to=var("sender"), subject=const("Re:"), body=const("Thanks, noted."))),
)


def run(label, sender_value, declassifier):
    sent = []

    def backend(tool, args):
        if tool == "send_email":
            sent.append(args)
            return "sent"
        if tool == "read_inbox":
            return sender_value  # the (untrusted) sender address
        return "ok"

    session = Session(policy=PolicyEngine(Strictness.PARANOID))
    session.register_tool(classify_tool("read_inbox", {"properties": {"folder": {}}}))
    session.register_tool(operator_profile(
        "send_email", reversibility=Reversibility.IRREVERSIBLE, exfiltration_capable=True))
    if declassifier is not None:
        session.register_declassifier("send_email", "to", declassifier)

    interp = PlanInterpreter(session, backend, auto_capabilities=False)
    interp.run(REPLY_PLAN)

    delivered_to = sent[0]["to"] if sent else None
    print(f"  {label}")
    print(f"     sender (untrusted): {sender_value}")
    print(f"     reply delivered to: {delivered_to if delivered_to else '(blocked)'}")
    return delivered_to


def main() -> None:
    # A regex that accepts any well-formed email -- looks strict, isn't.
    loose = PatternDeclassifier("any-email", r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
    # An allowlist of known contacts -- bounded, attacker-uninfluenced output.
    tight = AllowlistDeclassifier("known-contacts", [CONTACT, "alice@co.test"])

    print("=" * 70)
    print("1) NO declassifier -- the untrusted recipient is simply blocked")
    print("=" * 70)
    run("baseline", ATTACKER, None)

    print("\n" + "=" * 70)
    print("2) LOOSE declassifier (any-email pattern) -- UNSOUND")
    print("=" * 70)
    leaked = run("attacker sender", ATTACKER, loose)

    print("\n" + "=" * 70)
    print("3) TIGHT declassifier (contact allowlist) -- SOUND and USEFUL")
    print("=" * 70)
    blocked = run("attacker sender", ATTACKER, tight)
    delivered = run("legitimate sender", CONTACT, tight)

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"  loose pattern  -> attacker received the reply? {leaked == ATTACKER}  (LEAK)")
    print(f"  allowlist      -> attacker received the reply? {blocked == ATTACKER}  (contained)")
    print(f"  allowlist      -> legitimate reply delivered?  {delivered == CONTACT}  (useful)")
    print("\n  Same plan, same flow rule -- the only difference is the declassifier's")
    print("  output space. Bound it to values the attacker can't influence, or it")
    print("  becomes the laundering channel it was meant to prevent.")

    assert leaked == ATTACKER, "the loose pattern should leak (that is the lesson)"
    assert blocked is None, "the allowlist should contain the attacker"
    assert delivered == CONTACT, "the allowlist should still allow legitimate replies"


if __name__ == "__main__":
    main()
