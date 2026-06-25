import json

from tessera.classification import classify_tool
from tessera.labels import TrustLevel
from tessera.ledger import Ledger, MemorySink, open_ledger
from tessera.policy import PolicyEngine, Strictness


def test_entries_have_monotonic_seq():
    sink = MemorySink()
    led = Ledger(sink=sink, session_id="s1")
    led.record("label", x=1)
    led.record("label", x=2)
    entries = sink.entries()
    assert [e["seq"] for e in entries] == [1, 2]
    assert all(e["session_id"] == "s1" for e in entries)


def test_decision_recorder_captures_provenance_and_blast():
    sink = MemorySink()
    led = Ledger(sink=sink, session_id="s")
    engine = PolicyEngine(Strictness.BALANCED)
    profile = classify_tool("send_email", {"properties": {"to": {}, "body": {}}})
    result = engine.evaluate(profile, TrustLevel.UNTRUSTED, provenance=("web page",))
    led.decision(result)
    entry = sink.entries()[0]
    assert entry["kind"] == "decision"
    assert entry["decision"] == "block"
    assert entry["arg_level"] == "UNTRUSTED"
    assert entry["provenance"] == ["web page"]
    assert entry["blast_radius"]["exfiltration_capable"] is True


def test_file_sink_appends(tmp_path):
    path = tmp_path / "audit.jsonl"
    led = open_ledger(str(path), session_id="s")
    led.label(tool="t", level="UNTRUSTED", origin="WEB_CONTENT", node_id="val-1")
    led.label(tool="t2", level="TRUSTED", origin="USER_QUERY", node_id="val-2")
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["tool"] == "t"
    assert first["origin"] == "WEB_CONTENT"
