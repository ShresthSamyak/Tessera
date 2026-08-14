import json

import pytest

from tessera.classification import classify_tool
from tessera.cli import main
from tessera.labels import TrustLevel
from tessera.ledger import (
    GENESIS_HASH,
    Ledger,
    LedgerEntry,
    MemorySink,
    open_ledger,
    read_chain_state,
    verify_chain,
    verify_ledger,
)
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


# -- tamper-evidence: the hash chain ---------------------------------------


def _write(path, objs):
    """Write raw JSON objects as a JSONL ledger (for forging tampered files)."""
    path.write_text(
        "".join(json.dumps(o, ensure_ascii=False, sort_keys=True) + "\n" for o in objs),
        encoding="utf-8",
    )


def _rechain(objs, hmac_key=None):
    """Recompute a fully-valid chain over ``objs`` — an attacker's best move."""
    prev = GENESIS_HASH
    out = []
    for obj in objs:
        body = {k: v for k, v in obj.items() if k != "hash"}
        payload = {
            k: v
            for k, v in body.items()
            if k not in ("seq", "timestamp", "session_id", "kind", "prev_hash")
        }
        entry = LedgerEntry.create(
            seq=body["seq"],
            timestamp=body["timestamp"],
            session_id=body["session_id"],
            kind=body["kind"],
            payload=payload,
            prev_hash=prev,
            hmac_key=hmac_key,
        )
        out.append(json.loads(entry.to_json()))
        prev = entry.entry_hash
    return out


def _ledger_with(n=3, **kw):
    sink = MemorySink()
    led = Ledger(sink=sink, session_id="s", **kw)
    for i in range(n):
        led.label(tool=f"t{i}", level="UNTRUSTED", origin="WEB_CONTENT", node_id=f"v{i}")
    return led, sink


def test_entries_are_hash_chained():
    led, sink = _ledger_with(3)
    entries = sink.entries()
    assert entries[0]["prev_hash"] == GENESIS_HASH
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["hash"]
    assert led.head == entries[-1]["hash"]
    assert led.seq == 3


def test_clean_chain_verifies():
    _, sink = _ledger_with(3)
    result = verify_chain(sink.lines)
    assert result.ok and bool(result) is True
    assert result.entries == 3
    assert "intact" in result.describe()


def test_edited_entry_is_detected(tmp_path):
    _, sink = _ledger_with(3)
    objs = sink.entries()
    objs[1]["level"] = "TRUSTED"  # rewrite history: this was gated, now it isn't
    path = tmp_path / "audit.jsonl"
    _write(path, objs)

    result = verify_ledger(str(path))
    assert not result
    assert result.broken_at_line == 2
    assert result.broken_at_seq == 2
    assert result.entries == 1  # the untouched prefix still verified
    assert "modified after it was written" in result.reason


def test_deleted_entry_is_detected(tmp_path):
    _, sink = _ledger_with(4)
    objs = sink.entries()
    del objs[1]  # make an inconvenient decision disappear
    path = tmp_path / "audit.jsonl"
    _write(path, objs)

    result = verify_ledger(str(path))
    assert not result
    assert result.broken_at_line == 2
    assert "edited, deleted, or reordered" in result.reason


def test_reordered_entries_are_detected(tmp_path):
    _, sink = _ledger_with(3)
    objs = sink.entries()
    objs[0], objs[1] = objs[1], objs[0]
    path = tmp_path / "audit.jsonl"
    _write(path, objs)

    assert not verify_ledger(str(path))


def test_truncation_needs_an_external_anchor(tmp_path):
    """A dropped tail leaves a valid prefix — only an anchor catches it."""
    led, sink = _ledger_with(3)
    anchor = led.head
    path = tmp_path / "audit.jsonl"
    _write(path, sink.entries()[:2])  # drop the last entry

    # Honest limitation: the truncated chain verifies on its own.
    assert verify_ledger(str(path)).ok
    # ...but not against the head the operator recorded elsewhere.
    result = verify_ledger(str(path), expected_head=anchor)
    assert not result
    assert "trailing entries were dropped" in result.reason


def test_unkeyed_chain_can_be_recomputed_but_keyed_cannot(tmp_path):
    """The documented difference between SHA-256 and HMAC chaining."""
    key = b"collector-side-key"
    _, sink = _ledger_with(3, hmac_key=key)
    objs = sink.entries()
    objs[1]["level"] = "TRUSTED"

    # An attacker without the key can only produce a *plain* chain...
    forged = tmp_path / "forged.jsonl"
    _write(forged, _rechain(objs))
    assert verify_ledger(str(forged)).ok  # unkeyed verification is fooled
    assert not verify_ledger(str(forged), hmac_key=key)  # keyed verification is not

    # ...and with the key, the forgery verifies — which is why the key must not
    # live in the agent process.
    keyed = tmp_path / "keyed.jsonl"
    _write(keyed, _rechain(objs, hmac_key=key))
    assert verify_ledger(str(keyed), hmac_key=key).ok


def test_keyed_chain_rejects_the_wrong_key():
    _, sink = _ledger_with(2, hmac_key=b"right")
    assert verify_chain(sink.lines, hmac_key=b"right").ok
    assert not verify_chain(sink.lines, hmac_key=b"wrong")
    assert not verify_chain(sink.lines)  # unkeyed check of a keyed chain


def test_reopening_a_file_resumes_one_continuous_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = open_ledger(str(path), session_id="run1")
    first.label(tool="a", level="UNTRUSTED", origin="WEB_CONTENT", node_id="v1")
    first.label(tool="b", level="UNTRUSTED", origin="WEB_CONTENT", node_id="v2")

    # A restarted proxy must extend the chain, not silently start a second one.
    second = open_ledger(str(path), session_id="run2")
    assert second.seq == 2
    assert second.head == first.head
    second.label(tool="c", level="TRUSTED", origin="USER_QUERY", node_id="v3")

    result = verify_ledger(str(path))
    assert result.ok
    assert result.entries == 3
    assert result.head == second.head


def test_legacy_pre_chain_file_is_reported_not_silently_accepted(tmp_path):
    path = tmp_path / "old.jsonl"
    _write(path, [{"seq": 1, "timestamp": 1.0, "session_id": "s", "kind": "label"}])

    result = verify_ledger(str(path))
    assert not result
    assert "pre-chain version" in result.reason
    # Resuming from a legacy tail restarts the chain rather than faking one.
    assert read_chain_state(str(path)) == (0, GENESIS_HASH)


def test_missing_ledger_is_a_failure_not_an_empty_one(tmp_path):
    result = verify_ledger(str(tmp_path / "nope.jsonl"))
    assert not result
    assert result.entries == 0
    assert "no ledger file" in result.reason


def test_empty_file_is_a_valid_empty_chain(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    result = verify_ledger(str(path))
    assert result.ok
    assert result.entries == 0


def test_corrupt_line_is_reported(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("{not json\n", encoding="utf-8")
    result = verify_ledger(str(path))
    assert not result
    assert result.broken_at_line == 1
    assert "not valid JSON" in result.reason


def test_payload_cannot_shadow_the_entrys_own_fields():
    """A tool-supplied field named 'hash'/'seq' must not break verification."""
    sink = MemorySink()
    led = Ledger(sink=sink, session_id="s")
    led.record("label", hash="attacker", seq=99, tool="t")

    entry = sink.entries()[0]
    assert entry["seq"] == 1
    assert entry["payload_hash"] == "attacker"
    assert entry["payload_seq"] == 99
    assert verify_chain(sink.lines).ok


def test_decision_entries_stay_verifiable():
    """The real recorder path (nested dicts, lists) must round-trip exactly."""
    sink = MemorySink()
    led = Ledger(sink=sink, session_id="s")
    engine = PolicyEngine(Strictness.BALANCED)
    profile = classify_tool("send_email", {"properties": {"to": {}, "body": {}}})
    led.decision(engine.evaluate(profile, TrustLevel.UNTRUSTED, provenance=("web",)))
    led.sanitize("fetch_url", ["https://attacker.test/x"])
    assert verify_chain(sink.lines).ok


# -- the operator-facing `tessera verify` command ---------------------------


def _seed(tmp_path, name="audit.jsonl", **kw):
    path = tmp_path / name
    led = open_ledger(str(path), session_id="s", **kw)
    led.label(tool="fetch_url", level="UNTRUSTED", origin="WEB_CONTENT", node_id="v1")
    led.label(tool="send_email", level="TRUSTED", origin="USER_QUERY", node_id="v2")
    return path, led


def test_cli_verify_reports_intact_ledger(tmp_path, capsys):
    path, _ = _seed(tmp_path)
    assert main(["verify", str(path)]) == 0
    out = capsys.readouterr().out
    assert "ledger intact: 2 entries" in out
    assert "cannot detect a truncated tail" in out  # the honest caveat


def test_cli_verify_exits_nonzero_on_tampering(tmp_path, capsys):
    path, _ = _seed(tmp_path)
    objs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    objs[0]["level"] = "TRUSTED"
    _write(path, objs)

    assert main(["verify", str(path)]) == 1
    assert "ledger BROKEN at line 1" in capsys.readouterr().out


def test_cli_verify_detects_truncation_against_an_anchor(tmp_path, capsys):
    path, led = _seed(tmp_path)
    anchor = led.head
    objs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    _write(path, objs[:1])

    assert main(["verify", str(path), "--expected-head", anchor]) == 1
    assert "trailing entries were dropped" in capsys.readouterr().out


def test_cli_verify_uses_the_key_from_the_environment(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("TESSERA_TEST_KEY", "s3cret")
    path, _ = _seed(tmp_path, hmac_key=b"s3cret")

    assert main(["verify", str(path), "--key-env", "TESSERA_TEST_KEY"]) == 0
    assert main(["verify", str(path)]) == 1  # unkeyed check of a keyed chain
    assert "ledger BROKEN" in capsys.readouterr().out


def test_cli_verify_rejects_an_unset_key_env(tmp_path, monkeypatch):
    monkeypatch.delenv("TESSERA_TEST_KEY", raising=False)
    path, _ = _seed(tmp_path)
    with pytest.raises(SystemExit):
        main(["verify", str(path), "--key-env", "TESSERA_TEST_KEY"])
